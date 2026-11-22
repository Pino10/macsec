/**
 * White box for the web scan: reads the site's own source code (never changes it) and builds a map
 * of its routes and the parameters it reads. The scan then tests those, including routes that no
 * page links to, which a crawl from outside can never find. Each route that looks private and has
 * no visible access check in the code becomes a lead, and the scan confirms it live: a signed-out
 * request to that route that gets a real page proves the code and the site agree on the hole.
 *
 * Supported: Laravel, Express and similar (Fastify, Koa, Hono), Flask and FastAPI, Django, Rails,
 * Next.js (pages and app folders) and plain PHP files. It is a reading of text, not a full
 * understanding of the code, so what it finds is a lead until the live request shows it.
 */
import { readdirSync, readFileSync, statSync } from 'fs'
import { join, relative, sep } from 'path'

export interface CodeRoute {
  method: string
  path: string
  file: string
  line: number
  /** True when the lines around the definition mention an access check. */
  guarded: boolean
  framework: string
}

export interface CodeMap {
  routes: CodeRoute[]
  /** Parameter names the code reads, with the files that read them. */
  params: Record<string, string[]>
  frameworks: string[]
  files: number
}

const SKIP = new Set(['node_modules', 'vendor', '.git', 'storage', 'dist', 'build', 'out', '.next', '.nuxt', 'coverage', 'venv', '.venv', '__pycache__', 'bootstrap', 'cache', 'tmp', 'logs', 'public/build'])
const CODE = /\.(php|js|jsx|ts|tsx|mjs|cjs|py|rb)$/i
const GUARD = /(auth|middleware|guard|login_required|requireauth|isauthenticated|authorize|can:|permission|policy|jwt|verifytoken|ensure_?logged|before_action|authenticate)/i
export const PRIVATE_PATH = /(^|\/)(admin|administrator|dashboard|account|settings|profile|billing|internal|manage|backoffice|staff|users?|orders?|invoices?|reports?|export|api\/(users|admin|accounts|orders))(\/|$)/i

/** `{id}`, `:id`, `<int:id>` and `[id]` become 1, so a route can be requested. */
export function fillPath(p: string): string {
  return ('/' + p.replace(/^\/+/, ''))
    .replace(/\{[^}]+\?\}/g, '')
    .replace(/\{[^}]+\}/g, '1')
    .replace(/<[^>]*:?[^>]*>/g, '1')
    .replace(/:[A-Za-z_]\w*\??/g, '1')
    .replace(/\[\.\.\.[^\]]+\]|\[\[?[^\]]+\]\]?/g, '1')
    .replace(/\(\?P<[^>]+>[^)]*\)/g, '1')
    .replace(/[\^$]/g, '')
    .replace(/\/{2,}/g, '/')
}

function lineOf(text: string, index: number): number {
  let n = 1
  for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) n++
  return n
}

/** A guard word on the route's own line or the next one (chained middleware), or in the 600 characters before it (a group that opened above). Missing a guard means fewer leads, never more. */
function guarded(text: string, index: number): boolean {
  const lineEnd = text.indexOf('\n', index)
  const end = lineEnd < 0 ? text.length : lineEnd
  const nextEnd = text.indexOf('\n', end + 1)
  const next = text.slice(end + 1, nextEnd < 0 ? text.length : nextEnd)
  // The next line counts only when it continues the same statement (chained middleware).
  const after = text.slice(index, end) + (/^\s*(->|\.)/.test(next) ? `\n${next}` : '')
  return GUARD.test(text.slice(Math.max(0, index - 600), index)) || GUARD.test(after)
}

type Finder = { framework: string; re: RegExp; method: (m: RegExpExecArray) => string; path: (m: RegExpExecArray) => string; only?: RegExp }

const FINDERS: Finder[] = [
  { framework: 'Laravel', re: /Route::(get|post|put|patch|delete|any|match|resource|apiResource)\(\s*(?:\[[^\]]*\]\s*,\s*)?['"]([^'"]+)['"]/g, method: (m) => (/resource/i.test(m[1]) ? 'GET' : m[1].toUpperCase()), path: (m) => m[2], only: /\.php$/i },
  { framework: 'Express', re: /\b(?:app|router|server|api|routes|r)\.(get|post|put|patch|delete|all)\(\s*['"`](\/[^'"`]*)['"`]/g, method: (m) => m[1].toUpperCase(), path: (m) => m[2], only: /\.(js|jsx|ts|tsx|mjs|cjs)$/i },
  { framework: 'Flask', re: /@\w+\.route\(\s*['"]([^'"]+)['"](?:[^)]*methods\s*=\s*\[([^\]]*)\])?/g, method: (m) => (m[2] ? m[2].replace(/['"\s]/g, '').split(',')[0].toUpperCase() : 'GET'), path: (m) => m[1], only: /\.py$/i },
  { framework: 'FastAPI', re: /@\w+\.(get|post|put|patch|delete)\(\s*['"]([^'"]+)['"]/g, method: (m) => m[1].toUpperCase(), path: (m) => m[2], only: /\.py$/i },
  { framework: 'Django', re: /\b(?:re_)?path\(\s*r?['"]([^'"]*)['"]\s*,/g, method: () => 'GET', path: (m) => m[1], only: /urls\.py$/i },
  { framework: 'Rails', re: /^\s*(get|post|put|patch|delete|match)\s+['"]([^'"]+)['"]/gm, method: (m) => m[1].toUpperCase(), path: (m) => m[2], only: /routes\.rb$/i }
]

/** Next.js: the file's place in pages/ or app/ is its route. */
function nextRoute(rel: string): string | null {
  const parts = rel.split(sep).join('/')
  let m = /(?:^|\/)pages\/(.+?)\.(?:tsx?|jsx?)$/.exec(parts)
  if (m && !/(^|\/)(_app|_document|_error)$/.test(m[1])) return `/${m[1].replace(/(^|\/)index$/, '')}`
  m = /(?:^|\/)app\/(.*?)\/?(?:page|route)\.(?:tsx?|jsx?)$/.exec(parts)
  if (m) return `/${m[1].replace(/\([^)]*\)\/?/g, '')}`.replace(/\/+$/, '') || '/'
  return null
}

const PARAM_PATTERNS: RegExp[] = [
  /\$request->(?:input|get|query|post|has|string|integer|boolean)\(\s*['"](\w+)['"]/g,
  /\$_(?:GET|POST|REQUEST)\[\s*['"](\w+)['"]\s*\]/g,
  /\breq\.(?:query|body|params)\.(\w+)/g,
  /\breq\.(?:query|body)\[\s*['"](\w+)['"]\s*\]/g,
  /\brequest\.(?:args|form|values)\.get\(\s*['"](\w+)['"]/g,
  /\brequest\.(?:GET|POST)(?:\.get)?\(\s*['"](\w+)['"]/g,
  /\bparams\[\s*:(\w+)\s*\]/g
]

export function mapCode(root: string, o: { maxFiles?: number; maxBytes?: number } = {}): CodeMap {
  const routes: CodeRoute[] = []
  const params: Record<string, string[]> = {}
  const frameworks = new Set<string>()
  let files = 0
  const maxFiles = o.maxFiles ?? 4000
  const maxBytes = o.maxBytes ?? 400 * 1024
  const walk = (dir: string, depth: number): void => {
    if (depth > 10 || files >= maxFiles) return
    let names: string[]
    try {
      names = readdirSync(dir)
    } catch {
      return
    }
    for (const n of names) {
      if (files >= maxFiles) return
      if (SKIP.has(n) || (n.startsWith('.') && n !== '.')) continue
      const p = join(dir, n)
      let st
      try {
        st = statSync(p)
      } catch {
        continue
      }
      if (st.isDirectory()) walk(p, depth + 1)
      else if (st.isFile() && CODE.test(n) && st.size <= maxBytes) {
        files++
        let text: string
        try {
          text = readFileSync(p, 'utf8')
        } catch {
          continue
        }
        const rel = relative(root, p)
        for (const f of FINDERS) {
          if (f.only && !f.only.test(n)) continue
          f.re.lastIndex = 0
          let m: RegExpExecArray | null
          while ((m = f.re.exec(text))) {
            const path = f.path(m)
            if (!path) continue
            frameworks.add(f.framework)
            routes.push({ method: f.method(m), path, file: rel, line: lineOf(text, m.index), guarded: guarded(text, m.index), framework: f.framework })
          }
        }
        const nx = nextRoute(rel)
        if (nx) {
          frameworks.add('Next.js')
          routes.push({ method: /route\.(t|j)sx?$/.test(n) ? 'GET' : 'GET', path: nx, file: rel, line: 1, guarded: GUARD.test(text.slice(0, 4000)), framework: 'Next.js' })
        }
        if (/\.php$/i.test(n) && !frameworks.has('Laravel') && /(^|[\\/])(public|public_html|www|htdocs|web)[\\/]/i.test(rel + sep) === true) {
          const web = rel.split(sep).slice(1).join('/')
          if (web && !/(^|\/)(vendor|includes?|lib|config)\//i.test(web)) {
            frameworks.add('PHP')
            routes.push({ method: 'GET', path: `/${web}`, file: rel, line: 1, guarded: GUARD.test(text.slice(0, 3000)), framework: 'PHP' })
          }
        }
        for (const re of PARAM_PATTERNS) {
          re.lastIndex = 0
          let m: RegExpExecArray | null
          while ((m = re.exec(text))) {
            const name = m[1]
            if (name.length < 2 || name.length > 40) continue
            ;(params[name] ??= []).includes(rel) || params[name].push(rel)
          }
        }
      }
    }
  }
  walk(root, 0)
  const seen = new Set<string>()
  const uniq = routes.filter((r) => {
    const k = `${r.method} ${r.path}`
    if (seen.has(k)) return false
    seen.add(k)
    return true
  })
  return { routes: uniq.slice(0, 1500), params, frameworks: [...frameworks], files }
}

/** Routes a person can open with a plain GET, as paths. */
export const getPaths = (m: CodeMap): string[] => [...new Set(m.routes.filter((r) => /^(GET|ANY|ALL|MATCH)$/i.test(r.method)).map((r) => fillPath(r.path)))].filter((p) => !/\*|\.\./.test(p)).slice(0, 400)

/** Routes that look private and show no access check in the code around them: leads to confirm live. */
export const unguardedPrivate = (m: CodeMap): CodeRoute[] => m.routes.filter((r) => /^(GET|ANY|ALL|MATCH)$/i.test(r.method) && !r.guarded && PRIVATE_PATH.test(fillPath(r.path))).slice(0, 40)

/** Parameter names the code reads, most used first: what to try on every page. */
export const paramNames = (m: CodeMap, cap = 60): string[] => Object.entries(m.params).sort((a, b) => b[1].length - a[1].length).map(([k]) => k).slice(0, cap)
