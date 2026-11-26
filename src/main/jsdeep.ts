/**
 * The JavaScript analyzer: reads a site's own scripts the way a person reviewing a front end would.
 *
 *   Maps        the site's endpoints, front-end routes, GraphQL operations and build variables
 *   Chunks      finds scripts the page does not load yet (webpack chunk lists), so lazy admin screens are not missed
 *   Source maps downloads a published source map, rebuilds the original files into the session folder, and
 *               looks for keys in the original source
 *   Risks       browser functions that run text as code, message listeners that never look at the sender,
 *               internal addresses, cloud storage names, library versions
 *
 * Everything is a plain GET of a file the site already serves to every visitor. Facts that were seen
 * (a public source map) are confirmed with proof. What the code merely names is "possible" or info.
 */
import { mkdirSync, writeFileSync } from 'fs'
import { dirname, join, resolve, sep } from 'path'
import type { Finding, Severity } from '../shared/types'
import { fid } from './scanners/parse'
import { endpointsIn, parseSourceMap, secretsIn, sourceMapUrl } from './seckit/recon'
import { isPublicLibrary, plausibleVersion, seriesNote } from './decoys'
import { libsIn, proofOf, type Product } from './seckit/confirm'
import { cloudRefs, type Refs } from './mobilestatic'
import { guardedFetch } from './guardedfetch'

// ---------------------------------------------------------------- Reading one script

export interface JsDeep {
  routes: string[]
  graphql: string[]
  envVars: string[]
  sinks: { kind: string; count: number }[]
  /** Message listeners, and how many of them never look at who sent the message. */
  messages: { listeners: number; unchecked: number }
  internal: string[]
  notes: string[]
  chunks: string[]
  refs: Refs
}

const uniq = (a: string[]): string[] => [...new Set(a)]

const SINKS: [string, RegExp][] = [
  ['eval()', /\beval\s*\(/g],
  ['new Function()', /\bnew\s+Function\s*\(/g],
  ['document.write()', /\bdocument\.write(?:ln)?\s*\(/g],
  ['innerHTML', /\.(?:inner|outer)HTML\s*\+?=(?!=)/g],
  ['insertAdjacentHTML()', /\.insertAdjacentHTML\s*\(/g],
  ['dangerouslySetInnerHTML', /dangerouslySetInnerHTML/g],
  ['v-html', /\bv-html\b/g],
  ['bypassSecurityTrust', /bypassSecurityTrust(?:Html|Script|Url|ResourceUrl)/g]
]

/** The vendor and framework bundles name their own internals: only the app's own code is judged. */
export const isVendor = (url: string): boolean => /node_modules|vendor|chunk-vendors|framework[-.]|polyfills?|webpack-runtime|turbopack|\/runtime[-.]|jquery|bootstrap|lodash|moment|react-dom|angular\.min|\.min\.js.*(?:cdn|lib)/i.test(url)

/** A script's own text: what it talks to, how it is wired and what it does with the page. */
export function analyzeJs(text: string, url: string): JsDeep {
  const vendor = isVendor(url)
  const routes: string[] = []
  for (const m of text.matchAll(/\bpath\s*:\s*["'`](\/[\w\-/:.*]{1,100})["'`]/g)) routes.push(m[1])
  for (const m of text.matchAll(/\b(?:routerLink|to|href)\s*[=:]\s*["'`](\/[a-z][\w\-/:.]{1,100})["'`]/gi)) routes.push(m[1])
  const graphql: string[] = []
  for (const m of text.matchAll(/\b(query|mutation|subscription)\s+([A-Za-z_]\w{2,60})\s*[({]/g)) graphql.push(`${m[1]} ${m[2]}`)
  const envVars: string[] = []
  for (const m of text.matchAll(/\b(?:process\.env|import\.meta\.env)\.([A-Z][A-Z0-9_]{2,60})\b/g)) envVars.push(m[1])
  for (const m of text.matchAll(/\b((?:NEXT_PUBLIC|REACT_APP|VITE|VUE_APP|NG_APP|EXPO_PUBLIC|GATSBY)_[A-Z0-9_]{2,60})\b/g)) envVars.push(m[1])
  const sinks = vendor ? [] : SINKS.map(([kind, re]) => ({ kind, count: [...text.matchAll(re)].length })).filter((s) => s.count > 0)
  let listeners = 0
  let unchecked = 0
  if (!vendor)
    for (const m of text.matchAll(/addEventListener\(\s*["'`]message["'`]/g)) {
      listeners++
      const rest = text.slice(m.index! + 10, m.index! + 700)
      const next = rest.search(/addEventListener\(\s*["'`]message["'`]/)
      if (!/\.origin\b|\.source\b/.test(next > 0 ? rest.slice(0, next) : rest)) unchecked++
    }
  const internal = uniq([
    ...[...text.matchAll(/\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?::\d+)?\b/g)].map((m) => m[0]),
    ...[...text.matchAll(/\b([a-z0-9][a-z0-9.-]*\.(?:internal|corp|intranet|lan))\b/gi)].map((m) => m[1].toLowerCase()),
    ...[...text.matchAll(/["'`]https?:\/\/(localhost:\d+[^"'`\s]{0,60})["'`]/g)].map((m) => `localhost:${m[1].split('/')[0].split(':')[1]}`)
  ]).slice(0, 20)
  const notes = vendor ? [] : [...text.matchAll(/\/\/\s*((?:TODO|FIXME|HACK|XXX)[^\n]{0,140}|[^\n]{0,60}(?:password|secret|token|api[_ -]?key|backdoor)[^\n]{0,80})/gi)].map((m) => m[1].trim()).filter((n) => /(auth|secur|password|secret|token|key|admin|remove|backdoor|bypass)/i.test(n)).slice(0, 8)
  return { routes: uniq(routes).slice(0, 200), graphql: uniq(graphql).slice(0, 100), envVars: uniq(envVars).slice(0, 60), sinks, messages: { listeners, unchecked }, internal, notes, chunks: chunkUrls(text, url), refs: cloudRefs(text) }
}

/**
 * Scripts the page does not load yet. Webpack keeps a list of chunk ids and hashes in its runtime,
 * with the folder before it and the ending after it, so every lazy-loaded screen can be named.
 */
export function chunkUrls(js: string, base: string): string[] {
  const out = new Set<string>()
  let origin: string
  try {
    origin = new URL(base).origin
  } catch {
    return []
  }
  const map = /\{((?:\s*(?:\d+|"[\w.\-]+"|'[\w.\-]+'|[A-Za-z_$][\w$]*)\s*:\s*["'][0-9a-f]{6,20}["']\s*,?){3,})\}/g
  for (const m of js.matchAll(map)) {
    const before = js.slice(Math.max(0, m.index! - 400), m.index)
    const after = js.slice(m.index! + m[0].length, m.index! + m[0].length + 160)
    const folder = [...before.matchAll(/["'`]((?:[\w.\-]+\/)+)["'`]/g)].pop()?.[1] ?? ''
    const end = /["'`](\.chunk\.js|\.min\.js|\.js)["'`]/.exec(after)?.[1] ?? '.js'
    for (const e of m[1].matchAll(/(\d+|"[\w.\-]+"|'[\w.\-]+'|[A-Za-z_$][\w$]*)\s*:\s*["']([0-9a-f]{6,20})["']/g)) {
      const id = e[1].replace(/^["']|["']$/g, '')
      try {
        out.add(new URL(`${folder}${id}.${e[2]}${end}`, folder ? `${origin}/` : new URL('.', base).href).href)
      } catch {
        // A pattern that is not a real address.
      }
    }
  }
  for (const m of js.matchAll(/["'`]((?:\.{0,2}\/)?(?:static|assets|js|chunks|_next\/static)\/[\w\-./]*\.js)["'`]/g)) {
    try {
      out.add(new URL(m[1].startsWith('/') ? m[1] : `/${m[1].replace(/^\.\/?/, '')}`, origin).href)
    } catch {
      // Not an address.
    }
  }
  return [...out].filter((u) => u.startsWith(origin)).slice(0, 300)
}

// ---------------------------------------------------------------- Original source from a source map

/** A path from a source map that is safe to write under a folder, or null. */
export function safeSourcePath(p: string): string | null {
  let q = p.replace(/^[a-z][a-z0-9+.-]*:\/\/(?:\[[^\]]*\]\/)?/i, '').replace(/\?.*$/, '').replace(/\\/g, '/')
  q = q.split('/').filter((x) => x && x !== '.' && x !== '..' && !/^[a-z]:$/i.test(x)).join('/')
  q = q.replace(/[^\w.\-@/ ]/g, '_')
  if (!q || q.length > 200 || /(^|\/)node_modules\//.test(q) || /(^|\/)webpack\/(bootstrap|runtime)/.test(q)) return null
  return q
}

export interface Recovered {
  written: number
  bytes: number
  /** Keys that sit in the original source: the kind, the file and the first four characters. */
  keys: { kind: string; file: string; masked: string; severity: Severity }[]
}

/** Writes the original files a source map carries under `dir`, and looks for keys in them. */
export function recoverSources(mapText: string, dir: string, o: { maxFiles?: number; maxBytes?: number } = {}): Recovered {
  const out: Recovered = { written: 0, bytes: 0, keys: [] }
  let m: { sources?: string[]; sourcesContent?: (string | null)[]; sections?: { map?: { sources?: string[]; sourcesContent?: (string | null)[] } }[] }
  try {
    m = JSON.parse(mapText)
  } catch {
    return out
  }
  const parts = Array.isArray(m.sections) ? m.sections.map((s) => s.map ?? {}) : [m]
  const root = resolve(dir)
  for (const part of parts)
    (part.sources ?? []).forEach((src, i) => {
      const content = part.sourcesContent?.[i]
      if (typeof content !== 'string' || out.written >= (o.maxFiles ?? 1500) || out.bytes > (o.maxBytes ?? 30_000_000)) return
      const rel = safeSourcePath(src)
      if (!rel) return
      const file = resolve(root, rel)
      if (!file.startsWith(root + sep)) return
      mkdirSync(dirname(file), { recursive: true })
      writeFileSync(file, content)
      out.written++
      out.bytes += content.length
      for (const k of secretsIn(content)) if (k.severity !== 'info') out.keys.push({ kind: k.kind, file: rel, masked: k.masked, severity: k.severity })
    })
  return out
}

// ---------------------------------------------------------------- Reading all of a site's scripts

export interface ScriptInfo {
  url: string
  bytes: number
  endpoints: string[]
  routes: string[]
  graphql: string[]
  envVars: string[]
  libs: Product[]
  sourceMap?: { url: string; files: number; recovered: number }
}

export interface JsCrawl {
  scripts: ScriptInfo[]
  findings: Finding[]
  endpoints: string[]
  routes: string[]
  graphql: string[]
  envVars: string[]
  /** Other sites the scripts talk to. */
  hosts: string[]
  libs: Product[]
  refs: Refs
  /** Scripts read, and scripts that were only named by a chunk list and then read. */
  chunksFound: number
}

export interface CrawlOptions {
  scripts: string[]
  /** Only scripts on these sites are read. */
  allowed: (url: string) => boolean
  headers?: Record<string, string>
  fetchImpl?: typeof fetch
  cancelled?: () => boolean
  paused?: () => boolean
  note?: (t: string) => void
  /** Where recovered original source is written. Left out: source maps are checked but not written. */
  sourceDir?: string
  cap?: number
  delayMs?: number
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))

export async function crawlJs(o: CrawlOptions): Promise<JsCrawl> {
  const res: JsCrawl = { scripts: [], findings: [], endpoints: [], routes: [], graphql: [], envVars: [], hosts: [], libs: [], refs: { firebase: [], s3: [], gcs: [] }, chunksFound: 0 }
  const doFetch = o.fetchImpl ?? guardedFetch()
  const seen = new Set<string>()
  const queue = [...new Set(o.scripts)]
  const cap = o.cap ?? 150
  const internal: { url: string; list: string[] }[] = []
  const sinks = new Map<string, number>()
  const unchecked: string[] = []
  const notes: { url: string; note: string }[] = []
  const hosts = new Set<string>()
  const get = async (url: string): Promise<{ status: number; headers: Headers; text: string } | null> => {
    try {
      const r = await doFetch(url, { redirect: 'manual', headers: { 'User-Agent': 'MacSec JavaScript analysis', ...(o.headers ?? {}) }, signal: AbortSignal.timeout(20000) })
      return { status: r.status, headers: r.headers, text: (await r.text()).slice(0, 6_000_000) }
    } catch {
      return null
    }
  }
  while (queue.length && res.scripts.length < cap && !o.cancelled?.()) {
    while (o.paused?.() && !o.cancelled?.()) await sleep(300)
    const url = queue.shift()!.replace(/#.*$/, '')
    if (seen.has(url) || !o.allowed(url)) continue
    seen.add(url)
    o.note?.(`Reading script ${res.scripts.length + 1}`)
    const r = await get(url)
    if (!r || r.status !== 200 || !/javascript|ecmascript|text\/plain|octet-stream|^$/i.test(r.headers.get('content-type') ?? '')) continue
    const vendor = isVendor(url)
    const d = analyzeJs(r.text, url)
    const info: ScriptInfo = { url, bytes: r.text.length, endpoints: vendor ? [] : endpointsIn(r.text), routes: vendor ? [] : d.routes, graphql: d.graphql, envVars: vendor ? [] : d.envVars, libs: libsIn(url, r.text).filter((l) => plausibleVersion(l.name, l.version)).map((l) => ({ ...l, note: [l.note, seriesNote(l.name, l.version)].filter(Boolean).join(' '), proof: proofOf({ url, status: r.status, headers: r.headers, body: r.text.slice(0, 200000), shows: [l.from] }) })) }
    for (const u of d.chunks) if (!seen.has(u)) {
      queue.push(u)
      res.chunksFound++
    }
    for (const e of info.endpoints) {
      const h = /^https?:\/\/([^/:]+)/i.exec(e)?.[1]
      if (h && !o.allowed(e)) hosts.add(h.toLowerCase())
    }
    for (const k of ['firebase', 's3', 'gcs'] as const) res.refs[k].push(...d.refs[k])
    if (d.internal.length) internal.push({ url, list: d.internal })
    for (const s of d.sinks) sinks.set(s.kind, (sinks.get(s.kind) ?? 0) + s.count)
    if (d.messages.unchecked) unchecked.push(url)
    for (const n of d.notes) notes.push({ url, note: n })

    // The source map: where it points, or the same name with .map.
    const mapUrl = sourceMapUrl(r.text, url, r.headers.get('sourcemap') ?? r.headers.get('x-sourcemap')) ?? `${url.replace(/\?.*$/, '')}.map`
    if (o.allowed(mapUrl)) {
      const m = await get(mapUrl)
      const parsed = m && m.status === 200 ? parseSourceMap(m.text) : null
      if (m && parsed) {
        const rec = o.sourceDir && parsed.hasContent ? recoverSources(m.text, join(o.sourceDir, fid(mapUrl))) : { written: 0, bytes: 0, keys: [] }
        info.sourceMap = { url: mapUrl, files: parsed.files, recovered: rec.written }
        res.findings.push({ id: fid('map', mapUrl), tool: 'MacSec', category: 'web', severity: isPublicLibrary(mapUrl) ? 'info' : parsed.hasContent ? 'medium' : 'low', confidence: 'confirmed', title: `${isPublicLibrary(mapUrl) ? 'Library source map (already public)' : 'Source map public'}: ${parsed.files} original files`, url: mapUrl, file: mapUrl, cwe: 'CWE-540', description: `The original source code${parsed.hasContent ? ', with its full text,' : ''} can be rebuilt from this file. Files include: ${parsed.sample.join(', ')}.${rec.written ? ` ${rec.written} files were rebuilt into the session folder so you can read the code the way an attacker would.` : ''}`, fix: 'Stop publishing .map files to production (productionBrowserSourceMaps: false in Next.js, build.sourcemap: false in Vite), or upload them only to your error tracker.', proof: proofOf({ url: mapUrl, status: m.status, headers: m.headers, body: m.text.slice(0, 200000), shows: ['the map downloaded without signing in and parses as a source map', `it lists ${parsed.files} original files`, parsed.hasContent ? 'it includes the full text of the source files' : 'it lists file names only', `for example ${parsed.sample.slice(0, 5).join(', ')}`] }) })
        for (const k of rec.keys.slice(0, 20))
          res.findings.push({ id: fid('srckey', mapUrl, k.file, k.kind, k.masked), tool: 'MacSec', category: 'web', severity: /node_modules\//.test(k.file) || isPublicLibrary(mapUrl) ? 'info' : k.severity, confidence: 'possible', title: `${k.kind} in the original source: ${k.file}`, url: mapUrl, file: k.file, description: `Starts with ${k.masked}. It sits in code rebuilt from the public source map. MacSec does not test whether the key still works.`, fix: 'Revoke the key, keep it on the server, and stop publishing source maps.', proof: proofOf({ url: mapUrl, status: m.status, headers: m.headers, body: m.text.slice(0, 200000), shows: [`${k.kind} pattern in ${k.file}`, `starts with ${k.masked}`] }) })
      }
    }
    res.scripts.push(info)
    await sleep(o.delayMs ?? 80)
  }

  res.endpoints = uniq(res.scripts.flatMap((s) => s.endpoints)).sort()
  res.routes = uniq(res.scripts.flatMap((s) => s.routes)).sort()
  res.graphql = uniq(res.scripts.flatMap((s) => s.graphql)).sort()
  res.envVars = uniq(res.scripts.flatMap((s) => s.envVars)).sort()
  res.hosts = [...hosts].sort().slice(0, 60)
  res.libs = res.scripts.flatMap((s) => s.libs)
  for (const k of ['firebase', 's3', 'gcs'] as const) res.refs[k] = uniq(res.refs[k]).slice(0, 6)

  const info = (key: string, title: string, description: string, url: string, severity: Severity = 'info', confidence: 'confirmed' | 'possible' = 'possible'): Finding => ({ id: fid('jsdeep', key, url), tool: 'MacSec', category: 'web', severity, confidence, title, url, file: url, description })
  const first = res.scripts[0]?.url ?? ''
  const hidden = res.routes.filter((x) => /(admin|internal|debug|staging|dev|beta|private|manage|console|backoffice|superuser|impersonat)/i.test(x))
  if (res.routes.length) res.findings.push({ ...info('routes', `The front end names ${res.routes.length} routes${hidden.length ? `, ${hidden.length} look private` : ''}`, `${res.routes.slice(0, 60).join(', ')}. Screens that are hidden from the menu are often still reachable, and the server may not check who is asking. ${hidden.length ? `Worth a hand test: ${hidden.slice(0, 12).join(', ')}.` : ''}`, first), fix: 'Check every route here is also protected on the server, not only hidden in the interface.' })
  if (res.graphql.length) res.findings.push(info('graphql', `GraphQL operations written in the front end: ${res.graphql.length}`, `${res.graphql.slice(0, 40).join(', ')}. Mutations show what the API can change: test each one with another account's ids.`, first))
  if (res.envVars.length) res.findings.push(info('env', `Build variables named in the scripts: ${res.envVars.length}`, `${res.envVars.slice(0, 40).join(', ')}. Names only. Anything here is public, so none of them may hold a secret.`, first))
  if (internal.length) res.findings.push({ ...info('internal', 'Internal or development addresses are written in public scripts', internal.slice(0, 5).map((i) => `${i.list.slice(0, 4).join(', ')} (in ${i.url})`).join('; '), internal[0].url, 'low'), cwe: 'CWE-200', fix: 'Remove leftover development addresses from production builds. They show how the network behind the site is laid out.' })
  if (unchecked.length) res.findings.push({ ...info('postmessage', `Message listeners that never check who sent the message (${unchecked.length} script${unchecked.length === 1 ? '' : 's'})`, `A page can post a message to this one from any other site. If the listener acts on it without checking event.origin, another site can steer it. Scripts: ${unchecked.slice(0, 5).join(', ')}. Read the handler to see what it does with the message.`, unchecked[0], 'low'), cwe: 'CWE-346', fix: 'Check event.origin against an exact allow-list before using event.data.' })
  if (sinks.size) res.findings.push(info('sinks', 'Browser functions that turn text into code or markup are used', `${[...sinks].map(([k, n]) => `${k} ${n}`).join(', ')}. Normal in many apps. They matter only where the text can come from a visitor: search for these in the rebuilt source and follow where the data comes from.`, first))
  if (notes.length) res.findings.push(info('notes', 'Developer comments about security are left in public scripts', notes.slice(0, 6).map((n) => n.note.slice(0, 120)).join(' | '), notes[0].url, 'low'))
  const refs = res.refs
  if (refs.firebase.length + refs.s3.length + refs.gcs.length) res.findings.push(info('cloud', 'Cloud storage addresses are named in the scripts', [...refs.firebase, ...refs.s3, ...refs.gcs].join(', ') + '. Each is worth one read-only check for public access.', first))
  return res
}
