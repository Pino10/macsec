/**
 * Choosing skills for a review, shared by Laramac and MacSec (keep both copies of src/main/seckit
 * the same).
 *
 * Every skill a review could load is listed (the app's own, your own, and each skill pack's),
 * the project's stack is detected from its files, and the skills that fit it are switched on.
 * You can switch any of them on or off; the review then loads exactly those, from a folder
 * built for that review. More skills is not better: each one costs the reviewer attention and
 * time, so the estimate follows what you pick.
 */
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'fs'
import { join } from 'path'
import { SKILLS } from './skills'
import { SKILL_PACKS, packState } from './skillpacks'

export interface SkillItem {
  /** own:name, mine:name or pack:<pack>:<name>. */
  id: string
  name: string
  /** Where it comes from: the app, Your skills, Trail of Bits, Sentry, Cloudflare, Anthropic. */
  source: string
  about: string
  /** Extra reference guides that come with it (Cloudflare's audit has 14). */
  guides: number
  /** A single skill folder, or a whole plugin (Trail of Bits ships plugins). */
  kind: 'skill' | 'plugin'
  dir: string
}

/** The app's own skills that are about recon or internal, not a code review. */
const NOT_FOR_REVIEWS = new Set(['recon-methodology', 'js-recon', 'attack-surface-report', 'local-model-review'])

const firstSentence = (s: string): string => (s.split(/(?<=\.)\s/)[0] ?? s).trim().slice(0, 220)

function countGuides(dir: string): number {
  let n = 0
  const walk = (d: string, depth: number): void => {
    if (depth > 4) return
    let names: string[] = []
    try {
      names = readdirSync(d)
    } catch {
      return
    }
    for (const name of names) {
      const p = join(d, name)
      let st
      try {
        st = statSync(p)
      } catch {
        continue
      }
      if (st.isDirectory()) walk(p, depth + 1)
      else if (/\.md$/i.test(name) && name !== 'SKILL.md' && !/^readme\.md$/i.test(name)) n++
    }
  }
  walk(dir, 0)
  return n
}

function describe(skillDir: string): string {
  try {
    const md = readFileSync(join(skillDir, 'SKILL.md'), 'utf8')
    const m = /^description:\s*(.+)$/m.exec(md)
    return m ? firstSentence(m[1].replace(/^["']|["']$/g, '')) : ''
  } catch {
    return ''
  }
}

function pluginAbout(dir: string): string {
  try {
    return firstSentence(String((JSON.parse(readFileSync(join(dir, '.claude-plugin', 'plugin.json'), 'utf8')) as { description?: string }).description ?? ''))
  } catch {
    return ''
  }
}

const titled = (n: string): string => n.replace(/-/g, ' ').replace(/^\w/, (c) => c.toUpperCase())

/**
 * Every skill a review can use. `ownDir` is the app's plugin (its skills/ folder), `mineDir`
 * your own skills plugin, `packsRoot` where skill packs are kept.
 */
export function skillCatalog(o: { app: string; ownDir: string; mineDir?: string; packsRoot: string }): SkillItem[] {
  const out: SkillItem[] = []
  for (const [name, s] of Object.entries(SKILLS)) {
    if (NOT_FOR_REVIEWS.has(name)) continue
    out.push({ id: `own:${name}`, name: titled(name), source: o.app, about: firstSentence(s.description), guides: 0, kind: 'skill', dir: join(o.ownDir, 'skills', name) })
  }
  if (o.mineDir && existsSync(join(o.mineDir, 'skills'))) {
    for (const name of readdirSync(join(o.mineDir, 'skills'))) {
      const dir = join(o.mineDir, 'skills', name)
      if (existsSync(join(dir, 'SKILL.md'))) out.push({ id: `mine:${name}`, name: titled(name), source: 'Your skills', about: describe(dir), guides: countGuides(dir), kind: 'skill', dir })
    }
  }
  for (const pack of SKILL_PACKS) {
    const st = packState(o.packsRoot, pack.id)
    if (!st.installed) continue
    if (pack.layout === 'plugins') {
      for (const n of st.loaded) {
        const dir = join(o.packsRoot, pack.id, 'repo', 'plugins', n)
        if (existsSync(dir)) out.push({ id: `pack:${pack.id}:${n}`, name: titled(n), source: pack.name, about: pluginAbout(dir), guides: countGuides(dir), kind: 'plugin', dir })
      }
    } else {
      const skills = join(o.packsRoot, pack.id, 'plugin', 'skills')
      if (!existsSync(skills)) continue
      for (const n of readdirSync(skills)) {
        const dir = join(skills, n)
        if (existsSync(join(dir, 'SKILL.md'))) out.push({ id: `pack:${pack.id}:${n}`, name: titled(n.replace(new RegExp(`^${pack.id}-`), '')), source: pack.name, about: describe(dir), guides: countGuides(dir), kind: 'skill', dir })
      }
    }
  }
  return out
}

export type StackTag =
  | 'php' | 'laravel' | 'wordpress' | 'symfony' | 'js' | 'ts' | 'react' | 'vue' | 'next' | 'node-api' | 'electron' | 'ai'
  | 'python' | 'django' | 'go' | 'rust' | 'c' | 'solidity' | 'android' | 'ios' | 'docker' | 'terraform' | 'gha'
  | 'supabase' | 'firebase' | 'claude' | 'mobile'

/** What a project is made of, from the files at its top (and a few known places). */
export function detectStack(root: string): StackTag[] {
  const t = new Set<StackTag>()
  const has = (p: string): boolean => existsSync(join(root, p))
  let top: string[] = []
  try {
    top = readdirSync(root)
  } catch {
    return []
  }
  const read = (p: string): string => {
    try {
      return readFileSync(join(root, p), 'utf8')
    } catch {
      return ''
    }
  }
  if (has('composer.json') || top.some((n) => n.endsWith('.php'))) t.add('php')
  if (has('artisan')) t.add('laravel')
  if (has('wp-config.php') || has('wp-content')) t.add('wordpress')
  if (has('symfony.lock') || has('bin/console')) t.add('symfony')
  const pkg = read('package.json')
  if (pkg) {
    t.add('js')
    if (has('tsconfig.json')) t.add('ts')
    const deps = pkg.toLowerCase()
    if (deps.includes('"react"')) t.add('react')
    if (deps.includes('"vue"') || deps.includes('"nuxt"')) t.add('vue')
    if (deps.includes('"next"')) t.add('next')
    if (/"(express|fastify|koa|@nestjs\/core|hono)"/.test(deps)) t.add('node-api')
    if (deps.includes('"electron"')) t.add('electron')
    if (/"(openai|@anthropic-ai\/sdk|ai|@ai-sdk\/[a-z]+|langchain|@langchain\/core)"/.test(deps)) t.add('ai')
    if (deps.includes('"@supabase/supabase-js"')) t.add('supabase')
    if (deps.includes('"firebase"') || deps.includes('"firebase-admin"')) t.add('firebase')
    if (deps.includes('"react-native"') || deps.includes('"expo"')) t.add('mobile')
  }
  const py = read('requirements.txt') + read('pyproject.toml')
  if (py || top.some((n) => n.endsWith('.py'))) t.add('python')
  if (/django/i.test(py) || has('manage.py')) t.add('django')
  if (/openai|anthropic|langchain/i.test(py)) t.add('ai')
  if (has('go.mod')) t.add('go')
  if (has('Cargo.toml')) t.add('rust')
  if (top.some((n) => /\.(c|h|cc|cpp)$/.test(n)) || has('CMakeLists.txt') || has('Makefile')) t.add('c')
  if (has('hardhat.config.js') || has('foundry.toml') || top.some((n) => n.endsWith('.sol'))) t.add('solidity')
  if (has('android') || has('app/src/main/AndroidManifest.xml')) t.add('android')
  if (has('ios') || top.some((n) => n.endsWith('.xcodeproj'))) t.add('ios')
  if (has('Dockerfile') || has('docker-compose.yml') || has('compose.yaml') || has('compose.yml')) t.add('docker')
  if (top.some((n) => n.endsWith('.tf') || n.endsWith('.bicep'))) t.add('terraform')
  if (has('.github/workflows')) t.add('gha')
  if (has('supabase')) t.add('supabase')
  if (has('firebase.json')) t.add('firebase')
  if (has('.claude')) t.add('claude')
  return [...t]
}

const ALWAYS_OWN = ['review-vectors', 'security-code-review', 'threat-model', 'injection-catalog', 'auth-session-review', 'business-logic-review', 'secrets-triage', 'dependency-triage', 'supply-chain-review', 'privacy-data-review', 'security-report']
/** The app's versions of Trail of Bits methods: used when Trail of Bits is not installed. */
const OWN_LIKE_TOB: Record<string, string> = { 'audit-context': 'audit-context-building', 'entry-points': 'entry-point-analyzer', 'variant-analysis': 'variant-analysis', 'false-positive-check': 'fp-check', 'insecure-defaults': 'insecure-defaults', 'sharp-edges': 'sharp-edges' }
const TOB_GENERAL = ['audit-context-building', 'entry-point-analyzer', 'variant-analysis', 'fp-check', 'insecure-defaults', 'sharp-edges', 'supply-chain-risk-auditor', 'vulnerability-triage-brocards']

/** The skills that fit a project's stack: on by default. */
export function recommend(items: SkillItem[], stack: StackTag[], o: { changesOnly?: boolean } = {}): string[] {
  const s = new Set(stack)
  const any = (...tags: StackTag[]): boolean => tags.some((x) => s.has(x))
  const backend = any('php', 'laravel', 'wordpress', 'symfony', 'node-api', 'next', 'python', 'django', 'go', 'rust')
  const tob = items.some((i) => i.id.startsWith('pack:trailofbits:'))
  const on = new Set<string>()
  for (const i of items) {
    const [kind, a, b] = i.id.split(':')
    const name = kind === 'pack' ? b : a
    if (kind === 'mine') on.add(i.id)
    else if (kind === 'own') {
      if (ALWAYS_OWN.includes(name)) on.add(i.id)
      else if (name in OWN_LIKE_TOB && !tob) on.add(i.id)
      else if (name === 'api-security-review' && (backend || stack.length === 0)) on.add(i.id)
      else if (name === 'client-side-review' && (any('js', 'react', 'vue', 'next', 'wordpress') || stack.length === 0)) on.add(i.id)
      else if (name === 'infra-config-review' && any('docker', 'terraform', 'gha')) on.add(i.id)
      else if (name === 'cloud-baas-review' && any('supabase', 'firebase')) on.add(i.id)
      else if (name === 'ai-app-review' && any('ai')) on.add(i.id)
      else if (name === 'electron-review' && any('electron')) on.add(i.id)
      else if (name === 'change-review' && o.changesOnly) on.add(i.id)
    } else if (kind === 'pack') {
      if (a === 'anthropic' || a === 'cloudflare') on.add(i.id)
      else if (a === 'sentry') {
        if (['security-review', 'find-bugs', 'security-model', 'secret-serialization'].includes(name)) on.add(i.id)
        else if (name === 'gha-security-review' && any('gha')) on.add(i.id)
        else if (name === 'django-access-review' && any('django')) on.add(i.id)
        else if (name === 'claude-settings-audit' && any('claude')) on.add(i.id)
      } else if (a === 'trailofbits') {
        if (TOB_GENERAL.includes(name)) on.add(i.id)
        else if (name === 'differential-review' && o.changesOnly) on.add(i.id)
        else if (name === 'agentic-actions-auditor' && any('gha')) on.add(i.id)
        else if (name === 'firebase-apk-scanner' && any('android') && any('firebase')) on.add(i.id)
        else if (['c-review', 'zeroize-audit', 'constant-time-analysis'].includes(name) && any('c', 'rust')) on.add(i.id)
        else if (name === 'rust-review' && any('rust')) on.add(i.id)
        else if (name === 'building-secure-contracts' && any('solidity')) on.add(i.id)
      }
    }
  }
  return items.filter((i) => on.has(i.id)).map((i) => i.id)
}

export type ReviewerSpeed = 'claude' | 'claude-free' | 'claude-local' | 'codex' | 'gemini' | 'coderabbit' | 'model' | string

/** A rough range in minutes: bigger projects, more skills and slower models take longer. */
export function estimateMinutes(o: { files: number; skills: number; guides?: number; reviewer: ReviewerSpeed }): [number, number] {
  const speed: Record<string, number> = { claude: 1, 'claude-free': 1.6, 'claude-local': 3, codex: 1.1, gemini: 1.1, coderabbit: 0.6, model: 2.5 }
  const m = (2 + o.files / 140 + o.skills * 0.3 + (o.guides ?? 0) * 0.08) * (speed[o.reviewer] ?? 1.2)
  const lo = Math.max(2, Math.round(m * 0.8))
  return [lo, Math.max(lo + 1, Math.round(m * 1.4))]
}

/**
 * The folders to pass to Claude Code (--plugin-dir) for exactly these skills: one plugin built in
 * `outDir` with the chosen single skills, plus each chosen whole plugin as it is.
 */
export function buildSkillSet(items: SkillItem[], chosen: string[], outDir: string): string[] {
  const pick = new Set(chosen)
  const selected = items.filter((i) => pick.has(i.id))
  rmSync(outDir, { recursive: true, force: true })
  mkdirSync(join(outDir, '.claude-plugin'), { recursive: true })
  writeFileSync(join(outDir, '.claude-plugin', 'plugin.json'), JSON.stringify({ name: 'review-skills', version: '1.0.0', description: 'The skills chosen for this review.' }, null, 2))
  const used = new Set<string>()
  for (const i of selected.filter((x) => x.kind === 'skill')) {
    if (!existsSync(i.dir)) continue
    const base = i.dir.split('/').pop()!
    const name = used.has(base) ? `${i.id.split(':')[1]}-${base}` : base
    used.add(name)
    cpSync(i.dir, join(outDir, 'skills', name), { recursive: true })
  }
  return [outDir, ...selected.filter((x) => x.kind === 'plugin' && existsSync(x.dir)).map((x) => x.dir)]
}
