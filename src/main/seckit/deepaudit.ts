/**
 * Deep audit, shared by Laramac and MacSec (keep both copies of src/main/seckit the same).
 *
 * Two published security reviews, run through Claude Code on the AI you pick:
 *   cloudflare  Cloudflare's security-audit skill: six phases, many isolated agents that hunt by
 *               attack class, and a fresh agent that tries to disprove every candidate.
 *   anthropic   Anthropic's security review: one careful pass that reports only high-confidence problems.
 *
 * What the app promises, and how each promise is kept:
 *   - The project is read-only. Edits and writes to it are denied, and the project is measured
 *     before and after: if anything in it changed, the audit fails and says which files.
 *   - The audit can write only its own notes, in a folder inside the app's own folder.
 *   - No commands run (no Bash), no project code runs, and the web tools are off. Cloudflare's skill
 *     says to run target code only in an OS sandbox; there is none, so such leads stay "needs checking".
 *   - Nothing the AI claims is taken on trust: the app checks findings.json against Cloudflare's own
 *     schema and checks that every file and line it cites exists in the project.
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'fs'
import { isAbsolute, join, normalize } from 'path'

export type DeepEngine = 'cloudflare' | 'anthropic' | 'both'
export type DeepReviewer = 'claude' | 'claude-local' | 'claude-free' | 'claude-desktop'

export interface DeepEngineInfo {
  id: DeepEngine
  name: string
  about: string
  source: string
  license: string
  /** Rough minutes for a mid-sized project, on a hosted model. */
  minutes: [number, number]
}

export const DEEP_ENGINES: DeepEngineInfo[] = [
  {
    id: 'cloudflare',
    name: 'Cloudflare security audit',
    about: 'The most thorough: AI agents map the project, hunt for each kind of attack, and a fresh agent tries to disprove every candidate before it counts. Slow, but findings come with the code path that proves them.',
    source: 'github.com/cloudflare/security-audit-skill',
    license: 'MIT',
    minutes: [45, 180]
  },
  {
    id: 'anthropic',
    name: 'Claude Code security review',
    about: 'Anthropic’s own review: one careful pass that reports only high-confidence problems and filters out the usual false alarms. Fast.',
    source: 'github.com/anthropics/claude-code-security-review',
    license: 'MIT',
    minutes: [5, 25]
  },
  {
    id: 'both',
    name: 'Both, one after the other',
    about: 'Anthropic’s quick pass first, then Cloudflare’s full audit. The most coverage, and the longest wait.',
    source: 'both of the above',
    license: 'MIT',
    minutes: [50, 205]
  }
]

export const DEEP_REVIEWER_NAMES: Record<DeepReviewer, string> = {
  claude: 'Claude Code',
  'claude-local': 'Claude Code on your model (LM Studio or Ollama)',
  'claude-free': 'Claude Code on Free LLM API',
  'claude-desktop': 'Claude Desktop'
}

/** Where the code goes for each AI, in plain words. */
export const DEEP_REVIEWER_PRIVACY: Record<DeepReviewer, string> = {
  claude: 'The code it reads is sent to Anthropic, through your Claude account.',
  'claude-local': 'Nothing leaves this Mac: your own model reads the code.',
  'claude-free': 'The code it reads is sent to the free provider your Free LLM API chain picks.',
  'claude-desktop': 'You paste the request into the Claude app yourself; what it reads is sent to Anthropic.'
}

export function engineList(engine: DeepEngine): ('cloudflare' | 'anthropic')[] {
  return engine === 'both' ? ['anthropic', 'cloudflare'] : [engine]
}

// ---------------------------------------------------------------- What will run

export interface DeepPlanLine {
  label: string
  text: string
}

/** The "what is about to happen" list, shown before a deep audit starts. */
export function deepPlan(o: { engine: DeepEngine; reviewer: DeepReviewer; model?: string; packs: { id: string; name: string; commit: string | null }[]; app: string; outFolder: string; minutes?: [number, number] }): DeepPlanLine[] {
  const info = DEEP_ENGINES.find((e) => e.id === o.engine)!
  const used = engineList(o.engine).map((e) => {
    const pack = o.packs.find((p) => p.id === (e === 'cloudflare' ? 'cloudflare' : 'anthropic'))
    return `${e === 'cloudflare' ? 'Cloudflare security-audit' : 'Anthropic security-review'}${pack?.commit ? `, version ${pack.commit.slice(0, 7)}` : ''}`
  })
  const lines: DeepPlanLine[] = [
    { label: 'AI', text: `${DEEP_REVIEWER_NAMES[o.reviewer]}${o.model && o.reviewer !== 'claude' && o.reviewer !== 'claude-desktop' ? `, model ${o.model}` : ''}. ${DEEP_REVIEWER_PRIVACY[o.reviewer]}` },
    { label: 'Method', text: `${used.join(', then ')} (${info.license} licence, free). ${o.reviewer === 'claude-desktop' ? 'You run it in the Claude app.' : 'Loaded for this audit only; nothing is added to your own Claude setup.'}` },
    { label: 'Reads', text: 'Your project, read-only.' }
  ]
  if (o.reviewer !== 'claude-desktop') {
    lines.push(
      { label: 'Writes', text: `Only its own notes, in ${o.outFolder}. ${o.app} measures your project before and after, and stops with an error if anything in it changed.` },
      { label: 'Does not', text: 'Run commands, run your project’s code, or use the web. Leads that would need running code are listed as “needs checking”.' },
      { label: 'Checks', text: `${o.app} validates every finding against Cloudflare’s report format and confirms each file and line it cites exists, before anything is shown as confirmed.` }
    )
  }
  const [lo, hi] = o.minutes ?? info.minutes
  lines.push({ label: 'Time', text: `About ${lo} to ${hi} minutes on a mid-sized project${o.reviewer === 'claude-local' ? ' (longer on a local model)' : ''}. You can cancel any time.` })
  return lines
}

// ---------------------------------------------------------------- The Claude Code command

export interface DeepRunArgs {
  /** Run Claude Code here: the folder the audit writes into. */
  cwd: string
  args: string[]
  env: Record<string, string>
}

const ruleSafe = (p: string): boolean => isAbsolute(p) && !/[,()\n\r*?[\]]/.test(p)
/** Claude Code's rule for an absolute folder: a double slash, then the path. */
export const absRule = (p: string): string => `//${p.replace(/^\/+/, '').replace(/\/+$/, '')}/**`

/**
 * The Claude Code command line for one deep audit pass. `plugins` are the skill folders to load
 * (--plugin-dir); they are also made readable so the skill can open its own guides.
 */
export function deepClaudeArgs(o: { prompt: string; outDir: string; root: string; plugins: string[]; session: { id: string; name: string }; model?: string; localEnv?: Record<string, string> }): DeepRunArgs {
  for (const p of [o.outDir, o.root, ...o.plugins]) if (!ruleSafe(p)) throw new Error('A folder name has characters that cannot be used safely in a deep audit. Move the project to a plainer folder name.')
  const allow = ['Read', 'Grep', 'Glob', 'Skill', 'Agent', 'Task', `Edit(${absRule(o.outDir)})`, `Write(${absRule(o.outDir)})`]
  // Bare tool names remove those tools altogether; the folder rules make the project itself read-only.
  const deny = ['Bash', 'WebFetch', 'WebSearch', 'NotebookEdit', `Edit(${absRule(o.root)})`, `Write(${absRule(o.root)})`]
  return {
    cwd: o.outDir,
    args: [
      '-p',
      o.prompt,
      '--output-format',
      'text',
      '--allowedTools',
      allow.join(','),
      '--disallowedTools',
      deny.join(','),
      '--add-dir',
      o.root,
      ...o.plugins.flatMap((p) => ['--add-dir', p, '--plugin-dir', p]),
      '--session-id',
      o.session.id,
      '--name',
      o.session.name.slice(0, 80),
      ...(o.model ? ['--model', o.model] : [])
    ],
    env: o.localEnv ?? {}
  }
}

/** The request for one engine. `outDir` already exists and is the only place it may write. */
export function deepPrompt(o: { engine: 'cloudflare' | 'anthropic'; name: string; root: string; outDir: string; extraNotes?: string }): string {
  if (o.engine === 'anthropic') {
    return [
      `Run Anthropic's security review (the anthropic-security-review skill, the same as /security-review) on the project "${o.name}".`,
      `The project folder is ${o.root} (read-only). There is no git diff to review, so review the whole project: read its entry points, routes, authentication, data access and anything that handles user input. Report only high-confidence problems, as the skill says.`,
      `You cannot run commands. You may write notes only inside ${o.outDir}. Do not modify the project.`,
      `Write your result to ${join(o.outDir, 'REPORT.md')}. Then reply with the same report, ending with one fenced json block: {"findings":[{"severity":"high","title":"...","file":"relative/path","line":12,"cwe":"CWE-639","description":"...","why":"...","impact":"...","fix":"...","fixCode":"...","verify":"..."}]}.`,
      o.extraNotes ?? ''
    ]
      .filter(Boolean)
      .join('\n\n')
  }
  return [
    `Run a full security audit of the project "${o.name}" with the security-audit skill (load it with the Skill tool). This is an explicit full audit request: run the complete workflow, all six phases.`,
    `Use these values exactly and do not ask questions:\n- Target (repository root, read-only): ${o.root}\n- Output directory: ${o.outDir} (it already exists and is outside the target; use it as the output directory itself, with run-metadata.json, architecture.md, coverage-ledger.json, findings.json, REPORT.md, FINDINGS-DETAIL.md and NEEDS-VALIDATION.md inside it, plus the per-agent folders the skill describes).\n- Do not write anywhere else. Do not modify the target.`,
    `This environment: you cannot run commands, there is no network and no sandbox. So do not execute target code; keep any lead that needs it as needs_validation with its exact unresolved fact and a validation plan, as the skill instructs. You cannot run the validator scripts: the app runs them after you finish, against report-schema.json in the skill folder, so read that schema and write findings.json to match it exactly. The app also checks that every file and line you cite exists in the target.`,
    `Finish with a short summary: how many findings are confirmed, needs_validation and rejected, and where the files are. If you could not write files, reply with the report and a fenced json block holding the findings array instead.`,
    o.extraNotes ?? ''
  ]
    .filter(Boolean)
    .join('\n\n')
}

/** The same request, for the Claude app: the person pastes it into a Claude Code chat opened on the project. */
export function deepHandoffPrompt(o: { engine: DeepEngine; name: string; root: string }): string {
  const parts = engineList(o.engine).map((e) =>
    e === 'cloudflare'
      ? 'Run a full security audit with the security-audit skill (Cloudflare). Write the results to a new folder outside the project, such as ~/security-audit-skill/' + o.name + '/run-1.'
      : 'Run Anthropic’s security review (/security-review, or the anthropic-security-review skill) on the whole project.'
  )
  return [`Security review of "${o.name}" (project folder: ${o.root}). Do not change any project file.`, ...parts.map((p, i) => `${i + 1}. ${p}`), 'Report only problems you can trace through the code, with the file and line for each, and say which leads you could not confirm.'].join('\n\n')
}

// ---------------------------------------------------------------- Proof that the project was not touched

const SKIP = new Set(['node_modules', '.git', 'vendor', 'dist', 'build', '.next', '.nuxt', '.venv', 'venv', '__pycache__', 'target', '.gradle', 'Pods', 'DerivedData', '.cache', '.turbo', 'coverage'])

/** path -> "size:mtime" for the files an audit could touch. */
export function treeSignature(root: string, limit = 60_000): Map<string, string> {
  const out = new Map<string, string>()
  const walk = (dir: string, rel: string, depth: number): void => {
    if (depth > 14 || out.size >= limit) return
    let names: string[]
    try {
      names = readdirSync(dir)
    } catch {
      return
    }
    for (const n of names) {
      if (SKIP.has(n)) continue
      const p = join(dir, n)
      let st
      try {
        st = statSync(p)
      } catch {
        continue
      }
      const r = rel ? `${rel}/${n}` : n
      if (st.isDirectory()) walk(p, r, depth + 1)
      else out.set(r, `${st.size}:${Math.round(st.mtimeMs)}`)
    }
  }
  walk(root, '', 0)
  return out
}

/** The files that were added, removed or changed between two signatures. */
export function changedFiles(before: Map<string, string>, after: Map<string, string>): string[] {
  const out: string[] = []
  for (const [k, v] of before) if (after.get(k) !== v) out.push(k)
  for (const k of after.keys()) if (!before.has(k)) out.push(k)
  return out.sort()
}

// ---------------------------------------------------------------- Checking findings.json

type Schema = { type?: string; const?: unknown; enum?: unknown[]; minLength?: number; pattern?: string; minItems?: number; uniqueItems?: boolean; minimum?: number; required?: string[]; properties?: Record<string, Schema>; additionalProperties?: boolean | Schema; items?: Schema; oneOf?: Schema[]; visibleContent?: boolean }

const typeOk = (v: unknown, t: string): boolean => (t === 'array' ? Array.isArray(v) : t === 'object' ? !!v && typeof v === 'object' && !Array.isArray(v) : t === 'integer' ? Number.isInteger(v) : t === 'number' ? typeof v === 'number' : typeof v === t)

function check(v: unknown, s: Schema, at: string, errs: string[]): void {
  if (errs.length >= 40) return
  if (s.type && !typeOk(v, s.type)) return void errs.push(`${at}: should be ${s.type}`)
  if (s.const !== undefined && v !== s.const) errs.push(`${at}: should be ${JSON.stringify(s.const)}`)
  if (s.enum && !s.enum.includes(v)) errs.push(`${at}: should be one of ${s.enum.join(', ')}`)
  if (typeof v === 'string') {
    if (s.minLength !== undefined && v.length < s.minLength) errs.push(`${at}: is empty`)
    if (s.pattern && !new RegExp(s.pattern).test(v)) errs.push(`${at}: has characters that are not allowed`)
    if (s.visibleContent && !/[\p{L}\p{N}]/u.test(v)) errs.push(`${at}: has no readable text`)
  }
  if (typeof v === 'number' && s.minimum !== undefined && v < s.minimum) errs.push(`${at}: is below ${s.minimum}`)
  if (Array.isArray(v)) {
    if (s.minItems !== undefined && v.length < s.minItems) errs.push(`${at}: needs at least ${s.minItems} item(s)`)
    if (s.uniqueItems && new Set(v.map((x) => JSON.stringify(x))).size !== v.length) errs.push(`${at}: has duplicates`)
    if (s.items) v.forEach((x, i) => check(x, s.items!, `${at}[${i}]`, errs))
  }
  if (v && typeof v === 'object' && !Array.isArray(v)) {
    const o = v as Record<string, unknown>
    for (const k of s.required ?? []) if (!(k in o)) errs.push(`${at}.${k}: missing`)
    for (const [k, sub] of Object.entries(s.properties ?? {})) if (k in o) check(o[k], sub, `${at}.${k}`, errs)
    if (s.additionalProperties === false) for (const k of Object.keys(o)) if (!(s.properties ?? {})[k]) errs.push(`${at}.${k}: not part of the format`)
  }
}

/** Checks the whole findings.json against Cloudflare's report-schema.json. Returns plain messages; none means valid. */
export function validateFindings(doc: unknown, schema: unknown): string[] {
  const errs: string[] = []
  const s = schema as Schema
  if (!Array.isArray(doc)) return ['findings.json should be a list of findings']
  const options = s.items?.oneOf ?? []
  doc.forEach((rec, i) => {
    const verdict = (rec as { verdict?: unknown })?.verdict
    const match = options.find((o) => o.properties?.verdict?.const === verdict)
    if (!match) return void errs.push(`[${i}]: verdict should be confirmed, needs_validation or rejected`)
    check(rec, match, `[${i}]`, errs)
  })
  // Paths in the record must stay inside the project.
  const bad = (f: unknown): boolean => typeof f !== 'string' || isAbsolute(f) || normalize(f).startsWith('..') || /[\0\n\r]/.test(f)
  doc.forEach((rec, i) => {
    for (const k of ['trace', 'evidence'] as const) for (const [j, e] of ((rec as Record<string, unknown>)?.[k] as { file?: unknown }[] | undefined ?? []).entries()) if (bad(e?.file)) errs.push(`[${i}].${k}[${j}].file: should be a path inside the project`)
  })
  return errs.slice(0, 40)
}

// ---------------------------------------------------------------- Reading the result

export type DeepSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface DeepFinding {
  state: 'confirmed' | 'needs-checking'
  severity: DeepSeverity
  title: string
  file?: string
  line?: number
  description: string
  why?: string
  impact?: string
  fix?: string
  fixCode?: string
  verify?: string
  confidence?: string
  fingerprint?: string
  /** Why a confirmed finding was moved to "needs checking", or what blocks one. */
  note?: string
}

export interface DeepResult {
  report: string
  findings: DeepFinding[]
  counts: { confirmed: number; needsChecking: number; rejected: number }
  /** Plain-language problems: invalid records, citations that do not exist. */
  problems: string[]
  fromFiles: boolean
}

const SEV: Record<string, DeepSeverity> = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', informational: 'info', info: 'info' }
const str = (v: unknown): string => (typeof v === 'string' ? v : '')
const firstLine = (o: Record<string, unknown>[] | undefined, kinds: string[]): { file?: string; line?: number } => {
  for (const k of kinds) {
    const hit = o?.find((x) => x.kind === k)
    if (hit && typeof hit.file === 'string') return { file: hit.file, line: Number(hit.line) || undefined }
  }
  const any = o?.[0]
  return any && typeof any.file === 'string' ? { file: any.file, line: Number(any.line) || undefined } : {}
}

/** Latest findings.json under the audit folder (the skill writes it in the folder or in run-N). */
export function findDeepFiles(outDir: string): string | null {
  if (!existsSync(outDir)) return null
  if (existsSync(join(outDir, 'findings.json'))) return outDir
  const runs = readdirSync(outDir)
    .filter((n) => /^run-\d+$/.test(n) && existsSync(join(outDir, n, 'findings.json')))
    .sort((a, b) => Number(a.slice(4)) - Number(b.slice(4)))
  return runs.length ? join(outDir, runs[runs.length - 1]) : null
}

/** Does the cited file exist in the project, and is the line inside it? */
function citationProblem(root: string, file: string | undefined, line: number | undefined): string | null {
  if (!file) return 'it cites no file'
  const p = join(root, file)
  if (!p.startsWith(join(root) + '/') || !existsSync(p)) return `${file} is not in the project`
  if (line) {
    try {
      const n = readFileSync(p, 'utf8').split('\n').length
      if (line > n) return `${file} has no line ${line} (it has ${n})`
    } catch {
      return null
    }
  }
  return null
}

export function readDeepResults(outDir: string, root: string, schemaPath: string | null): DeepResult {
  const dir = findDeepFiles(outDir)
  const result: DeepResult = { report: '', findings: [], counts: { confirmed: 0, needsChecking: 0, rejected: 0 }, problems: [], fromFiles: false }
  if (!dir) return result
  const read = (n: string): string => {
    try {
      return readFileSync(join(dir, n), 'utf8')
    } catch {
      return ''
    }
  }
  let doc: unknown
  try {
    doc = JSON.parse(read('findings.json'))
  } catch {
    result.problems.push('findings.json could not be read as JSON.')
    result.report = read('REPORT.md')
    return result
  }
  result.fromFiles = true
  result.report = [read('REPORT.md'), read('NEEDS-VALIDATION.md')].filter(Boolean).join('\n\n')
  let invalid = false
  if (schemaPath && existsSync(schemaPath)) {
    try {
      const errs = validateFindings(doc, JSON.parse(readFileSync(schemaPath, 'utf8')))
      if (errs.length) {
        invalid = true
        result.problems.push(`findings.json does not follow Cloudflare’s report format (${errs.length} problem${errs.length === 1 ? '' : 's'}), so nothing in it is shown as confirmed. First: ${errs[0]}`)
      }
    } catch {
      invalid = true
      result.problems.push('Cloudflare’s report format file could not be read, so findings could not be checked against it.')
    }
  } else {
    invalid = true
    result.problems.push('Cloudflare’s skill is not installed here, so findings could not be checked against its report format.')
  }
  if (!Array.isArray(doc)) return result
  for (const rec of doc as Record<string, unknown>[]) {
    const verdict = str(rec.verdict)
    if (verdict === 'rejected') {
      result.counts.rejected++
      continue
    }
    const trace = rec.trace as Record<string, unknown>[] | undefined
    const evidence = rec.evidence as Record<string, unknown>[] | undefined
    const where = firstLine(trace, ['sink']).file ? firstLine(trace, ['sink']) : firstLine(evidence, [])
    const sev = rec.severity as { overall_severity?: string; impact?: { reason?: string } } | undefined
    const rem = rec.remediation as { strategy?: string; code_changes?: { file_name?: string; fixed_code?: string }[] } | undefined
    const exec = rec.execution as { instructions?: unknown[]; observed_result?: string } | undefined
    const conf = rec.confidence as { score?: string; reason?: string } | undefined
    const blockers = (rec.blockers as unknown[] | undefined)?.map((b) => (typeof b === 'string' ? b : JSON.stringify(b))).join('; ')
    let state: DeepFinding['state'] = verdict === 'confirmed' ? 'confirmed' : 'needs-checking'
    let note = verdict === 'confirmed' ? undefined : blockers ? `Blocked: ${blockers}` : 'Needs a check the audit could not make.'
    if (state === 'confirmed') {
      const cited = [...(trace ?? []), ...(evidence ?? [])]
      const miss = cited.map((c) => citationProblem(root, str(c.file), Number(c.line) || undefined)).find(Boolean)
      if (invalid) {
        state = 'needs-checking'
        note = 'The audit’s file did not pass the format check, so this was not counted as confirmed.'
      } else if (miss) {
        state = 'needs-checking'
        note = `Moved to needs checking: ${miss}.`
        result.problems.push(`“${str(rec.title).slice(0, 80)}”: ${miss}.`)
      }
    }
    const severity: DeepSeverity = state === 'confirmed' ? SEV[str(sev?.overall_severity)] ?? 'medium' : 'info'
    result.findings.push({
      state,
      severity,
      title: str(rec.title) || 'Untitled finding',
      ...where,
      description: str(rec.description),
      why: str(rec.root_cause) || str(rec.claimed_root_cause) || undefined,
      impact: sev?.impact?.reason,
      fix: rem?.strategy,
      fixCode: rem?.code_changes?.[0]?.fixed_code,
      verify: exec?.instructions?.length ? exec.instructions.map(String).join(' ') : undefined,
      confidence: conf?.score,
      fingerprint: str(rec.fingerprint) || undefined,
      note
    })
    if (state === 'confirmed') result.counts.confirmed++
    else result.counts.needsChecking++
  }
  return result
}

/** The findings as a Markdown report, in the format both apps read ("### [SEVERITY] Title"). */
export function deepMarkdown(r: DeepResult, name: string, engineNames: string[]): string {
  const sevWord = (s: DeepSeverity): string => (s === 'info' ? 'LOW' : s.toUpperCase())
  const confirmed = r.findings.filter((f) => f.state === 'confirmed')
  const leads = r.findings.filter((f) => f.state === 'needs-checking')
  const code = (s: string): string => '```\n' + s.replace(/```/g, "'''") + '\n```'
  const one = (f: DeepFinding): string =>
    [
      `### [${f.state === 'confirmed' ? sevWord(f.severity) : 'LEAD'}] ${f.title}`,
      f.file ? `- **Where:** \`${f.file}${f.line ? `:${f.line}` : ''}\`` : '',
      f.description ? `- **What:** ${f.description}` : '',
      f.why ? (f.state === 'confirmed' ? `- **Why it is rated ${sevWord(f.severity)}:** ${f.why}` : `- **Suspected cause:** ${f.why}`) : '',
      f.impact ? `- **Impact:** ${f.impact}` : '',
      f.fix ? `- **Fix:** ${f.fix}` : '',
      f.fixCode ? code(f.fixCode) : '',
      f.verify ? `- **How to verify:** ${f.verify}` : '',
      f.confidence ? `- **Confidence:** ${f.confidence}` : '',
      f.note ? `- **Note:** ${f.note}` : ''
    ]
      .filter(Boolean)
      .join('\n')
  return [
    `## Executive summary`,
    `Deep audit of ${name} with ${engineNames.join(' and ')}: ${confirmed.length} confirmed finding${confirmed.length === 1 ? '' : 's'}, ${leads.length} lead${leads.length === 1 ? '' : 's'} that need${leads.length === 1 ? 's' : ''} checking, ${r.counts.rejected} candidate${r.counts.rejected === 1 ? '' : 's'} disproved. Confirmed means the audit traced the problem through the code and every file and line it cites exists here.`,
    r.problems.length ? `### Things to know\n${r.problems.map((p) => `- ${p}`).join('\n')}` : '',
    '## Findings',
    confirmed.length ? confirmed.map(one).join('\n\n') : 'No confirmed findings.',
    leads.length ? `## Needs checking\nThese are leads the audit could not prove or disprove from the code alone.\n\n${leads.map(one).join('\n\n')}` : ''
  ]
    .filter(Boolean)
    .join('\n\n')
}

/** For the Anthropic pass (and the fallback), which writes a report with a json block rather than findings.json. */
export function deepFindingsFromJson(text: string): DeepFinding[] {
  const blocks = [...text.matchAll(/```json\s*([\s\S]*?)```/g)]
  const last = blocks.at(-1)
  if (!last) return []
  try {
    const j = JSON.parse(last[1]) as { findings?: Record<string, unknown>[] } | Record<string, unknown>[]
    const list = Array.isArray(j) ? j : j.findings ?? []
    return list
      .filter((f) => str(f.title))
      .map((f) => ({
        state: 'confirmed' as const,
        severity: SEV[str(f.severity).toLowerCase()] ?? 'medium',
        title: str(f.title),
        file: str(f.file) || undefined,
        line: typeof f.line === 'number' ? f.line : undefined,
        description: str(f.description),
        why: str(f.why) || undefined,
        impact: str(f.impact) || undefined,
        fix: str(f.fix) || undefined,
        fixCode: str(f.fixCode) || undefined,
        verify: str(f.verify) || undefined
      }))
  } catch {
    return []
  }
}

/** Findings whose cited file or line is not in the project move to "needs checking" (for the json-block path). */
export function checkCitations(root: string, list: DeepFinding[]): { findings: DeepFinding[]; problems: string[] } {
  const problems: string[] = []
  const findings = list.map((f) => {
    if (f.state !== 'confirmed') return f
    const miss = citationProblem(root, f.file, f.line)
    if (!miss) return f
    problems.push(`“${f.title.slice(0, 80)}”: ${miss}.`)
    return { ...f, state: 'needs-checking' as const, severity: 'info' as const, note: `Moved to needs checking: ${miss}.` }
  })
  return { findings, problems }
}
