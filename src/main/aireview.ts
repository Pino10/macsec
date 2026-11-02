/**
 * The AI part of a code review. The reviewer reads the code itself, checks what the scanners
 * found (real or false alarm), and hunts for what scanners cannot see: broken access control,
 * missing authorization, insecure direct object references, business logic flaws, unsafe flows
 * across files.
 *
 * Claude Code and Codex run read-only in the project and are not saved as sessions of their own.
 * A local model (LM Studio) reads the riskiest files in parts.
 */
import { spawn, type ChildProcess } from 'child_process'
import { readFileSync } from 'fs'
import { join } from 'path'
import type { Finding, ReviewDepth, ReviewFocus, Severity } from '../shared/types'
import { agentEnv, findCli } from './agents'
import { chatWithLlm } from './models'
import { fid } from './scanners/parse'

const FOCUS: Record<ReviewFocus, string> = {
  security: 'security vulnerabilities',
  bugs: 'bugs and reliability problems that could cause wrong results, crashes or data loss',
  all: 'security vulnerabilities first, then bugs and risky code'
}

const CHECKLIST = `Work through, in this order:
1. Map the entry points: routes, controllers, API handlers, CLI commands, jobs, webhooks, file uploads.
2. Authentication: login, password reset, sessions, tokens (JWT signing and expiry), remember-me, MFA.
3. Authorization: every route that reads or changes data checks WHO is asking. Look for missing checks, IDOR (an id from the request used without an ownership check), mass assignment, role checks done only in the UI.
4. Injection: SQL (raw queries, string-built queries), command execution, template injection, LDAP, XPath, NoSQL, header injection, log injection.
5. Cross-site scripting: unescaped output, dangerous HTML in frameworks (v-html, dangerouslySetInnerHTML, {!! !!}, |safe).
6. Server-side request forgery, open redirects, path traversal, unsafe file upload and download, zip slip.
7. Deserialization, XXE, prototype pollution, unsafe eval or dynamic code.
8. Crypto: weak hashing for passwords, hard-coded keys, predictable tokens, missing TLS checks.
9. Secrets in code and config; debug modes and verbose errors in production settings.
10. CSRF, CORS, cookie flags, security headers, rate limiting on login and expensive endpoints.
11. Business logic: prices, quantities, state changes that can be skipped or repeated, race conditions.
12. Dependencies used in a dangerous way.
Trace data from where it enters to where it is used, across files. Only report what the code actually shows.`

const OUTPUT = `Write the report in Markdown:
- Start with "## Summary": 2 to 4 sentences on the overall state and the most urgent fix.
- Then one section per finding, most severe first, headed "### [SEVERITY] Title" where SEVERITY is CRITICAL, HIGH, MEDIUM or LOW, with: **Where:** \`path/to/file:line\`, **What is wrong**, **How it could be abused** (one or two sentences, no working exploit), **How to fix** (concrete code-level change).
- If there is nothing worth reporting, say so plainly.

At the very end, add one fenced code block tagged json with this exact shape:
{"findings":[{"severity":"high","title":"...","file":"path","line":12,"cwe":"CWE-639","description":"...","fix":"..."}],"verdicts":[{"id":"<scanner finding id>","verdict":"confirmed"}]}
"findings" lists every finding in your report. "verdicts" gives, for each scanner finding you checked, "confirmed" (a real problem) or "false-positive" (explain why in the report).`

/** The scanner findings the reviewer should check, most severe first. */
export function scannerBrief(findings: Finding[], max = 120): string {
  if (findings.length === 0) return 'The scanners found nothing. Look carefully anyway: they miss logic and access-control flaws.'
  const lines = findings.slice(0, max).map((f) => `- id=${f.id} [${f.severity}] ${f.tool}: ${f.title}${f.file ? ` at ${f.file}${f.line ? `:${f.line}` : ''}` : ''}${f.cwe ? ` (${f.cwe})` : ''}`)
  return `Automated scanners reported these (${findings.length} in total${findings.length > max ? `, the ${max} most severe shown` : ''}). Check the code-level ones in the code and give a verdict for each you checked:\n${lines.join('\n')}`
}

export function reviewPrompt(name: string, focus: ReviewFocus, depth: ReviewDepth, findings: Finding[]): string {
  return [
    `You are a senior application security engineer reviewing the project "${name}" in the current folder. Review it for ${FOCUS[focus]}.`,
    depth === 'deep' ? 'This is a deep review: read every entry point and follow the data through the code. Take the time you need.' : depth === 'quick' ? 'This is a quick review: concentrate on the most exposed code (routes, auth, database access, uploads).' : '',
    CHECKLIST,
    scannerBrief(findings),
    'Do not modify any file. Do not run anything.',
    OUTPUT
  ]
    .filter(Boolean)
    .join('\n\n')
}

export interface AiResult {
  report: string
  findings: Finding[]
  verdicts: Map<string, 'confirmed' | 'false-positive'>
}

/** Pulls the json block out of the reviewer's answer. */
export function parseAiOutput(text: string, tool: string): AiResult {
  const clean = text.replace(/<think>[\s\S]*?<\/think>/g, '').trim()
  const blocks = [...clean.matchAll(/```json\s*([\s\S]*?)```/g)]
  const verdicts = new Map<string, 'confirmed' | 'false-positive'>()
  const findings: Finding[] = []
  const last = blocks.at(-1)
  if (last) {
    try {
      const j = JSON.parse(last[1]) as { findings?: { severity?: string; title?: string; file?: string; line?: number; cwe?: string; description?: string; fix?: string }[]; verdicts?: { id: string; verdict: string }[] }
      for (const f of j.findings ?? []) {
        if (!f.title) continue
        const s = String(f.severity ?? 'medium').toLowerCase()
        const severity: Severity = (['critical', 'high', 'medium', 'low', 'info'] as const).includes(s as Severity) ? (s as Severity) : 'medium'
        findings.push({ id: fid(tool, f.file, f.line, f.title), tool, category: 'ai', severity, title: f.title, file: f.file, line: typeof f.line === 'number' ? f.line : undefined, cwe: f.cwe, description: f.description, fix: f.fix, verdict: 'confirmed' })
      }
      for (const v of j.verdicts ?? []) if (v.verdict === 'confirmed' || v.verdict === 'false-positive') verdicts.set(v.id, v.verdict)
    } catch {
      // The model wrote invalid JSON: the report is still shown, without the structured list.
    }
  }
  const report = last ? clean.replace(last[0], '').trim() : clean
  return { report, findings, verdicts }
}

function runCli(bin: string, args: string[], cwd: string, onChild: (c: ChildProcess) => void, timeoutMs: number, onActivity: () => void): Promise<{ code: number | null; out: string; err: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, { cwd, env: agentEnv(), stdio: ['ignore', 'pipe', 'pipe'] })
    onChild(child)
    let out = ''
    let err = ''
    child.stdout.on('data', (d) => {
      out += d.toString()
      onActivity()
    })
    child.stderr.on('data', (d) => (err += d.toString()))
    const timer = setTimeout(() => child.kill('SIGTERM'), timeoutMs)
    child.on('error', (e) => {
      clearTimeout(timer)
      reject(e)
    })
    child.on('exit', (code) => {
      clearTimeout(timer)
      resolve({ code, out, err })
    })
  })
}

const TIMEOUT: Record<ReviewDepth, number> = { quick: 15, standard: 40, deep: 120 }

export async function reviewWithClaude(root: string, prompt: string, depth: ReviewDepth, onChild: (c: ChildProcess) => void, onActivity: () => void): Promise<AiResult> {
  const bin = findCli('claude')
  if (!bin) throw new Error('Claude Code’s command line tool is not installed (the Claude desktop app is separate). Install it on the Tools page.')
  // Plan mode and read-only tools; a one-off session that Claude Code does not save.
  const base = ['-p', prompt, '--output-format', 'text', '--permission-mode', 'plan', '--allowedTools', 'Read,Grep,Glob']
  let r = await runCli(bin, [...base, '--no-session-persistence'], root, onChild, TIMEOUT[depth] * 60_000, onActivity)
  if (r.code !== 0 && /unknown option.*no-session-persistence/i.test(r.err)) r = await runCli(bin, base, root, onChild, TIMEOUT[depth] * 60_000, onActivity)
  if (r.code !== 0 || !r.out.trim()) {
    if (/log ?in|auth|credential|api key/i.test(r.err)) throw new Error('Claude Code is not signed in. Run claude once in Terminal to sign in.')
    throw new Error(`Claude Code stopped without a report. ${r.err.trim().split('\n').slice(-2).join(' ')}`.trim())
  }
  return parseAiOutput(r.out, 'Claude Code')
}

export async function reviewWithCodex(root: string, prompt: string, depth: ReviewDepth, outFile: string, onChild: (c: ChildProcess) => void, onActivity: () => void): Promise<AiResult> {
  const bin = findCli('codex')
  if (!bin) throw new Error('Codex is not installed. Install it on the Tools page.')
  const r = await runCli(bin, ['exec', '--sandbox', 'read-only', '--skip-git-repo-check', '--color', 'never', '--output-last-message', outFile, prompt], root, onChild, TIMEOUT[depth] * 60_000, onActivity)
  let text = ''
  try {
    text = readFileSync(outFile, 'utf8')
  } catch {
    text = r.out
  }
  if (!text.trim()) {
    if (/log ?in|auth|api key/i.test(r.err)) throw new Error('Codex is not signed in. Run codex once in Terminal to sign in.')
    throw new Error(`Codex stopped without a report. ${r.err.trim().split('\n').slice(-2).join(' ')}`.trim())
  }
  return parseAiOutput(text, 'Codex')
}

/** Files most worth a model's limited attention: the ones scanners flagged, then risky names. */
export function rankFiles(files: string[], findings: Finding[]): string[] {
  const flagged = new Map<string, number>()
  const weight: Record<Severity, number> = { critical: 50, high: 20, medium: 8, low: 2, info: 0 }
  for (const f of findings) if (f.file && f.category !== 'dependency') flagged.set(f.file, (flagged.get(f.file) ?? 0) + weight[f.severity])
  const risky = /(auth|login|password|session|token|jwt|admin|user|account|payment|order|upload|file|api|route|controller|middleware|guard|policy|permission|db|query|sql|model|repository|config|security|crypto|webhook)/i
  const score = (f: string): number => (flagged.get(f) ?? 0) + (risky.test(f) ? 10 : 0) - f.split('/').length
  return [...files].sort((a, b) => score(b) - score(a))
}

export function chunkFiles(root: string, files: string[], perChunk: number, total: number): string[] {
  const chunks: string[] = []
  let cur = ''
  let used = 0
  for (const rel of files) {
    if (used >= total) break
    let text: string
    try {
      text = readFileSync(join(root, rel), 'utf8')
    } catch {
      continue
    }
    if (/\0/.test(text.slice(0, 1000)) || text.length > 400_000) continue
    const block = `=== ${rel} ===\n${text.split('\n').slice(0, 1500).map((l, i) => `${i + 1}: ${l}`).join('\n')}\n`
    const piece = block.slice(0, perChunk)
    if (cur.length + piece.length > perChunk && cur) {
      chunks.push(cur)
      cur = ''
    }
    cur += piece
    used += piece.length
  }
  if (cur) chunks.push(cur)
  return chunks
}

/** A local or saved model: reads the riskiest files in parts, then merges its notes. */
export async function reviewWithModel(root: string, name: string, files: string[], findings: Finding[], focus: ReviewFocus, depth: ReviewDepth, progress: (label: string) => void, cancelled: () => boolean): Promise<AiResult> {
  // Big-context models (LM Studio with 100k+ tokens) take large parts; budgets grow with depth.
  const budget = { quick: { per: 40_000, total: 120_000 }, standard: { per: 80_000, total: 400_000 }, deep: { per: 120_000, total: 1_200_000 } }[depth]
  const chunks = chunkFiles(root, rankFiles(files, findings), budget.per, budget.total)
  if (chunks.length === 0) throw new Error('No source files were found to review.')
  const notes: string[] = []
  for (const [i, chunk] of chunks.entries()) {
    if (cancelled()) throw new Error('Cancelled.')
    progress(`Model reading part ${i + 1} of ${chunks.length}`)
    const relevant = findings.filter((f) => f.file && chunk.includes(`=== ${f.file} ===`))
    const reply = await chatWithLlm(
      [
        { role: 'system', content: `You are a senior application security engineer. Lines are numbered as "N: code". Review for ${FOCUS[focus]}.\n\n${CHECKLIST}\n\n${OUTPUT}` },
        { role: 'user', content: `Project "${name}", part ${i + 1} of ${chunks.length}.\n\n${scannerBrief(relevant, 60)}\n\n${chunk}` }
      ],
      30 * 60_000
    )
    notes.push(reply)
  }
  const parts = notes.map((n) => parseAiOutput(n, 'Model'))
  const findingsOut = parts.flatMap((p) => p.findings)
  const verdicts = new Map(parts.flatMap((p) => [...p.verdicts]))
  let report = parts.map((p) => p.report).join('\n\n')
  if (parts.length > 1) {
    progress('Model writing the final report')
    try {
      report = (
        await chatWithLlm(
          [
            { role: 'system', content: 'You merge security review notes into one report. Remove duplicates, keep every real finding with its file and line, order by severity. Start with "## Summary". Use "### [SEVERITY] Title" headings. Do not add a JSON block.' },
            { role: 'user', content: parts.map((p, i) => `--- Notes for part ${i + 1} ---\n${p.report}`).join('\n\n') }
          ],
          20 * 60_000
        )
      )
        .replace(/<think>[\s\S]*?<\/think>/g, '')
        .trim()
    } catch {
      // Keep the joined notes.
    }
  }
  return { report, findings: findingsOut, verdicts }
}
