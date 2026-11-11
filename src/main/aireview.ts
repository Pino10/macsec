/**
 * The AI part of a code review. The reviewer reads the code itself, checks what the scanners
 * found (real or false alarm), and hunts for what scanners cannot see: broken access control,
 * missing authorization, insecure direct object references, business logic flaws, unsafe flows
 * across files.
 *
 * Claude Code and Codex run read-only in the project and are not saved as sessions of their own.
 * A local model (LM Studio) reads the riskiest files in parts.
 */
import { ensureLmContext } from './seckit/lmstudio'
import { spawn, type ChildProcess } from 'child_process'
import { readFileSync } from 'fs'
import { join } from 'path'
import type { Finding, ReviewDepth, ReviewFocus, Severity } from '../shared/types'
import { agentEnv, findCli } from './agents'
import { pluginArgs } from './skills'
import { explainFailure, localModelEnv, type LocalModel } from './seckit/reviewers'
import { skillText } from './seckit/skills'
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

const OUTPUT = `Write a tailored security report in Markdown, for the owner of this code. Explain like a senior engineer briefing a colleague: concrete, specific to THIS code, no generic advice.

## Executive summary
3 to 5 sentences: overall state, the most urgent fix, and the main risk themes.

## Risk overview
A Markdown table: | Severity | Finding | Where | Status |, one row per finding (yours and the confirmed scanner ones), most severe first.

## Findings
For each finding, most severe first, a section headed "### [SEVERITY] Title" (SEVERITY is CRITICAL, HIGH, MEDIUM or LOW) containing:
- **Where:** \`path/to/file:line\`
- **Evidence:** a fenced code block quoting the exact lines from the code (mask any secret value after its first 4 characters).
- **Why it is rated SEVERITY:** what makes it this serious here (reachability, who can trigger it, what data it touches).
- **Impact:** what could happen, in plain words (no working exploit).
- **Fix:** what to change, then a fenced code block with the corrected code.
- **How to verify:** how to confirm the fix worked.

## Scanner results checked
For each scanner finding you checked: confirmed or false alarm, and why, in one line each.

## What was reviewed
Entry points and areas you read, and anything you could not check.

At the very end, add one fenced code block tagged json with this exact shape:
{"findings":[{"severity":"high","title":"...","file":"path","line":12,"cwe":"CWE-639","description":"what is wrong","why":"why this severity","impact":"what could happen","fix":"what to change","fixCode":"corrected code","verify":"how to check"}],
 "verdicts":[{"id":"<scanner finding id>","verdict":"confirmed","severity":"high","reason":"why"}]}
"findings" lists every finding YOU found (not the scanner ones). "verdicts" covers each scanner finding you checked: "confirmed" or "false-positive", the severity you would give it, and one sentence of reasoning.`

/** The scanner findings the reviewer should check, most severe first. */
export function scannerBrief(findings: Finding[], max = 150): string {
  if (findings.length === 0) return 'The scanners found nothing. Look carefully anyway: they miss logic and access-control flaws.'
  const lines = findings.slice(0, max).map((f, i) => {
    const head = `- id=${f.id} [${f.severity}] ${f.tool} (${f.category}): ${f.title}${f.file ? ` at ${f.file}${f.line ? `:${f.line}` : ''}` : ''}${f.cwe ? ` (${f.cwe})` : ''}${f.advisory ? ` ${f.advisory}` : ''}`
    // The most severe come with their code, so even a model without file access can judge them.
    const ctx = i < 40 && f.context ? `\n  \`\`\`\n${f.context.lines.map((l, j) => `  ${f.context!.start + j}${f.context!.start + j === f.context!.at ? '>' : ':'} ${l}`).join('\n')}\n  \`\`\`` : ''
    return head + ctx
  })
  return `Automated scanners (Semgrep, Bearer, Gitleaks, TruffleHog, OSV-Scanner, Trivy and others) reported these (${findings.length} in total${findings.length > max ? `, the ${max} most severe shown` : ''}). Open each code-level one in the code, decide whether it is real, and give a verdict with a reason. Package advisories: check whether the vulnerable part is actually used.\n${lines.join('\n')}`
}

export function reviewPrompt(name: string, focus: ReviewFocus, depth: ReviewDepth, findings: Finding[]): string {
  return [
    `You are a senior application security engineer reviewing the project "${name}" in the current folder. Review it for ${FOCUS[focus]}.`,
    depth === 'deep' ? 'This is a deep review: read every entry point and follow the data through the code. Take the time you need.' : depth === 'quick' ? 'This is a quick review: concentrate on the most exposed code (routes, auth, database access, uploads).' : '',
    CHECKLIST,
    scannerBrief(findings),
    'Use your security skills if they are available: start with review-vectors to plan which areas apply, then security-code-review and every vector skill that applies (api-security-review, auth-session-review, injection-catalog, client-side-review, business-logic-review, infra-config-review, supply-chain-review, cloud-baas-review, ai-app-review, electron-review, privacy-data-review), then secrets-triage, dependency-triage and security-report. Say which areas were not applicable.',
    'Do not modify any file. Do not run anything.',
    OUTPUT
  ]
    .filter(Boolean)
    .join('\n\n')
}

export interface Verdict {
  verdict: 'confirmed' | 'false-positive'
  severity?: Severity
  reason?: string
}

export interface AiResult {
  report: string
  findings: Finding[]
  verdicts: Map<string, 'confirmed' | 'false-positive'>
  details: Map<string, Verdict>
}

/** Pulls the json block out of the reviewer's answer. */
export function parseAiOutput(text: string, tool: string): AiResult {
  const clean = text.replace(/<think>[\s\S]*?<\/think>/g, '').trim()
  const blocks = [...clean.matchAll(/```json\s*([\s\S]*?)```/g)]
  const verdicts = new Map<string, 'confirmed' | 'false-positive'>()
  const details = new Map<string, Verdict>()
  const findings: Finding[] = []
  const sevOf = (v: unknown): Severity | undefined => {
    const x = String(v ?? '').toLowerCase()
    return (['critical', 'high', 'medium', 'low', 'info'] as const).includes(x as Severity) ? (x as Severity) : undefined
  }
  const last = blocks.at(-1)
  if (last) {
    try {
      const j = JSON.parse(last[1]) as { findings?: { severity?: string; title?: string; file?: string; line?: number; cwe?: string; description?: string; fix?: string; why?: string; impact?: string; fixCode?: string; verify?: string }[]; verdicts?: { id: string; verdict: string; severity?: string; reason?: string }[] }
      for (const f of j.findings ?? []) {
        if (!f.title) continue
        const s = String(f.severity ?? 'medium').toLowerCase()
        const severity: Severity = (['critical', 'high', 'medium', 'low', 'info'] as const).includes(s as Severity) ? (s as Severity) : 'medium'
        findings.push({ id: fid(tool, f.file, f.line, f.title), tool, category: 'ai', severity, title: f.title, file: f.file, line: typeof f.line === 'number' ? f.line : undefined, cwe: f.cwe, description: f.description, fix: f.fix, why: f.why, impact: f.impact, fixCode: f.fixCode, verify: f.verify, verdict: 'confirmed' })
      }
      for (const v of j.verdicts ?? []) {
        if (v.verdict !== 'confirmed' && v.verdict !== 'false-positive') continue
        verdicts.set(v.id, v.verdict)
        details.set(v.id, { verdict: v.verdict, severity: sevOf(v.severity), reason: v.reason })
      }
    } catch {
      // The model wrote invalid JSON: the report is still shown, without the structured list.
    }
  }
  const report = last ? clean.replace(last[0], '').trim() : clean
  return { report, findings, verdicts, details }
}

export function runCli(bin: string, args: string[], cwd: string, onChild: (c: ChildProcess) => void, timeoutMs: number, onActivity: () => void, extraEnv: Record<string, string> = {}): Promise<{ code: number | null; out: string; err: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, { cwd, env: { ...agentEnv(), ...extraEnv }, stdio: ['ignore', 'pipe', 'pipe'] })
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

/**
 * Claude Code runs as a normal session of yours (your sign-in, or an API key if you set one), with
 * MacSec's security skills loaded for that session only. It is saved under a known id and name, so
 * "Continue in Claude Code" picks up the same conversation. Read-only: plan mode, and only the
 * Read, Grep and Glob tools.
 */
export async function reviewWithClaude(root: string, prompt: string, depth: ReviewDepth, onChild: (c: ChildProcess) => void, onActivity: () => void, session?: { id: string; name: string }, local?: LocalModel, free = false, plugins?: string[]): Promise<AiResult> {
  const bin = findCli('claude')
  if (!bin) throw new Error('Claude Code’s command line tool is not installed (the Claude desktop app is separate). Install it on the Tools page.')
  // With a local model, Claude Code talks to LM Studio's Anthropic-compatible API instead of Anthropic.
  const env = local ? localModelEnv(local) : {}
  // Free LLM API routes to big hosted models: they get the full method, not the short local one.
  const method = local ? `\n\nFollow this method:\n${skillText(['untrusted-content-guard', 'review-vectors', 'security-code-review', free ? 'false-positive-check' : 'local-model-review', 'security-report'])}` : ''
  if (local && !free) {
    const ctx = await ensureLmContext(local.baseUrl, local.model, local.token)
    if (!ctx.ok) throw new Error(ctx.note)
  }
  const base = ['-p', prompt + method, '--output-format', 'text', '--permission-mode', 'plan', '--allowedTools', 'Read,Grep,Glob,Skill', ...(local ? ['--model', local.model] : []), ...(plugins ?? pluginArgs())]
  const keep = session ? ['--session-id', session.id, '--name', session.name] : ['--no-session-persistence']
  let r = await runCli(bin, [...base, ...keep], root, onChild, (local ? 2 : 1) * TIMEOUT[depth] * 60_000, onActivity, env)
  if (local && r.code !== 0) throw new Error(explainFailure(free ? 'claude-free' : 'claude-local', r.err))
  // Older Claude Code versions: without the newer options.
  if (r.code !== 0 && /unknown option/i.test(r.err)) r = await runCli(bin, ['-p', prompt, '--output-format', 'text', '--permission-mode', 'plan', '--allowedTools', 'Read,Grep,Glob'], root, onChild, TIMEOUT[depth] * 60_000, onActivity)
  if (r.code !== 0 || !r.out.trim()) {
    if (/log ?in|auth|credential|api key/i.test(r.err)) throw new Error('Claude Code is not signed in. Run claude once in Terminal to sign in.')
    throw new Error(`Claude Code stopped without a report. ${r.err.trim().split('\n').slice(-2).join(' ')}`.trim())
  }
  return parseAiOutput(r.out, 'Claude Code')
}

/** Google's Gemini CLI in plan mode: it reads the project, it cannot change files or run commands. */
export async function reviewWithGemini(root: string, prompt: string, depth: ReviewDepth, onChild: (c: ChildProcess) => void, onActivity: () => void): Promise<AiResult> {
  const bin = findCli('gemini')
  if (!bin) throw new Error('Gemini CLI is not installed (npm install -g @google/gemini-cli), then run gemini once to sign in.')
  const r = await runCli(bin, ['-p', `${prompt}\n\nFollow this method:\n${skillText(['review-vectors', 'security-code-review', 'api-security-review', 'auth-session-review', 'injection-catalog', 'client-side-review', 'business-logic-review', 'infra-config-review', 'supply-chain-review', 'cloud-baas-review', 'secrets-triage', 'security-report'])}`, '--approval-mode', 'plan', '--skip-trust', '--output-format', 'text'], root, onChild, TIMEOUT[depth] * 60_000, onActivity)
  if (!r.out.trim()) throw new Error(explainFailure('gemini', r.err))
  return parseAiOutput(r.out, 'Gemini CLI')
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
  const details = new Map(parts.flatMap((p) => [...p.details]))
  let report = parts.map((p) => p.report).join('\n\n')
  if (parts.length > 1) {
    progress('Model writing the final report')
    try {
      report = (
        await chatWithLlm(
          [
            { role: 'system', content: 'You merge security review notes into one tailored report. Remove duplicates, keep every real finding with its file, line, evidence code, why it has its severity, impact, fix with code, and how to verify. Use the sections: ## Executive summary, ## Risk overview (a table), ## Findings ("### [SEVERITY] Title"), ## Scanner results checked, ## What was reviewed. Do not add a JSON block.' },
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
  return { report, findings: findingsOut, verdicts, details }
}
