/**
 * For web and API scans: the AI reads the findings (never the site itself) and writes what
 * matters most, what is likely noise, and how to fix each problem.
 */
import { freeServer } from './freellm'
import { spawn } from 'child_process'
import type { Finding, Reviewer } from '../shared/types'
import { agentEnv, findCli } from './agents'
import { chatWithLlm } from './models'
import { parseAiOutput, type Verdict } from './aireview'
import { pluginArgs } from './skills'
import { skillText } from './seckit/skills'
import { localModelEnv } from './seckit/reviewers'
import { getSettings } from './settings'
import type { Op } from './engine'

/** The review methods that fit each kind of check, so the report judges findings the way an expert in that area would. */
export const METHOD: Record<'web' | 'api' | 'mobile' | 'cloud' | 'server', string[]> = {
  web: ['client-side-review', 'infra-config-review', 'identity-surface-review', 'http-cache-review', 'standards-mapping-catalog', 'false-positive-check', 'evidence-gate-review', 'untrusted-content-guard'],
  api: ['api-security-review', 'standards-mapping-catalog', 'graphql-review', 'auth-session-review', 'false-positive-check', 'evidence-gate-review', 'untrusted-content-guard'],
  mobile: ['mobile-app-review', 'android-app-review', 'ios-app-review', 'false-positive-check', 'evidence-gate-review', 'untrusted-content-guard'],
  cloud: ['cloud-iam-review', 'cloud-baas-review', 'false-positive-check', 'evidence-gate-review', 'untrusted-content-guard'],
  server: ['network-server-review', 'infra-config-review', 'false-positive-check', 'evidence-gate-review', 'untrusted-content-guard']
}

const WHAT = { web: ['web', 'site'], api: ['API', 'API'], mobile: ['mobile app', 'app'], cloud: ['cloud account', 'cloud account'], server: ['server and open ports', 'server'] } as const

export function summaryPrompt(kind: keyof typeof WHAT, target: string, context: string, findings: Finding[]): string {
  const [scan, thing] = WHAT[kind]
  const list = findings
    .slice(0, 150)
    .map((f) => `- id=${f.id} [${f.severity}] ${f.tool}: ${f.title}${f.url ? ` at ${f.url}` : f.file ? ` at ${f.file}` : ''}${f.cwe ? ` (${f.cwe})` : ''}${f.description ? `: ${f.description.slice(0, 200).replace(/\n/g, ' ')}` : ''}`)
    .join('\n')
  return `You are a senior application security engineer. A read-only ${scan} security check of ${target} found the items below.
${context}

Write a tailored report in Markdown for the person who owns this ${thing}, specific to the technologies detected:
## Executive summary
3 to 5 sentences: the overall state and the single most urgent fix.
## Risk overview
A table: | Severity | Finding | Where |, most severe first. Group repeated items (all missing headers in one row).
## Findings
For each problem worth fixing, "### [SEVERITY] Title" (CRITICAL, HIGH, MEDIUM or LOW) with: **Where** (the address), **Evidence** (what the scan saw), **Why it is rated SEVERITY**, **Impact** in plain words, **Fix** with the exact configuration, code or command for this stack in a fenced code block, and **How to verify** (a command such as curl -I, or what to check in the browser).
## Probably harmless
Items that look alarming but are not, and why.

End with one fenced json block: {"verdicts":[{"id":"<id>","verdict":"confirmed" or "false-positive","severity":"high","reason":"one sentence"}]} for the items you judged.

Use this method to judge what matters and what is noise:
${skillText(METHOD[kind])}

Findings (${findings.length}):
${list || '(none)'}`
}

export async function summarizeWithAi(reviewer: Reviewer, prompt: string, op: Op, cwd: string): Promise<{ report: string; verdicts: Map<string, 'confirmed' | 'false-positive'>; details: Map<string, Verdict> }> {
  let text: string
  if (reviewer === 'model') text = await chatWithLlm([{ role: 'user', content: prompt }], 20 * 60_000)
  else {
    const cli = reviewer === 'codex' ? 'codex' : reviewer === 'gemini' ? 'gemini' : 'claude'
    const bin = findCli(cli)
    if (!bin) throw new Error(`${reviewer === 'codex' ? 'Codex' : reviewer === 'gemini' ? 'Gemini CLI' : 'Claude Code'} is not installed. Set it up on Tools.`)
    const st = getSettings()
    const free = reviewer === 'claude-free' ? freeServer() : null
    const localEnv = reviewer === 'claude-local' ? localModelEnv({ baseUrl: st.llm.baseUrl, model: st.llm.model }) : free ? localModelEnv(free) : {}
    // The AI only reads the findings in the prompt: no tools, no session saved.
    const args =
      reviewer === 'codex'
        ? ['exec', '--sandbox', 'read-only', '--skip-git-repo-check', '--color', 'never', prompt]
        : reviewer === 'gemini'
          ? ['-p', prompt, '--approval-mode', 'plan', '--skip-trust', '--output-format', 'text']
          : ['-p', prompt, '--output-format', 'text', '--permission-mode', 'plan', '--disallowedTools', 'Bash,Edit,Write,WebFetch,WebSearch,NotebookEdit', '--no-session-persistence', ...(reviewer === 'claude-local' ? ['--model', st.llm.model] : free ? ['--model', free.model] : []), ...pluginArgs()]
    text = await new Promise<string>((resolve, reject) => {
      const child = spawn(bin, args, { cwd, env: { ...agentEnv(), ...localEnv }, stdio: ['ignore', 'pipe', 'pipe'] })
      op.children.add(child)
      let out = ''
      let err = ''
      child.stdout.on('data', (d) => (out += d.toString()))
      child.stderr.on('data', (d) => (err += d.toString()))
      const timer = setTimeout(() => child.kill('SIGTERM'), 20 * 60_000)
      child.on('error', reject)
      child.on('exit', (code) => {
        clearTimeout(timer)
        op.children.delete(child)
        if (out.trim()) resolve(out)
        else reject(new Error(/log ?in|auth/i.test(err) ? 'Sign in first: run it once in Terminal.' : `No report (code ${code}). ${err.trim().split('\n').pop() ?? ''}`))
      })
    })
  }
  const r = parseAiOutput(text, 'AI')
  return { report: r.report, verdicts: r.verdicts, details: r.details }
}
