/**
 * For web and API scans: the AI reads the findings (never the site itself) and writes what
 * matters most, what is likely noise, and how to fix each problem.
 */
import { freeServer } from './freellm'
import { spawn } from 'child_process'
import type { Finding, Reviewer } from '../shared/types'
import { agentEnv, findCli } from './agents'
import { chatWithLlm, chosenLocal } from './models'
import { parseAiOutput, type Verdict } from './aireview'
import { pluginArgs } from './skills'
import { methodText } from './bountyskills'
import { knowledgeBlock } from './knowledge'
import { localModelEnv } from './seckit/reviewers'
import { getSettings } from './settings'
import type { Op } from './engine'

/** The review methods that fit each kind of check, so the report judges findings the way an expert in that area would. */
export const METHOD: Record<'web' | 'api' | 'mobile' | 'cloud' | 'server', string[]> = {
  web: ['client-side-review', 'infra-config-review', 'identity-surface-review', 'http-cache-review', 'standards-mapping-catalog', 'false-positive-check', 'evidence-gate-review', 'verify-with-proof', 'novelty-and-impact', 'hypotheses-from-invariants', 'bounty-report-writing', 'untrusted-content-guard'],
  api: ['api-security-review', 'standards-mapping-catalog', 'graphql-review', 'auth-session-review', 'false-positive-check', 'evidence-gate-review', 'verify-with-proof', 'novelty-and-impact', 'hypotheses-from-invariants', 'bounty-report-writing', 'untrusted-content-guard'],
  mobile: ['mobile-app-review', 'android-app-review', 'ios-app-review', 'false-positive-check', 'evidence-gate-review', 'verify-with-proof', 'novelty-and-impact', 'bounty-report-writing', 'untrusted-content-guard'],
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
  const kb = ['web', 'api', 'mobile'].includes(kind) ? knowledgeBlock(`${context} ${findings.map((f) => f.title).join(' ')}`, { max: 4, maxChars: 12000, prefer: kind === 'mobile' ? ['mobile', 'authz'] : ['authz', 'authn', 'logic', kind === 'api' ? 'api' : 'web'] }) : ''
  const notes = kb ? `\nExpert notes that match what was found (use them to judge impact and to suggest what to try next by hand):\n${kb}\n` : ''
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
## What to try next
Up to 6 leads for a person to test by hand, most promising first: each with the exact first step, what result would count as proof, and what would make it a false alarm. Use only what the findings and context support. Never suggest anything that changes or deletes other people's data.

End with one fenced json block: {"verdicts":[{"id":"<id>","verdict":"confirmed" or "false-positive","severity":"high","reason":"one sentence"}]} for the items you judged.

Use this method to judge what matters and what is noise:
${methodText(METHOD[kind])}
${notes}
Findings (${findings.length}):
${list || '(none)'}`
}

/** Sends a prompt to the chosen AI (read-only, no tools) and returns its text. */
export async function askAi(reviewer: Reviewer, prompt: string, op: Op, cwd: string): Promise<string> {
  let text: string
  if (reviewer === 'model') text = await chatWithLlm([{ role: 'user', content: prompt }], 20 * 60_000)
  else {
    const cli = reviewer === 'codex' ? 'codex' : reviewer === 'gemini' ? 'gemini' : 'claude'
    const bin = findCli(cli)
    if (!bin) throw new Error(`${reviewer === 'codex' ? 'Codex' : reviewer === 'gemini' ? 'Gemini CLI' : 'Claude Code'} is not installed. Set it up on Tools.`)
    const st = getSettings()
    const free = reviewer === 'claude-free' ? freeServer() : null
    const localEnv = reviewer === 'claude-local' ? localModelEnv(chosenLocal()) : free ? localModelEnv(free) : {}
    // The AI only reads the findings in the prompt: no tools, no session saved.
    const args =
      reviewer === 'codex'
        ? ['exec', '--sandbox', 'read-only', '--skip-git-repo-check', '--color', 'never', prompt]
        : reviewer === 'gemini'
          ? ['-p', prompt, '--approval-mode', 'plan', '--skip-trust', '--output-format', 'text']
          : ['-p', prompt, '--output-format', 'text', '--permission-mode', 'plan', '--strict-mcp-config', '--disallowedTools', 'Bash,Edit,Write,WebFetch,WebSearch,NotebookEdit', '--no-session-persistence', ...(reviewer === 'claude-local' ? ['--model', st.llm.model] : free ? ['--model', free.model] : []), ...pluginArgs()]
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
  return text
}

export async function summarizeWithAi(reviewer: Reviewer, prompt: string, op: Op, cwd: string): Promise<{ report: string; verdicts: Map<string, 'confirmed' | 'false-positive'>; details: Map<string, Verdict> }> {
  const text = await askAi(reviewer, prompt, op, cwd)
  const r = parseAiOutput(text, 'AI')
  return { report: r.report, verdicts: r.verdicts, details: r.details }
}
