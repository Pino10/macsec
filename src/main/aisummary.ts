/**
 * For web and API scans: the AI reads the findings (never the site itself) and writes what
 * matters most, what is likely noise, and how to fix each problem.
 */
import { spawn } from 'child_process'
import type { Finding, Reviewer } from '../shared/types'
import { agentEnv, findCli } from './agents'
import { chatWithLlm } from './models'
import { parseAiOutput, type Verdict } from './aireview'
import { pluginArgs } from './skills'
import type { Op } from './engine'

export function summaryPrompt(kind: 'web' | 'api', target: string, context: string, findings: Finding[]): string {
  const list = findings
    .slice(0, 150)
    .map((f) => `- id=${f.id} [${f.severity}] ${f.tool}: ${f.title}${f.url ? ` at ${f.url}` : f.file ? ` at ${f.file}` : ''}${f.cwe ? ` (${f.cwe})` : ''}${f.description ? `: ${f.description.slice(0, 200).replace(/\n/g, ' ')}` : ''}`)
    .join('\n')
  return `You are a senior application security engineer. A read-only ${kind === 'web' ? 'web' : 'API'} security scan of ${target} found the items below.
${context}

Write a tailored report in Markdown for the person who owns this ${kind === 'web' ? 'site' : 'API'}, specific to the technologies detected:
## Executive summary
3 to 5 sentences: the overall state and the single most urgent fix.
## Risk overview
A table: | Severity | Finding | Where |, most severe first. Group repeated items (all missing headers in one row).
## Findings
For each problem worth fixing, "### [SEVERITY] Title" (CRITICAL, HIGH, MEDIUM or LOW) with: **Where** (the address), **Evidence** (what the scan saw), **Why it is rated SEVERITY**, **Impact** in plain words, **Fix** with the exact configuration or code for this stack in a fenced code block (Nginx, Apache, Laravel, Express and so on), and **How to verify** (a command such as curl -I, or what to check in the browser).
## Probably harmless
Items that look alarming but are not, and why.

End with one fenced json block: {"verdicts":[{"id":"<id>","verdict":"confirmed" or "false-positive","severity":"high","reason":"one sentence"}]} for the items you judged.

Findings (${findings.length}):
${list || '(none)'}`
}

export async function summarizeWithAi(reviewer: Reviewer, prompt: string, op: Op, cwd: string): Promise<{ report: string; verdicts: Map<string, 'confirmed' | 'false-positive'>; details: Map<string, Verdict> }> {
  let text: string
  if (reviewer === 'model') text = await chatWithLlm([{ role: 'user', content: prompt }], 20 * 60_000)
  else {
    const bin = findCli(reviewer === 'codex' ? 'codex' : 'claude')
    if (!bin) throw new Error(`${reviewer === 'codex' ? 'Codex' : 'Claude Code'} is not installed. Set it up on Tools.`)
    // The AI only reads the findings in the prompt: no tools, no session saved.
    const args = reviewer === 'codex' ? ['exec', '--sandbox', 'read-only', '--skip-git-repo-check', '--color', 'never', prompt] : ['-p', prompt, '--output-format', 'text', '--permission-mode', 'plan', '--disallowedTools', 'Bash,Edit,Write,WebFetch,WebSearch,NotebookEdit', '--no-session-persistence', ...pluginArgs()]
    text = await new Promise<string>((resolve, reject) => {
      const child = spawn(bin, args, { cwd, env: agentEnv(), stdio: ['ignore', 'pipe', 'pipe'] })
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
