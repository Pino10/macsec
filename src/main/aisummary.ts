/**
 * For web and API scans: the AI reads the findings (never the site itself) and writes what
 * matters most, what is likely noise, and how to fix each problem.
 */
import { spawn } from 'child_process'
import type { Finding, Reviewer } from '../shared/types'
import { agentEnv, findCli } from './agents'
import { chatWithLlm } from './models'
import { parseAiOutput } from './aireview'
import type { Op } from './engine'

export function summaryPrompt(kind: 'web' | 'api', target: string, context: string, findings: Finding[]): string {
  const list = findings
    .slice(0, 150)
    .map((f) => `- id=${f.id} [${f.severity}] ${f.tool}: ${f.title}${f.url ? ` at ${f.url}` : f.file ? ` at ${f.file}` : ''}${f.cwe ? ` (${f.cwe})` : ''}${f.description ? `: ${f.description.slice(0, 200).replace(/\n/g, ' ')}` : ''}`)
    .join('\n')
  return `You are a senior application security engineer. A read-only ${kind === 'web' ? 'web' : 'API'} security scan of ${target} found the items below.
${context}

Write a report in Markdown for the person who owns this ${kind === 'web' ? 'site' : 'API'}:
- "## Summary": 2 to 4 sentences: the overall state and the single most urgent fix.
- Then the problems worth fixing, most severe first, each headed "### [SEVERITY] Title" (SEVERITY is CRITICAL, HIGH, MEDIUM or LOW), with **Where**, **Why it matters** and **How to fix** (concrete configuration or code changes for the technologies detected).
- Group similar items (all missing headers in one section). Say which items are probably harmless and why.

End with one fenced json block: {"verdicts":[{"id":"<id>","verdict":"confirmed" or "false-positive"}]} for the items you judged.

Findings (${findings.length}):
${list || '(none)'}`
}

export async function summarizeWithAi(reviewer: Reviewer, prompt: string, op: Op, cwd: string): Promise<{ report: string; verdicts: Map<string, 'confirmed' | 'false-positive'> }> {
  let text: string
  if (reviewer === 'model') text = await chatWithLlm([{ role: 'user', content: prompt }], 20 * 60_000)
  else {
    const bin = findCli(reviewer === 'codex' ? 'codex' : 'claude')
    if (!bin) throw new Error(`${reviewer === 'codex' ? 'Codex' : 'Claude Code'} is not installed. Set it up on Tools.`)
    // The AI only reads the findings in the prompt: no tools, no session saved.
    const args = reviewer === 'codex' ? ['exec', '--sandbox', 'read-only', '--skip-git-repo-check', '--color', 'never', prompt] : ['-p', prompt, '--output-format', 'text', '--permission-mode', 'plan', '--disallowedTools', 'Bash,Edit,Write,WebFetch,WebSearch,NotebookEdit', '--no-session-persistence']
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
  return { report: r.report, verdicts: r.verdicts }
}
