/**
 * The independent verifier: a second AI session whose only job is to try to disprove one finding.
 * It gets the finding and a masked excerpt of the code, never the first reviewer's reasoning, so it
 * cannot simply agree. Its answer is stored beside the finding; it never changes the confidence.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs'
import { join } from 'path'
import type { ChildProcess } from 'child_process'
import type { Finding, SessionDetail } from '../shared/types'
import { findCli } from './agents'
import { runCli } from './aireview'
import { maskSecrets } from './evidence'
import { readSession, sessionDetail, setSecondOpinion } from './sessions'
import { dirs } from './paths'

export interface Opinion {
  verdict: 'seconded' | 'refuted' | 'uncertain'
  reason: string
  by: string
  at: string
}

export function parseOpinion(text: string): Omit<Opinion, 'by' | 'at'> {
  const v = /VERDICT:\s*(seconded|refuted|uncertain)/i.exec(text)
  if (!v) throw new Error('The second AI did not give a verdict. Nothing was changed.')
  const r = /REASON:\s*(.+)/i.exec(text)
  return { verdict: v[1].toLowerCase() as Opinion['verdict'], reason: (r?.[1] ?? '').trim().slice(0, 600) }
}

export function secondOpinionPrompt(f: Finding, excerpt: string): string {
  return `You are an independent security verifier. A scanner reported one problem. Your only job is to try to DISPROVE it. Do not trust the scanner. Judge only the code below.

FINDING: ${f.title}
SEVERITY: ${f.severity}
WHERE: ${f.file ?? f.url ?? 'not said'}${f.line ? `:${f.line}` : ''}
SCANNER: ${f.tool}
DESCRIPTION: ${(f.description ?? '').slice(0, 1200)}

CODE AROUND IT:
${excerpt.slice(0, 12_000)}

Answer with exactly two lines, and nothing else:
VERDICT: seconded or refuted or uncertain
REASON: one sentence pointing at the code that decided it.

Use "seconded" only when the code clearly shows the problem. Use "refuted" when the code shows it cannot happen (safe API, escaping, a guard, test code only). Use "uncertain" when the excerpt is not enough.`
}

const SETTINGS = (dir: string): string => {
  const file = join(dir, 'settings.json')
  const deny = [
    'Read(//**/.ssh/**)', 'Read(//**/.aws/**)', 'Read(//**/.gnupg/**)', 'Read(//**/.kube/**)', 'Read(//**/.docker/**)',
    'Read(//**/.config/gcloud/**)', 'Read(//**/Library/Keychains/**)', 'Read(//**/.netrc)', 'Read(//**/.npmrc)', 'Read(//**/.git-credentials)', 'Read(//**/id_rsa)', 'Read(//**/id_ed25519)'
  ]
  try {
    writeFileSync(file, JSON.stringify({ permissions: { deny } }, null, 2))
    return file
  } catch {
    return ''
  }
}

/** The excerpt: 40 lines either side, with every secret masked before it leaves the Mac. */
export function excerptFor(root: string, f: Finding): string {
  if (!f.file) return (f.snippet ?? f.description ?? '').slice(0, 4000)
  const path = join(root, f.file)
  if (!existsSync(path)) return (f.snippet ?? f.description ?? '').slice(0, 4000)
  try {
    const text = readFileSync(path, 'utf8')
    if (!f.line) return maskSecrets(text.slice(0, 6000))
    const lines = text.split('\n')
    const at = Math.max(0, f.line - 1)
    return maskSecrets(lines.slice(Math.max(0, at - 40), Math.min(lines.length, at + 40)).map((l, i) => `${Math.max(1, at - 40) + i + 1}: ${l}`).join('\n'))
  } catch {
    return (f.snippet ?? f.description ?? '').slice(0, 4000)
  }
}

export async function secondOpinion(sessionId: string, findingId: string, onChild?: (c: ChildProcess) => void): Promise<SessionDetail> {
  const s = readSession(sessionId)
  const d = sessionDetail(sessionId)
  const f = d.findings.find((x) => x.id === findingId)
  if (!f) throw new Error('That finding is not in this result.')
  if (!s.codePath) throw new Error('The code is no longer on this Mac for this result. Keep the code next time, or run the review on a local project.')
  const bin = findCli('claude')
  if (!bin) throw new Error('Claude Code’s command line tool is not installed. Set it up on Tools, or use another reviewer for the review itself.')
  const work = join(dirs.config(), 'second-opinion')
  mkdirSync(work, { recursive: true, mode: 0o700 })
  const settings = SETTINGS(work)
  const prompt = secondOpinionPrompt(f, excerptFor(s.codePath, f))
  const r = await runCli(bin, ['-p', prompt, '--output-format', 'text', '--permission-mode', 'plan', '--strict-mcp-config', '--allowedTools', 'Read', ...(settings ? ['--settings', settings] : [])], s.codePath, onChild ?? (() => {}), 4 * 60_000, () => {})
  if (r.code !== 0 || !r.out.trim()) {
    if (/log ?in|auth|credential|api key/i.test(r.err)) throw new Error('Claude Code is not signed in. Run claude once in Terminal to sign in.')
    throw new Error(`The second AI stopped without an answer. ${r.err.trim().split('\n').slice(-2).join(' ')}`.trim())
  }
  const o = parseOpinion(r.out)
  setSecondOpinion(sessionId, findingId, { ...o, by: 'Claude Code', at: new Date().toISOString() })
  return sessionDetail(sessionId)
}
