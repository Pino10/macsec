/**
 * Findings as tickets. A ticket carries what a developer needs and nothing secret: the problem, where,
 * how it was proven and how to repeat it, and the fix. It can be copied as Markdown (GitHub, Linear),
 * as Jira wiki text, or created as a GitHub issue with a token kept in the Keychain. The token is sent
 * only to api.github.com, and only for the repository you name.
 */
import type { Finding, SessionInfo } from '../shared/types'

const SEV = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' } as const

export function ticketTitle(f: Finding): string {
  return `[${SEV[f.severity]}] ${f.title}`.slice(0, 200)
}

export function ticketMarkdown(f: Finding, s: Pick<SessionInfo, 'title' | 'target' | 'createdAt'>): string {
  const p = f.proof
  const lines = [
    `**Found by MacSec** in ${s.title} (${s.target}) on ${s.createdAt.slice(0, 10)}`,
    '',
    `| | |`,
    `|---|---|`,
    `| Severity | ${SEV[f.severity]} |`,
    ...(f.exploit ? [`| Status | ${f.exploit.label}: ${f.exploit.why.replace(/\|/g, '/')} |`] : f.confidence ? [`| Status | ${f.confidence === 'confirmed' ? 'Confirmed' : 'Possible'} |`] : []),
    ...(f.checkId ? [`| Check | ${f.checkId} |`] : []),
    ...(f.cwe ? [`| Weakness | ${f.cwe} |`] : []),
    ...(f.advisory ? [`| Advisory | ${f.advisory} |`] : []),
    ...(f.url || f.file ? [`| Where | \`${(f.url ?? f.file ?? '').replace(/`/g, '')}\` |`] : []),
    '',
    ...(f.description ? ['## What is wrong', f.description, ''] : []),
    ...(p ? ['## How it was shown', ...p.shows.map((x) => `- ${x}`), '', 'Repeat it:', '```sh', p.reproduce, '```', ''] : []),
    ...(f.fix ? ['## How to fix it', f.fix, ''] : []),
    '_Secrets are never included in MacSec findings. After the fix, run the same check again to close this ticket._'
  ]
  return lines.join('\n')
}

/** Jira wiki markup. */
export function ticketJira(f: Finding, s: Pick<SessionInfo, 'title' | 'target' | 'createdAt'>): string {
  const p = f.proof
  return [
    `*Found by MacSec* in ${s.title} (${s.target}) on ${s.createdAt.slice(0, 10)}`,
    `*Severity:* ${SEV[f.severity]}${f.exploit ? `   *Status:* ${f.exploit.label}` : ''}${f.cwe ? `   *Weakness:* ${f.cwe}` : ''}${f.checkId ? `   *Check:* ${f.checkId}` : ''}`,
    ...(f.url || f.file ? [`*Where:* {{${(f.url ?? f.file ?? '').replace(/[{}]/g, '')}}}`] : []),
    '',
    ...(f.description ? ['h3. What is wrong', f.description, ''] : []),
    ...(p ? ['h3. How it was shown', ...p.shows.map((x) => `* ${x}`), '', '{code}', p.reproduce, '{code}', ''] : []),
    ...(f.fix ? ['h3. How to fix it', f.fix] : [])
  ].join('\n')
}

export const validRepo = (r: string): boolean => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}$/.test(r)

export async function createGithubIssue(repo: string, f: Finding, s: Pick<SessionInfo, 'title' | 'target' | 'createdAt'>, token: string, fetchImpl: typeof fetch = fetch): Promise<{ url: string; number: number }> {
  if (!validRepo(repo)) throw new Error('Enter the repository as owner/name, for example acme/shop.')
  if (!token) throw new Error('Connect GitHub on Settings first: MacSec needs a token that may create issues.')
  const r = await fetchImpl(`https://api.github.com/repos/${repo}/issues`, {
    method: 'POST',
    redirect: 'manual',
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'MacSec', 'Content-Type': 'application/json' },
    body: JSON.stringify({ title: ticketTitle(f), body: ticketMarkdown(f, s).slice(0, 60000) }),
    signal: AbortSignal.timeout(30000)
  })
  if (r.status === 404) throw new Error('GitHub says that repository does not exist, or the token cannot see it.')
  if (r.status === 401 || r.status === 403) throw new Error('GitHub refused the token. It needs permission to create issues (Issues: write).')
  if (r.status === 410) throw new Error('Issues are turned off for that repository.')
  if (r.status !== 201) throw new Error(`GitHub answered ${r.status}.`)
  const j = (await r.json()) as { html_url?: string; number?: number }
  if (!j.html_url || !/^https:\/\/github\.com\//.test(j.html_url)) throw new Error('GitHub did not return the issue address.')
  return { url: j.html_url, number: j.number ?? 0 }
}
