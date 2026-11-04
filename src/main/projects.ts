/**
 * Where code comes from: your www folder (shared with Laramac), your GitHub account, and your
 * Azure DevOps organization. Tokens come from the Keychain and are only ever sent to the service
 * they belong to.
 */
import { execFile } from 'child_process'
import { cpSync, existsSync, lstatSync, mkdirSync, readdirSync, statSync } from 'fs'
import { basename, join } from 'path'
import type { Accounts, AzureProject, LocalProject, RemoteRepo } from '../shared/types'
import { getSettings } from './settings'
import { getPlain, getSecret, setPlain, setSecret } from './secrets'
import { projectStats } from './scanners/plan'
import { USER_AGENT } from './download'
import { localSites } from './webscan'

export function listLocal(): LocalProject[] {
  const www = getSettings().wwwPath
  if (!existsSync(www)) return []
  return readdirSync(www)
    .filter((n) => !n.startsWith('.'))
    .map((n) => join(www, n))
    .filter((p) => {
      try {
        return statSync(p).isDirectory()
      } catch {
        return false
      }
    })
    .map((p) => {
      const s = projectStats(p)
      return { name: basename(p), path: p, languages: s.languages.slice(0, 3), git: s.git, url: localSites().find((x) => x.name === basename(p))?.url }
    })
    .sort((a, b) => a.name.localeCompare(b.name))
}

/** Copies a folder you chose into www (links left out), the way Laramac imports. */
export function importIntoWww(src: string): string {
  const www = getSettings().wwwPath
  mkdirSync(www, { recursive: true })
  const base = basename(src).replace(/[^A-Za-z0-9._-]/g, '-') || 'project'
  let name = base
  for (let i = 2; existsSync(join(www, name)); i++) name = `${base}-${i}`
  const target = join(www, name)
  cpSync(src, target, { recursive: true, filter: (f) => !lstatSync(f).isSymbolicLink() })
  return target
}

// ---------------------------------------------------------------- Accounts

export function accounts(): Accounts {
  return {
    github: { connected: !!getSecret('github'), login: getPlain('github-login') },
    azure: { connected: !!getSecret('azure'), org: getPlain('azure-org') }
  }
}

async function gh<T>(path: string, token: string): Promise<{ data: T; next: string | null }> {
  const res = await fetch(path.startsWith('https://') ? path : `https://api.github.com${path}`, {
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'User-Agent': USER_AGENT },
    signal: AbortSignal.timeout(20000)
  })
  if (res.status === 401) throw new Error('GitHub did not accept that token.')
  if (!res.ok) throw new Error(`GitHub answered ${res.status}.`)
  const next = /<([^>]+)>;\s*rel="next"/.exec(res.headers.get('link') ?? '')?.[1] ?? null
  return { data: (await res.json()) as T, next }
}

export async function connectGitHub(token: string | null): Promise<Accounts> {
  if (!token) {
    setSecret('github', null)
    setPlain('github-login', null)
    return accounts()
  }
  const { data } = await gh<{ login: string }>('/user', token.trim())
  setSecret('github', token.trim())
  setPlain('github-login', data.login)
  return accounts()
}

/** Every repository the account can read: its own, its organizations', and shared ones. */
export async function githubRepos(): Promise<RemoteRepo[]> {
  const token = getSecret('github')
  if (!token) throw new Error('Connect GitHub first.')
  type R = { full_name: string; clone_url: string; private: boolean; description: string | null; language: string | null; pushed_at: string; default_branch: string }
  const out: RemoteRepo[] = []
  let url: string | null = '/user/repos?per_page=100&sort=pushed&affiliation=owner,collaborator,organization_member'
  for (let i = 0; url && i < 20; i++) {
    const page: { data: R[]; next: string | null } = await gh<R[]>(url, token)
    out.push(...page.data.map((r) => ({ name: r.full_name, url: r.clone_url, private: r.private, description: r.description ?? undefined, language: r.language ?? undefined, updatedAt: r.pushed_at, defaultBranch: r.default_branch })))
    url = page.next
  }
  return out
}

/** Accepts "myorg", "dev.azure.com/myorg" or a full https address. */
export function azureOrg(input: string): string {
  const o = input
    .trim()
    .replace(/^https?:\/\//, '')
    .replace(/^dev\.azure\.com\//, '')
    .replace(/\.visualstudio\.com.*$/, '')
    .split('/')[0]
  if (!/^[\w.-]{1,100}$/.test(o)) throw new Error('Enter your Azure DevOps organization: the name after dev.azure.com/.')
  return o
}

async function az<T>(org: string, path: string, pat: string): Promise<T> {
  const res = await fetch(`https://dev.azure.com/${encodeURIComponent(org)}/${path}`, {
    headers: { Authorization: `Basic ${Buffer.from(`:${pat}`).toString('base64')}`, Accept: 'application/json' },
    redirect: 'manual',
    signal: AbortSignal.timeout(25000)
  })
  // A bad token gets a redirect to the sign-in page instead of a 401.
  if (res.status === 401 || res.status === 203 || (res.status >= 300 && res.status < 400)) throw new Error('Azure DevOps did not accept that token. It needs Code (Read) and Project and Team (Read).')
  if (res.status === 404) throw new Error(`The organization ${org} was not found.`)
  if (!res.ok) throw new Error(`Azure DevOps answered ${res.status}.`)
  return (await res.json()) as T
}

export async function connectAzure(org: string | null, pat: string | null): Promise<Accounts> {
  if (!org || !pat) {
    setSecret('azure', null)
    setPlain('azure-org', null)
    return accounts()
  }
  const o = azureOrg(org)
  await az(o, '_apis/projects?api-version=7.1&$top=1', pat.trim())
  setSecret('azure', pat.trim())
  setPlain('azure-org', o)
  return accounts()
}

/**
 * Every project and repository in the organization, or in one project when the path names one
 * (myorg/MyProject). As an administrator you see them all.
 */
export async function azureProjects(path: string): Promise<AzureProject[]> {
  const pat = getSecret('azure')
  if (!pat) throw new Error('Connect Azure DevOps first.')
  const parts = path.trim().replace(/^https?:\/\//, '').replace(/^dev\.azure\.com\//, '').split('/').filter(Boolean)
  const org = azureOrg(parts[0] || getPlain('azure-org') || '')
  const only = parts[1] ? decodeURIComponent(parts[1]) : null
  type P = { name: string; description?: string }
  type R = { name: string; remoteUrl: string; defaultBranch?: string; isDisabled?: boolean; project: { name: string; visibility?: string } }
  const projects = only ? [{ name: only }] : (await az<{ value: P[] }>(org, '_apis/projects?api-version=7.1&$top=500', pat)).value
  const repos = (await az<{ value: R[] }>(org, '_apis/git/repositories?api-version=7.1', pat)).value.filter((r) => !r.isDisabled)
  return projects
    .map((p) => ({
      name: p.name,
      description: 'description' in p ? p.description : undefined,
      repos: repos
        .filter((r) => r.project.name === p.name)
        .map((r) => ({ name: `${p.name}/${r.name}`, url: r.remoteUrl, private: r.project.visibility !== 'public', project: p.name, defaultBranch: r.defaultBranch?.replace('refs/heads/', '') }))
        .sort((a, b) => a.name.localeCompare(b.name))
    }))
    .filter((p) => p.repos.length > 0)
    .sort((a, b) => a.name.localeCompare(b.name))
}

// ---------------------------------------------------------------- Cloning

/** A header for one git command, so the token is never written into the copy's settings. */
export function authHeader(url: string, token: string): string[] {
  const host = new URL(url).hostname
  const user = host === 'github.com' ? 'x-access-token' : 'pat'
  return ['-c', `http.${new URL(url).origin}/.extraheader=AUTHORIZATION: basic ${Buffer.from(`${user}:${token}`).toString('base64')}`]
}

/** Clones into a session's private folder. Full history for deep reviews (secrets in old commits). */
export function cloneInto(url: string, target: string, fullHistory: boolean, onChild?: (c: ReturnType<typeof execFile>) => void): Promise<void> {
  if (!/^https:\/\/[^\s'"]+$/.test(url)) return Promise.reject(new Error('Only https repository addresses are supported.'))
  const host = new URL(url).hostname
  const token = host === 'github.com' ? getSecret('github') : /dev\.azure\.com$|visualstudio\.com$/.test(host) ? getSecret('azure') : null
  const clean = url.replace(/^https:\/\/[^@/]+@/, 'https://')
  const args = [...(token ? authHeader(clean, token) : []), 'clone', '--quiet', ...(fullHistory ? [] : ['--depth', '1']), clean, target]
  return new Promise((resolve, reject) => {
    const child = execFile('git', args, { env: { ...process.env, GIT_TERMINAL_PROMPT: '0' }, timeout: 30 * 60_000, maxBuffer: 1024 * 1024 }, (err, _o, stderr) => {
      if (!err) return resolve()
      const msg = String(stderr || err.message)
      reject(new Error(/Authentication|403|401|could not read Username|not found/i.test(msg) ? 'The repository could not be read. Check that the account you connected can see it.' : `Cloning failed: ${msg.trim().split('\n').pop()}`))
    })
    onChild?.(child)
  })
}
