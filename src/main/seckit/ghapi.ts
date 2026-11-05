/**
 * GitHub, without running out. Shared by Laramac and MacSec (keep both copies of src/main/seckit
 * the same).
 *
 * GitHub allows about 60 API calls an hour from a network that is not signed in, and every app on
 * that network shares them. Update checks, the Updates page, tool installs and version lookups
 * used to spend them one by one, so after a busy hour GitHub answered 403 to everything.
 *
 * Now every call to api.github.com goes through here:
 *   - with your GitHub sign-in when you added one (5,000 an hour), sent only to api.github.com;
 *   - answers are kept for a while, and asked again with an ETag, which GitHub does not count
 *     when nothing changed;
 *   - when the hour is used up, the last answer is used if there is one, and release lookups
 *     fall back to github.com's own release pages, which have no hourly limit;
 *   - and when nothing works, you get a sentence that says when it comes back.
 */
export const GITHUB_API = 'https://api.github.com'

type Fetch = typeof fetch

export class GitHubLimitError extends Error {
  constructor(public resetAt: number | null, signedIn: boolean) {
    super(limitMessage(resetAt, signedIn))
  }
}

let tokenFn: () => string | null = () => null
let userAgent = 'GitHub client'
/** The app gives its name and, when there is one, a way to read the GitHub sign-in. */
export function configureGitHub(o: { userAgent: string; token?: () => string | null }): void {
  userAgent = o.userAgent
  if (o.token) tokenFn = o.token
}

const cache = new Map<string, { at: number; etag: string | null; data: unknown }>()
let limitedUntil = 0
export const KEEP_MS = 10 * 60_000

/** For tests. */
export function resetGitHubCache(): void {
  cache.clear()
  limitedUntil = 0
}

const clock = (ms: number): string => new Date(ms).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })

export function limitMessage(resetAt: number | null, signedIn: boolean): string {
  const when = resetAt ? ` It comes back at ${clock(resetAt)}.` : ' It comes back within the hour.'
  return signedIn
    ? `GitHub's hourly limit for your account is used up.${when}`
    : `GitHub only allows about 60 checks an hour from apps that are not signed in, and this network has used them up.${when} Connect your GitHub account to get 5,000 an hour.`
}

function token(): string | null {
  try {
    return tokenFn() || null
  } catch {
    return null
  }
}

/** GETs a GitHub API path (or full api.github.com address). `keep` is how long an answer counts as fresh. */
export async function githubApi<T>(path: string, o: { keep?: number; f?: Fetch; now?: () => number } = {}): Promise<T> {
  const f = o.f ?? fetch
  const now = o.now ?? Date.now
  const url = path.startsWith(GITHUB_API) ? path : `${GITHUB_API}${path.startsWith('/') ? '' : '/'}${path}`
  if (!url.startsWith(`${GITHUB_API}/`)) throw new Error('Only GitHub API addresses go here.')
  const hit = cache.get(url)
  if (hit && now() - hit.at < (o.keep ?? KEEP_MS)) return hit.data as T
  const tok = token()
  if (!tok && now() < limitedUntil) {
    if (hit) return hit.data as T
    throw new GitHubLimitError(limitedUntil, false)
  }
  const headers: Record<string, string> = { 'User-Agent': userAgent, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' }
  if (hit?.etag) headers['If-None-Match'] = hit.etag
  let res = await f(url, { headers: tok ? { ...headers, Authorization: `Bearer ${tok}` } : headers, signal: AbortSignal.timeout(20_000) })
  // A sign-in that expired: ask again as a visitor rather than fail.
  if (res.status === 401 && tok) res = await f(url, { headers, signal: AbortSignal.timeout(20_000) })
  if (res.status === 304 && hit) {
    hit.at = now()
    return hit.data as T
  }
  if (res.ok) {
    const data = (await res.json()) as T
    cache.set(url, { at: now(), etag: res.headers.get('etag'), data })
    return data
  }
  const remaining = res.headers.get('x-ratelimit-remaining')
  if (res.status === 429 || (res.status === 403 && (remaining === '0' || res.headers.has('retry-after')))) {
    const reset = Number(res.headers.get('x-ratelimit-reset'))
    const retry = Number(res.headers.get('retry-after'))
    const until = reset > 0 ? reset * 1000 : retry > 0 ? now() + retry * 1000 : now() + 15 * 60_000
    if (!tok) limitedUntil = until
    if (hit) return hit.data as T
    throw new GitHubLimitError(until, !!tok)
  }
  if (hit) return hit.data as T
  throw new Error(res.status === 404 ? 'GitHub could not find that.' : `GitHub answered ${res.status}.`)
}

export interface LatestRelease {
  tag: string
  assets: { name: string; url: string }[]
  /** True when it came from github.com's release page: the asset list is then empty. */
  fromWeb: boolean
}

/** A file's address in a release. These links are not rate limited. */
export const assetUrl = (repo: string, tag: string, name: string): string => `https://github.com/${repo}/releases/download/${encodeURIComponent(tag)}/${encodeURIComponent(name)}`

/** The newest release's tag from github.com/<repo>/releases/latest, which redirects to the tag. No API, no limit. */
export async function latestTagFromWeb(repo: string, f: Fetch = fetch): Promise<string> {
  const res = await f(`https://github.com/${repo}/releases/latest`, { redirect: 'manual', headers: { 'User-Agent': userAgent }, signal: AbortSignal.timeout(20_000) })
  const loc = res.headers.get('location') ?? ''
  const m = /\/releases\/tag\/([^/?#]+)/.exec(loc)
  if (!m) throw new Error(`GitHub did not say which release of ${repo} is the newest.`)
  return decodeURIComponent(m[1])
}

/** The newest release: from the API, or when GitHub's hour is used up, from its release page. */
export async function latestRelease(repo: string, f?: Fetch): Promise<LatestRelease> {
  try {
    const r = await githubApi<{ tag_name: string; assets: { name: string; browser_download_url: string }[] }>(`/repos/${repo}/releases/latest`, { f })
    return { tag: r.tag_name, assets: r.assets.map((a) => ({ name: a.name, url: a.browser_download_url })), fromWeb: false }
  } catch (e) {
    if (!(e instanceof GitHubLimitError)) throw e
    return { tag: await latestTagFromWeb(repo, f), assets: [], fromWeb: true }
  }
}

export interface FeedRelease {
  tag: string
  updated: string
  url: string
  /** The release notes, turned from the feed's HTML back into simple Markdown. */
  notes: string
}

const unescape = (s: string): string =>
  s
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&#x27;/g, "'")
    .replace(/&amp;/g, '&')

/** HTML release notes to the Markdown the app shows: headings, lists, bold, code, paragraphs. */
export function htmlToMarkdown(html: string): string {
  return unescape(
    html
      .replace(/\r/g, '')
      .replace(/<h([1-6])[^>]*>([\s\S]*?)<\/h\1>/gi, (_m, n: string, t: string) => `\n\n${'#'.repeat(Number(n))} ${t.trim()}\n\n`)
      .replace(/<li[^>]*>([\s\S]*?)<\/li>/gi, (_m, t: string) => `\n- ${t.replace(/<\/?p[^>]*>/gi, '').trim()}`)
      .replace(/<\/?(ul|ol)[^>]*>/gi, '\n')
      .replace(/<(strong|b)>([\s\S]*?)<\/\1>/gi, '**$2**')
      .replace(/<(em|i)>([\s\S]*?)<\/\1>/gi, '*$2*')
      .replace(/<code>([\s\S]*?)<\/code>/gi, '`$1`')
      .replace(/<a [^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/gi, '[$2]($1)')
      .replace(/<br\s*\/?>/gi, '\n')
      .replace(/<\/p>/gi, '\n\n')
      .replace(/<[^>]+>/g, '')
  )
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim()
}

/** Parses github.com/<repo>/releases.atom: every recent release with its notes. */
export function parseReleaseFeed(xml: string): FeedRelease[] {
  const out: FeedRelease[] = []
  for (const m of xml.matchAll(/<entry>([\s\S]*?)<\/entry>/g)) {
    const e = m[1]
    const url = /<link[^>]*href="([^"]+)"/.exec(e)?.[1] ?? ''
    const tag = /\/releases\/tag\/([^/"?#]+)/.exec(url)?.[1]
    if (!tag) continue
    const content = /<content[^>]*>([\s\S]*?)<\/content>/.exec(e)?.[1] ?? ''
    out.push({ tag: decodeURIComponent(tag), updated: /<updated>([^<]+)<\/updated>/.exec(e)?.[1] ?? '', url: unescape(url), notes: htmlToMarkdown(unescape(content)) })
  }
  return out
}

export async function releaseFeed(repo: string, f: Fetch = fetch): Promise<FeedRelease[]> {
  const res = await f(`https://github.com/${repo}/releases.atom`, { headers: { 'User-Agent': userAgent, Accept: 'application/atom+xml' }, signal: AbortSignal.timeout(20_000) })
  if (!res.ok) throw new Error(`GitHub's release feed answered ${res.status}.`)
  return parseReleaseFeed(await res.text())
}

/** Release lists in the API's shape, built from the feed: for app updates when the hour is used up. */
export interface ApiLikeRelease {
  tag_name: string
  draft: boolean
  body: string | null
  published_at: string
  html_url: string
  assets: { name: string; browser_download_url: string }[]
}

/** `files(version)` names the files each release has (the DMGs and SHA256SUMS.txt); their links are built, not looked up. */
export async function releasesWithFallback(repo: string, files: (version: string) => string[], f?: Fetch): Promise<ApiLikeRelease[]> {
  try {
    return await githubApi<ApiLikeRelease[]>(`/repos/${repo}/releases?per_page=30`, { f })
  } catch (e) {
    if (!(e instanceof GitHubLimitError)) throw e
    const feed = await releaseFeed(repo, f)
    return feed.map((r) => ({
      tag_name: r.tag,
      draft: false,
      body: r.notes,
      published_at: r.updated,
      html_url: r.url,
      assets: files(r.tag.replace(/^v/, '')).map((name) => ({ name, browser_download_url: assetUrl(repo, r.tag, name) }))
    }))
  }
}
