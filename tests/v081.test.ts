import { readFileSync } from 'fs'
import { join } from 'path'
import { beforeEach, describe, expect, it } from 'vitest'
import { configureGitHub, GitHubLimitError, githubApi, latestRelease, parseReleaseFeed, releasesWithFallback, resetGitHubCache } from '../src/main/seckit/ghapi'

const feed = readFileSync(join(__dirname, 'fixtures', 'github', 'laramac-releases.atom'), 'utf8')
type Call = { url: string; headers: Record<string, string> }
const fake = (answer: (url: string, n: number) => Response) => {
  const calls: Call[] = []
  const f = (async (url: string, init?: { headers?: Record<string, string> }) => {
    calls.push({ url, headers: init?.headers ?? {} })
    return answer(url, calls.length)
  }) as unknown as typeof fetch
  return { f, calls }
}
const json = (data: unknown, headers: Record<string, string> = {}): Response => new Response(JSON.stringify(data), { status: 200, headers: { 'content-type': 'application/json', ...headers } })
const limited = (): Response => new Response('{"message":"API rate limit exceeded"}', { status: 403, headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': String(Math.floor(Date.now() / 1000) + 1800) } })

describe('GitHub without running out', () => {
  beforeEach(() => {
    resetGitHubCache()
    configureGitHub({ userAgent: 'Test', token: () => null })
  })

  it('keeps answers, and asks again with the ETag later', async () => {
    let t = 0
    const { f, calls } = fake((_u, n) => (n === 1 ? json({ v: 1 }, { etag: '"abc"' }) : new Response(null, { status: 304 })))
    expect(await githubApi('/repos/a/b', { f, now: () => t })).toEqual({ v: 1 })
    expect(await githubApi('/repos/a/b', { f, now: () => t })).toEqual({ v: 1 })
    expect(calls).toHaveLength(1)
    t = 11 * 60_000
    expect(await githubApi('/repos/a/b', { f, now: () => t })).toEqual({ v: 1 })
    expect(calls).toHaveLength(2)
    expect(calls[1].headers['If-None-Match']).toBe('"abc"')
  })

  it('uses the GitHub sign-in, only for api.github.com', async () => {
    configureGitHub({ userAgent: 'Test', token: () => 'gho_token' })
    const { f, calls } = fake(() => json([]))
    await githubApi('/repos/a/b/releases', { f })
    expect(calls[0].url).toBe('https://api.github.com/repos/a/b/releases')
    expect(calls[0].headers.Authorization).toBe('Bearer gho_token')
    await githubApi('https://evil.example/repos', { f })
    expect(calls[1].url.startsWith('https://api.github.com/')).toBe(true)
  })

  it('says when the hourly limit comes back, and stops asking until then', async () => {
    const { f, calls } = fake(() => limited())
    const e = await githubApi('/repos/a/b', { f }).catch((x) => x)
    expect(e).toBeInstanceOf(GitHubLimitError)
    expect(String(e.message)).toMatch(/60 checks an hour.*comes back at \d\d:\d\d.*Connect your GitHub account/)
    await expect(githubApi('/repos/a/c', { f })).rejects.toBeInstanceOf(GitHubLimitError)
    expect(calls).toHaveLength(1)
  })

  it('uses the last answer when the limit is reached', async () => {
    let t = 0
    const { f } = fake((_u, n) => (n === 1 ? json({ tag_name: 'v1' }) : limited()))
    await githubApi('/repos/a/b', { f, now: () => t })
    t = 20 * 60_000
    expect(await githubApi('/repos/a/b', { f, now: () => t })).toEqual({ tag_name: 'v1' })
  })

  it('finds the newest release from github.com when the API is used up', async () => {
    const { f, calls } = fake((url) => (url.startsWith('https://api.github.com') ? limited() : new Response(null, { status: 302, headers: { location: 'https://github.com/ollama/ollama/releases/tag/v0.12.9' } })))
    const r = await latestRelease('ollama/ollama', f)
    expect(r).toEqual({ tag: 'v0.12.9', assets: [], fromWeb: true })
    expect(calls[1].url).toBe('https://github.com/ollama/ollama/releases/latest')
  })

  it('reads the real release feed', () => {
    const list = parseReleaseFeed(feed)
    expect(list).toHaveLength(10)
    expect(list[0].tag).toBe('v0.23.1')
    expect(list[0].url).toBe('https://github.com/Pino10/laramac/releases/tag/v0.23.1')
    expect(list[0].notes.startsWith('## New in 0.23.1\n\n### Studio, rich and in glass')).toBe(true)
    expect(list[1].notes).toContain('- **claudefree**')
    expect(list[0].notes).not.toMatch(/<\/?[a-z]+>|&lt;|&amp;/)
  })

  it('offers app updates from the feed, with links built for the DMGs and checksums', async () => {
    const { f } = fake((url) => (url.startsWith('https://api.github.com') ? limited() : new Response(feed, { status: 200 })))
    const list = await releasesWithFallback('Pino10/laramac', (v) => [`Laramac-${v}-arm64.dmg`, 'SHA256SUMS.txt'], f)
    expect(list[0].tag_name).toBe('v0.23.1')
    expect(list[0].assets).toEqual([
      { name: 'Laramac-0.23.1-arm64.dmg', browser_download_url: 'https://github.com/Pino10/laramac/releases/download/v0.23.1/Laramac-0.23.1-arm64.dmg' },
      { name: 'SHA256SUMS.txt', browser_download_url: 'https://github.com/Pino10/laramac/releases/download/v0.23.1/SHA256SUMS.txt' }
    ])
  })
})
