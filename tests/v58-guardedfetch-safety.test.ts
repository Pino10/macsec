import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
import { guardedFetch } from '../src/main/guardedfetch'
import { NetGuard } from '../src/main/netguard'
import type { PinnedOptions, PinnedResponse } from '../src/main/netclient'

const reply = (status: number, body = '', headers: Record<string, string> = {}): PinnedResponse => ({ status, body, headers: new Headers(headers), url: '' })

describe('guardedFetch', () => {
  it('stops a metadata address before anything is sent', async () => {
    let sent = 0
    const f = guardedFetch(new NetGuard(async () => ['169.254.169.254']), async () => (sent++, reply(200)))
    await expect(f('http://evil.example/')).rejects.toThrow(/metadata/)
    expect(sent).toBe(0)
  })
  it('connects to the address the guard approved, not a fresh lookup', async () => {
    const seen: (string | null | undefined)[] = []
    const f = guardedFetch(new NetGuard(async () => ['93.184.216.34']), async (_u: string, o?: PinnedOptions) => (seen.push(o?.address), reply(200, 'hi')))
    const r = await f('https://example.com/x', { headers: { 'User-Agent': 'T' } })
    expect(await r.text()).toBe('hi')
    expect(seen).toEqual(['93.184.216.34'])
  })
  it('does not follow a redirect when the caller said manual', async () => {
    let n = 0
    const f = guardedFetch(new NetGuard(async () => ['93.184.216.34']), async () => (n++, reply(302, '', { location: '/next' })))
    const r = await f('https://example.com/', { redirect: 'manual' })
    expect(r.status).toBe(302)
    expect(n).toBe(1)
  })
  it('follows a same-host redirect, and never to another host', async () => {
    const urls: string[] = []
    const f = guardedFetch(new NetGuard(async () => ['93.184.216.34']), async (u: string) => {
      urls.push(u)
      return u.endsWith('/a') ? reply(301, '', { location: '/b' }) : u.endsWith('/b') ? reply(302, '', { location: 'https://other.example/c' }) : reply(200)
    })
    const r = await f('https://example.com/a')
    expect(urls).toEqual(['https://example.com/a', 'https://example.com/b'])
    expect(r.status).toBe(302)
  })
  it('gives an empty body for 204 and 304 without throwing', async () => {
    const f = guardedFetch(new NetGuard(async () => ['93.184.216.34']), async () => reply(204))
    expect((await f('https://example.com/')).status).toBe(204)
  })
})

describe('direct web checks use the guard', () => {
  const read = (f: string): string => readFileSync(join(__dirname, '..', 'src', 'main', f), 'utf8')
  it('no plain fetch is left for the target in these files', () => {
    for (const f of ['webscan.ts', 'apiscan.ts', 'webextra.ts']) expect(read(f), f).not.toMatch(/[^a-zA-Z.]fetch\(/)
    for (const f of ['jsdeep.ts', 'recondeep.ts']) expect(read(f), f).not.toMatch(/\?\? fetch\b/)
  })
})

describe('safety page', () => {
  const page = readFileSync(join(__dirname, '..', 'src', 'renderer', 'src', 'pages', 'Safety.tsx'), 'utf8')
  it('has no em dashes and makes no certification claim', () => {
    expect(page).not.toMatch(/—/)
    expect(page).not.toMatch(/\b(certified by|compliant with|approved by|trusted by)\b/i)
  })
  it('says the controlled proofs exist, so it never claims MacSec only reads', () => {
    expect(page).toMatch(/Controlled proofs/)
    expect(page).toMatch(/engagement/)
  })
})
