import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Engagement } from '../src/shared/impact'
import type { PinnedOptions } from '../src/main/netclient'

const calls: { url: string; o?: PinnedOptions }[] = []
vi.mock('../src/main/netclient', () => ({
  pinnedRequest: async (url: string, o?: PinnedOptions) => {
    calls.push({ url, o })
    return { status: 200, headers: new Headers({ 'x-a': '1' }), body: 'hello', url }
  }
}))

import { ImpactClient, ImpactRefused } from '../src/main/impact/client'
import { NetGuard } from '../src/main/netguard'

const iso = (d: number): string => new Date(Date.now() + d * 86_400_000).toISOString()
const eng = (over: Partial<Engagement> = {}): Engagement => ({
  id: 'eng-test0002', client: 'Acme', authorityRef: 'R', authorizedBy: 'C', hosts: ['shop.example'], allowPrivate: false,
  startsAt: iso(-1), endsAt: iso(7), caps: { requests: 20, writes: 2, minutes: 5 }, allowed: ['confidentiality'], createdAt: iso(0), used: { requests: 0, writes: 0 }, ...over
})
const client = (guard: NetGuard | false | undefined, over: Partial<Engagement> = {}): ImpactClient =>
  new ImpactClient({ engagement: eng(over), budget: { requests: 20, writes: 2 }, origin: 'https://shop.example', allowWrites: false, delayMs: 0, ...(guard !== undefined ? { guard } : {}) })

beforeEach(() => {
  calls.length = 0
})

describe('the controlled-proof client connects to the approved address', () => {
  it('passes the guard-approved address to the connection, not a fresh lookup', async () => {
    const c = client(new NetGuard(async () => ['93.184.216.34']))
    const r = await c.get('https://shop.example/x')
    expect(r.body).toBe('hello')
    expect(calls[0].o?.address).toBe('93.184.216.34')
    expect(calls[0].o?.method).toBe('GET')
  })
  it('refuses a name that points at a cloud metadata address, and sends nothing', async () => {
    const c = client(new NetGuard(async () => ['169.254.169.254']))
    await expect(c.get('https://shop.example/x')).rejects.toBeInstanceOf(ImpactRefused)
    expect(calls).toEqual([])
  })
  it('refuses a name that resolves to a private address unless the engagement says staging', async () => {
    await expect(client(new NetGuard(async () => ['10.0.0.5'])).get('https://shop.example/x')).rejects.toThrow(/not a public address/)
    expect(calls).toEqual([])
    const staging = client(new NetGuard(async () => ['10.0.0.5']), { allowPrivate: true })
    await staging.get('https://shop.example/x')
    expect(calls[0].o?.address).toBe('10.0.0.5')
  })
  it('still refuses a name that moves from public to private between two requests', async () => {
    let ans = ['93.184.216.34']
    let now = 0
    const c = new ImpactClient({ engagement: eng(), budget: { requests: 20, writes: 2 }, origin: 'https://shop.example', allowWrites: false, delayMs: 0, guard: new NetGuard(async () => ans, 1000, () => now) })
    await c.get('https://shop.example/a')
    ans = ['10.0.0.9']
    now = 5000
    await expect(c.get('https://shop.example/b')).rejects.toThrow()
    expect(calls).toHaveLength(1)
  })
  it('has a guard of its own when none is given (the real app passes none)', () => {
    expect((client(undefined) as unknown as { guard: unknown }).guard).toBeInstanceOf(NetGuard)
  })
  it('only turns the guard off when a test says so', () => {
    expect((client(false) as unknown as { guard: unknown }).guard).toBeNull()
  })
  it('uses an IP address as it is', async () => {
    const c = new ImpactClient({ engagement: eng({ hosts: ['93.184.216.34'] }), budget: { requests: 5, writes: 0 }, origin: 'https://93.184.216.34', allowWrites: false, delayMs: 0 })
    await c.get('https://93.184.216.34/x')
    expect(calls[0].o?.address).toBe('93.184.216.34')
  })
})
