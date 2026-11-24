/**
 * Bounded virtual-host discovery: one address, a short fixed list of Host headers, every answer
 * compared with a name that cannot exist. Read-only GETs, a pause between them, and nothing is
 * reported unless the answer differs from the made-up baseline in a way that can be seen.
 */
import { createHash, randomBytes } from 'crypto'
import { lookup } from 'dns/promises'
import type { VhostHit } from '../shared/types'
import { pinnedRequest } from './netclient'

const titleOf = (body: string): string => (/<title[^>]*>([^<]{1,120})<\/title>/i.exec(body)?.[1] ?? '').replace(/\s+/g, ' ').trim()
const fingerprint = (status: number, title: string, body: string): string => `${status}|${title}|${createHash('sha256').update(body).digest('hex').slice(0, 16)}`

/** Common names for a host that is already yours; the caller can pass its own instead. */
export const COMMON_VHOSTS = ['www', 'admin', 'api', 'staging', 'dev', 'test', 'internal', 'portal', 'beta', 'mail']

export async function probeVhosts(origin: string, address: string | null, names: string[], opts: { delayMs?: number; timeoutMs?: number; max?: number } = {}): Promise<VhostHit[]> {
  const base = new URL(origin)
  const delay = Math.max(0, opts.delayMs ?? 300)
  const timeout = Math.min(Math.max(1000, opts.timeoutMs ?? 8000), 20_000)
  const max = Math.min(Math.max(1, opts.max ?? 12), 20)
  const candidates = [...new Set(names)].map((n) => n.trim().toLowerCase()).filter((n) => /^[a-z0-9]([a-z0-9.-]{0,118})$/.test(n)).slice(0, max)
  const bogus = `macsec-${randomBytes(4).toString('hex')}.invalid`
  const get = async (host: string): Promise<{ status: number; body: string } | null> => {
    try {
      const r = await pinnedRequest(`${base.protocol}//${base.host}/`, { address, headers: { Host: host }, timeoutMs: timeout, maxBytes: 250_000 })
      return { status: r.status, body: r.body }
    } catch {
      return null
    }
  }
  const baseline = await get(bogus)
  const baseFp = baseline ? fingerprint(baseline.status, titleOf(baseline.body), baseline.body) : ''
  const hits: VhostHit[] = []
  for (const name of candidates) {
    if (delay) await new Promise((r) => setTimeout(r, delay))
    const r = await get(name)
    if (!r) continue
    const title = titleOf(r.body)
    if (fingerprint(r.status, title, r.body) === baseFp) continue
    hits.push({
      name,
      url: `${base.protocol}//${name}${base.port ? `:${base.port}` : ''}`,
      status: r.status,
      title,
      length: r.body.length,
      reason: baseline
        ? `a name that cannot exist answered ${baseline.status} "${titleOf(baseline.body) || 'no title'}"; this name answered ${r.status} "${title || 'no title'}"`
        : `a name that cannot exist did not answer; this name answered ${r.status} "${title || 'no title'}"`
    })
  }
  return hits
}

/** The address to pin, or null when the name does not resolve (the request may still work locally). */
export async function resolveForVhosts(host: string): Promise<string | null> {
  try {
    const r = await lookup(host)
    return r.address
  } catch {
    return null
  }
}
