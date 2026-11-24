/**
 * Where a test request may go. A site you test can answer with an address that is not its own: a private
 * network address, the cloud metadata address, or an address that changes between two questions (DNS
 * rebinding). This guard looks up the site's addresses before a request, pins the first answer, and refuses:
 *   - the cloud metadata addresses, always (nobody tests those);
 *   - an answer that mixes public and private addresses (the usual rebinding trick);
 *   - an address that is not in the pinned set any more.
 * A target that is on your own network or this Mac is fine: the first answer is simply pinned.
 * Nothing here sends a request to the site.
 */
import { lookup } from 'dns/promises'
import { isIP } from 'net'

export type IpClass = 'public' | 'private' | 'loopback' | 'link-local' | 'metadata' | 'reserved'

function v4(ip: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip)
  if (!m) return null
  const p = m.slice(1).map(Number)
  return p.every((x) => x >= 0 && x <= 255) ? p : null
}

/** What kind of address this is. IPv6 addresses that wrap an IPv4 one are judged by the IPv4 inside. */
export function classify(ip: string): IpClass {
  const raw = ip.toLowerCase().replace(/^\[|\]$/g, '').split('%')[0]
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(raw)?.[1]
  const a = v4(mapped ?? raw)
  if (a) {
    const [x, y] = a
    if (x === 169 && y === 254 && a[2] === 169 && a[3] === 254) return 'metadata'
    if (x === 100 && y === 100 && a[2] === 100 && a[3] === 200) return 'metadata'
    if (x === 127) return 'loopback'
    if (x === 10 || (x === 172 && y >= 16 && y <= 31) || (x === 192 && y === 168)) return 'private'
    if (x === 169 && y === 254) return 'link-local'
    if (x === 100 && y >= 64 && y <= 127) return 'private'
    if (x === 0 || x >= 224 || (x === 192 && y === 0 && a[2] === 0) || (x === 198 && (y === 18 || y === 19))) return 'reserved'
    return 'public'
  }
  if (raw === '::1') return 'loopback'
  if (raw === '::' || raw.startsWith('ff')) return 'reserved'
  if (raw === 'fd00:ec2::254') return 'metadata'
  if (/^f[cd]/.test(raw)) return 'private'
  if (/^fe[89ab]/.test(raw)) return 'link-local'
  return isIP(raw) ? 'public' : 'reserved'
}

export const isRestricted = (ip: string): boolean => classify(ip) !== 'public'

export type Resolver = (host: string) => Promise<string[]>

const defaultResolver: Resolver = async (host) => (await lookup(host, { all: true })).map((r) => r.address)

export class NetGuard {
  private pinned = new Map<string, Set<string>>()
  private checked = new Map<string, number>()
  /** The address this host was approved on, for a request that must not resolve again. */
  private approved = new Map<string, string>()

  constructor(private resolver: Resolver = defaultResolver, private every = 10_000, private now: () => number = Date.now) {}

  /** Throws with a plain reason when the request should not go. A name that does not resolve is left to the request itself. */
  /** The approved address for a host, or null when nothing was pinned (a name that does not resolve). */
  addressFor(host: string): string | null {
    const h = host.replace(/^\[|\]$/g, '').toLowerCase()
    return this.approved.get(h) ?? null
  }

  async check(host: string): Promise<void> {
    const h = host.replace(/^\[|\]$/g, '').toLowerCase()
    const last = this.checked.get(h)
    if (last !== undefined && this.now() - last < this.every) return
    let ips: string[]
    try {
      ips = isIP(h) ? [h] : await this.resolver(h)
    } catch {
      return
    }
    if (!ips.length) return
    this.checked.set(h, this.now())
    const bad = ips.find((ip) => classify(ip) === 'metadata')
    if (bad) throw new Error(`${h} points at a cloud metadata address (${bad}). MacSec never tests that.`)
    const classes = new Set(ips.map((ip) => (classify(ip) === 'public' ? 'public' : 'inside')))
    if (classes.size > 1) throw new Error(`${h} answers with both public and private addresses. That is a DNS rebinding trick, so the test stopped.`)
    const pin = this.pinned.get(h)
    if (!pin) {
      this.pinned.set(h, new Set(ips))
      this.approved.set(h, ips[0])
      return
    }
    const moved = ips.filter((ip) => !pin.has(ip))
    if (moved.length) {
      // A normal change of server inside the same kind of network is allowed once; going from public to private never is.
      const was = [...pin].some((ip) => classify(ip) === 'public')
      if (was && moved.some((ip) => classify(ip) !== 'public')) throw new Error(`${h} moved from a public address to a private one (${moved[0]}) during the test. DNS rebinding is possible, so the test stopped.`)
      for (const ip of moved) pin.add(ip)
    }
  }
}
