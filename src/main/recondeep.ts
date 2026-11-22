/**
 * The deeper recon pass. The first pass finds the names and what answers. This one looks at what
 * each live host is actually running and how it is set up, the way a vulnerability scanner would
 * for a whole estate: security headers, certificates, firewall and CDN, versions matched to live
 * vulnerability data, and DevOps tools left open. It only reads (GET), only on hosts the recon
 * itself found, through ConfirmClient. A weakness that appears on many hosts is reported once,
 * with the list of hosts, so the report stays readable.
 */
import type { Finding } from '../shared/types'
import { checkHeaders } from './scanners/web'
import { checkTls } from './webextra'
import { ConfirmClient } from './confirmtests'
import { devopsChecks, dnsChecks, protectionOf } from './webposture'
import { bannersOf, proofOf, type Product } from './seckit/confirm'
import { cveFindings, epssFor, liveCves } from './cvelive'
import { fid } from './scanners/parse'

export interface LiveHost {
  host: string
  url: string
  status: number
  cname?: string
}

export interface DeepOptions {
  /** Base address for a host. Tests point it at a local server. */
  baseOf?: (h: LiveHost) => string
  cancelled?: () => boolean
  paused?: () => boolean
  note?: (t: string) => void
  maxHosts?: number
  skipDns?: boolean
  skipTls?: boolean
  skipCves?: boolean
  fetchImpl?: typeof fetch
}

/** The same finding on several hosts becomes one finding that lists them. */
export function mergeByTitle(perHost: { host: string; findings: Finding[] }[]): Finding[] {
  const by = new Map<string, { first: Finding; hosts: string[] }>()
  for (const { host, findings } of perHost)
    for (const f of findings) {
      const key = `${f.tool}|${f.title.replace(/https?:\/\/\S+/g, '').trim()}`
      const e = by.get(key)
      if (e) {
        if (!e.hosts.includes(host)) e.hosts.push(host)
      } else by.set(key, { first: f, hosts: [host] })
    }
  return [...by.values()].map(({ first, hosts }) => {
    if (hosts.length === 1) return first
    return { ...first, id: fid('recon-merged', first.title, hosts.join(',')), title: `${first.title} (${hosts.length} hosts)`, description: `${first.description ?? ''}\n\nSeen on: ${hosts.slice(0, 25).join(', ')}${hosts.length > 25 ? `, and ${hosts.length - 25} more` : ''}.`.trim() }
  })
}

export async function deepHosts(hosts: LiveHost[], o: DeepOptions = {}): Promise<Finding[]> {
  const note = o.note ?? (() => undefined)
  const doFetch = o.fetchImpl ?? fetch
  const list = hosts.filter((h) => h.status > 0 && h.status < 500).slice(0, o.maxHosts ?? 30)
  const perHeaders: { host: string; findings: Finding[] }[] = []
  const perTls: { host: string; findings: Finding[] }[] = []
  const devops: Finding[] = []
  const found: { product: Product; host: string }[] = []
  const unprotected: string[] = []
  for (const [i, h] of list.entries()) {
    if (o.cancelled?.()) break
    const base = o.baseOf?.(h) ?? h.url
    note(`${h.host} (${i + 1} of ${list.length})`)
    try {
      const c = new ConfirmClient(base, { cap: 140, delayMs: 100, cancelled: o.cancelled, paused: o.paused, headers: undefined })
      const home = await c.get('/', { headers: 'none' })
      perHeaders.push({ host: h.host, findings: checkHeaders(home.url, home.headers, home.headers.getSetCookie?.() ?? []) })
      for (const b of bannersOf(home.headers, home.body)) found.push({ product: { ...b, proof: proofOf({ url: home.url, status: home.status, headers: home.headers, body: home.body.slice(0, 200000), shows: [b.from] }) }, host: h.host })
      const p = protectionOf(home.headers, home.headers.get('set-cookie') ?? '')
      if (!p.waf.length && !p.hosting.length && home.status < 400) unprotected.push(h.host)
      if (!o.skipTls && base.startsWith('https://')) perTls.push({ host: h.host, findings: await checkTls(base).catch(() => []) })
      const d = await devopsChecks(new ConfirmClient(base, { cap: 110, delayMs: 100, cancelled: o.cancelled, paused: o.paused }), h.host, { note })
      devops.push(...d.findings)
      found.push(...d.products)
    } catch {
      /* one host that does not answer never stops the others */
    }
  }
  const out: Finding[] = [...mergeByTitle(perHeaders), ...mergeByTitle(perTls), ...devops]
  if (unprotected.length)
    out.push({ id: fid('recon-noshield', unprotected.join(',')), tool: 'MacSec', category: 'web', severity: 'info', confidence: 'possible', title: `No web firewall or CDN was recognised in front of ${unprotected.length} ${unprotected.length === 1 ? 'host' : 'hosts'}`, description: `Nothing in the answers named a firewall or CDN for: ${unprotected.slice(0, 20).join(', ')}${unprotected.length > 20 ? ', and more' : ''}. That is only what the headers show: a firewall that hides itself looks the same.`, fix: 'Put public hosts behind a CDN or web firewall where it makes sense, and keep the origin servers closed to everyone else.' })
  if (!o.skipDns) {
    const names = [...new Set(hosts.filter((h) => h.cname).map((h) => h.host))].slice(0, 20)
    for (const n of names) out.push(...(await dnsChecks(n).catch(() => [])))
  }
  if (!o.skipCves && found.length && !o.cancelled?.()) {
    const live = await liveCves(found, { cancelled: o.cancelled, note, cap: 12, fetchImpl: doFetch }).catch(() => null)
    if (live) out.push(...cveFindings(live.results, await epssFor(live.results.flatMap((r) => r.matches.slice(0, 10).map((x) => x.id))).catch(() => new Map())))
  }
  return out
}
