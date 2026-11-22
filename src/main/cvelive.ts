/**
 * Live vulnerability counts. For every software version a scan reads (a server banner, a script's own
 * banner, a WordPress generator tag), MacSec asks the public NVD database which known flaws list a
 * version range that includes it, marks the ones on CISA's known-exploited list, and adds FIRST's
 * EPSS chance of exploitation. The result is a version match: it says "this version is listed for
 * these flaws", never "this server is vulnerable", because distributions patch without changing the
 * number and some flaws need settings we cannot see. Those findings are always "possible".
 */
import type { Finding } from '../shared/types'
import { fid } from './scanners/parse'
import { matchNvd, nvdUrl, versionSeverity, type CveMatch, type Product } from './seckit/confirm'

const UA = 'MacSec (+https://github.com/Pino10/macsec) version check'

export interface Epss {
  epss: number
  percentile: number
}

export interface LiveCve {
  product: Product
  host: string
  matches: CveMatch[]
}

export interface LiveOptions {
  fetchImpl?: typeof fetch
  cancelled?: () => boolean
  note?: (t: string) => void
  /** How many NVD requests at most (NVD allows about 5 per 30 seconds without a key). */
  cap?: number
  pauseMs?: number
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))

/** FIRST's EPSS: the chance that each flaw is exploited in the next 30 days. */
export async function epssFor(ids: string[], fetchImpl: typeof fetch = fetch): Promise<Map<string, Epss>> {
  const out = new Map<string, Epss>()
  const list = [...new Set(ids)].filter((i) => /^CVE-\d{4}-\d{4,7}$/.test(i)).slice(0, 80)
  if (!list.length) return out
  try {
    const r = await fetchImpl(`https://api.first.org/data/v1/epss?cve=${list.join(',')}`, { headers: { 'User-Agent': UA, Accept: 'application/json' }, signal: AbortSignal.timeout(20000) })
    if (!r.ok) return out
    const j = (await r.json()) as { data?: { cve?: string; epss?: string; percentile?: string }[] }
    for (const d of j.data ?? []) if (d.cve && Number.isFinite(Number(d.epss))) out.set(d.cve, { epss: Number(d.epss), percentile: Number(d.percentile) })
  } catch {
    // EPSS is a bonus: the matches stand without it.
  }
  return out
}

/** Asks NVD about each product once (a little apart, as NVD asks), and keeps the flaws that cover the version. */
export async function liveCves(items: { product: Product; host: string }[], o: LiveOptions = {}): Promise<{ results: LiveCve[]; note: string }> {
  const doFetch = o.fetchImpl ?? fetch
  const results: LiveCve[] = []
  const seen = new Set<string>()
  let looked = 0
  let note = ''
  for (const { product, host } of items) {
    const key = `${product.name}@${product.version}`
    if (seen.has(key)) continue
    seen.add(key)
    if (o.cancelled?.() || looked >= (o.cap ?? 10) || note) break
    const matches = new Map<string, CveMatch>()
    for (const pair of product.cpe) {
      if (o.cancelled?.()) break
      if (looked++ > 0) await sleep(o.pauseMs ?? 6500)
      o.note?.(`Known flaws for ${product.name} ${product.version}`)
      try {
        const r = await doFetch(nvdUrl(pair, product.version), { headers: { 'User-Agent': UA, Accept: 'application/json' }, signal: AbortSignal.timeout(25000) })
        if (r.status === 403 || r.status === 429) {
          note = 'The vulnerability database asked us to slow down, so version matching stopped early.'
          break
        }
        if (!r.ok) continue
        for (const m of matchNvd((await r.text()).slice(0, 8_000_000), product)) matches.set(m.id, m)
      } catch {
        note = 'The vulnerability database could not be reached, so versions were not matched.'
        break
      }
    }
    if (matches.size) results.push({ product, host, matches: [...matches.values()].sort((a, b) => Number(b.kev) - Number(a.kev) || (b.score ?? 0) - (a.score ?? 0)) })
  }
  return { results, note }
}

/** One finding per product, with the live count, the exploited count and the EPSS of the top flaws. */
export function cveFindings(results: LiveCve[], epss: Map<string, Epss>): Finding[] {
  return results.map(({ product, host, matches }) => {
    const kev = matches.filter((m) => m.kev).length
    const top = matches.slice(0, 5)
    const topEpss = Math.max(0, ...matches.map((m) => epss.get(m.id)?.epss ?? 0))
    const line = (m: CveMatch): string => `${m.id}${m.score ? ` (score ${m.score})` : ''}${m.kev ? ', on CISA’s exploited list' : ''}${epss.has(m.id) ? `, ${(epss.get(m.id)!.epss * 100).toFixed(1)}% chance of use in the next 30 days` : ''}${m.conditional ? ', needs other conditions too' : ''}`
    return {
      id: fid('ver', product.name, product.version, host),
      tool: 'MacSec',
      category: 'web' as const,
      severity: versionSeverity(matches),
      confidence: 'possible' as const,
      title: `${product.name} ${product.version} matches ${matches.length} known flaw${matches.length === 1 ? '' : 's'}${kev ? `, ${kev} on CISA's exploited list` : ''}`,
      url: product.proof?.request.replace(/^GET /, '') ?? host,
      file: host,
      advisory: matches[0].id,
      cves: { count: matches.length, kev, topEpss, top: top.map((m) => ({ id: m.id, score: m.score, kev: m.kev, epss: epss.get(m.id)?.epss })) },
      description: `The version comes from ${product.from}. The public NVD database lists ${matches.length} flaw${matches.length === 1 ? '' : 's'} whose affected range includes it. Top: ${top.map(line).join('; ')}${matches.length > 5 ? `; and ${matches.length - 5} more` : ''}. This is a version match, not proof: the number can be old while the fixes are in${product.distro ? ` (${product.distro} fixes problems without changing the number)` : ''}, and some flaws need settings MacSec cannot see.`,
      fix: 'Update to the newest release, or ask your provider whether these fixes are in the build you run. Start with the ones on the exploited list.',
      proof: product.proof ? { ...product.proof, shows: [...product.proof.shows, `NVD lists ${matches.length} flaw${matches.length === 1 ? '' : 's'} whose range includes ${product.version}`, `counted on ${new Date().toISOString().slice(0, 10)}`] } : undefined
    }
  })
}
