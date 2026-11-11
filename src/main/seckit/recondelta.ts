/**
 * "What changed since last time": compares two recon runs of the same domain.
 * Pure and read-only: it only looks at what the two runs already saved.
 */
export interface ReconSnapshot {
  session: string
  at: string
  hosts: string[]
  endpoints: string[]
  findings: { id: string; title: string; severity: string }[]
}

export interface ReconDelta {
  since: { session: string; at: string }
  newHosts: string[]
  goneHosts: string[]
  newEndpoints: string[]
  newFindings: { id: string; title: string; severity: string }[]
  fixedFindings: { id: string; title: string; severity: string }[]
}

const MAX = 200
const diff = <T>(a: T[], b: T[], key: (x: T) => string): T[] => {
  const have = new Set(b.map(key))
  return a.filter((x) => !have.has(key(x)))
}

export function reconDelta(prev: ReconSnapshot, cur: Omit<ReconSnapshot, 'session' | 'at'>): ReconDelta {
  const id = (x: { id: string }): string => x.id
  const s = (x: string): string => x
  return {
    since: { session: prev.session, at: prev.at },
    newHosts: diff(cur.hosts, prev.hosts, s).sort().slice(0, MAX),
    goneHosts: diff(prev.hosts, cur.hosts, s).sort().slice(0, MAX),
    newEndpoints: diff(cur.endpoints, prev.endpoints, s).sort().slice(0, MAX),
    newFindings: diff(cur.findings, prev.findings, id).slice(0, MAX),
    fixedFindings: diff(prev.findings, cur.findings, id).slice(0, MAX)
  }
}

export const deltaIsEmpty = (d: ReconDelta): boolean => !d.newHosts.length && !d.goneHosts.length && !d.newEndpoints.length && !d.newFindings.length && !d.fixedFindings.length

/** A short plain-English summary for the report. */
export function deltaText(d: ReconDelta): string {
  if (deltaIsEmpty(d)) return `Nothing changed since the last recon (${d.since.at.slice(0, 10)}).`
  const parts: string[] = []
  if (d.newHosts.length) parts.push(`${d.newHosts.length} new host${d.newHosts.length === 1 ? '' : 's'}`)
  if (d.goneHosts.length) parts.push(`${d.goneHosts.length} host${d.goneHosts.length === 1 ? '' : 's'} no longer seen`)
  if (d.newEndpoints.length) parts.push(`${d.newEndpoints.length} new endpoint${d.newEndpoints.length === 1 ? '' : 's'}`)
  if (d.newFindings.length) parts.push(`${d.newFindings.length} new finding${d.newFindings.length === 1 ? '' : 's'}`)
  if (d.fixedFindings.length) parts.push(`${d.fixedFindings.length} finding${d.fixedFindings.length === 1 ? '' : 's'} no longer seen`)
  return `Since the last recon (${d.since.at.slice(0, 10)}): ${parts.join(', ')}.`
}
