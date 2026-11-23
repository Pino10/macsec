/**
 * The same problem found by two scanners should be one finding. Two findings are the same when they are in
 * the same place (the same file and line, or the same address) and name the same weakness (the same CWE, or
 * the same title once numbers and tool names are taken out). The stronger one is kept, and it lists the
 * other tools in `alsoFoundBy`. Findings in different places are never merged, and nothing with a proof is
 * dropped: when both have proof, both stay.
 */
import type { Finding, Severity } from '../shared/types'

const RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

const place = (f: Finding): string => `${(f.file ?? f.url ?? '').toLowerCase()}:${f.line ?? ''}`
const kind = (f: Finding): string => (f.cwe ? f.cwe.toUpperCase() : f.title.toLowerCase().replace(/\d+/g, '#').replace(/[^a-z# ]+/g, '').replace(/\s+/g, ' ').trim())

/** Merges findings that two tools both made. Returns a new list; the input is not changed. */
export function correlate(findings: Finding[]): Finding[] {
  const groups = new Map<string, Finding[]>()
  const out: Finding[] = []
  for (const f of findings) {
    // A finding with no place cannot be matched: leave it alone.
    if (!(f.file ?? f.url)) {
      out.push(f)
      continue
    }
    const key = `${place(f)}|${kind(f)}`
    groups.set(key, [...(groups.get(key) ?? []), f])
  }
  for (const list of groups.values()) {
    const primary = new Set(list.map((f) => f.tool))
    // Tools an earlier merge already listed stay listed.
    const tools = [...new Set(list.flatMap((f) => [f.tool, ...(f.alsoFoundBy ?? [])]))]
    if (list.length === 1 || primary.size === 1) {
      out.push(...list)
      continue
    }
    const withProof = list.filter((f) => f.proof)
    if (withProof.length > 1) {
      out.push(...list)
      continue
    }
    const best = [...list].sort((a, b) => Number(!!b.proof) - Number(!!a.proof) || RANK[a.severity] - RANK[b.severity] || (b.description?.length ?? 0) - (a.description?.length ?? 0))[0]
    out.push({ ...best, alsoFoundBy: tools.filter((t) => t !== best.tool) })
  }
  return out
}
