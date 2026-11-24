/**
 * Find a finding anywhere: across every session on this Mac, without opening them one by one.
 * It reads the newest sessions first and stops at the limit, so it stays quick at this size; a
 * real index (SQLite) is the next step when a Mac holds thousands of sessions.
 */
import type { SessionInfo } from '../shared/types'
import { listSessions, sessionDetail } from './sessions'
import { indexFindings, indexSessionRow, isBuilt, markBuilt, searchIndex } from './indexdb'

export interface SearchHit {
  sessionId: string
  sessionTitle: string
  kind: SessionInfo['kind']
  at: string
  findingId: string
  title: string
  severity: string
  tool: string
  where: string
}

export async function searchFindings(query: string, limit = 80): Promise<SearchHit[]> {
  const term = String(query ?? '').trim().toLowerCase()
  if (term.length < 2) return []
  const indexed = await searchIndex(term, limit)
  if (indexed && indexed.length) return indexed
  if (indexed && (await isBuilt())) return []
  const out: SearchHit[] = []
  for (const s of listSessions().slice(0, 300)) {
    if (out.length >= limit) break
    if (s.status === 'running') continue
    let detail: ReturnType<typeof sessionDetail>
    try {
      detail = sessionDetail(s.id)
    } catch {
      continue
    }
    for (const f of detail.findings) {
      const where = f.file ?? f.url ?? ''
      if (![f.title, f.tool, where, f.checkId ?? ''].some((x) => x.toLowerCase().includes(term))) continue
      out.push({ sessionId: s.id, sessionTitle: s.title, kind: s.kind, at: s.createdAt, findingId: f.id, title: f.title, severity: f.severity, tool: f.tool, where })
      if (out.length >= limit) break
    }
  }
  // First run (or an index that cannot be used): read the sessions once, then warm the index.
  if (indexed !== null) {
    for (const s of listSessions().slice(0, 300)) {
      try {
        const d = sessionDetail(s.id)
        await indexSessionRow(s)
        await indexFindings(s.id, d.findings, s.createdAt)
      } catch {
        // A session that cannot be read is skipped.
      }
    }
    await markBuilt()
  }
  return out
}
