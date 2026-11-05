import type { SessionInfo } from './types'

/**
 * The newest finished test of each target, which is what the Overview counts. A full audit runs a
 * code review and a web scan as sessions of their own and copies their findings into itself, so
 * those child sessions are left out here: otherwise every finding of an audit counted twice.
 * `sessions` is newest first, as listSessions gives it.
 */
export function latestPerTarget<T extends Pick<SessionInfo, 'id' | 'kind' | 'target' | 'status' | 'children'>>(sessions: T[], o: { finished?: boolean } = {}): T[] {
  const children = new Set(sessions.flatMap((s) => s.children ?? []))
  const seen = new Set<string>()
  const out: T[] = []
  for (const s of sessions) {
    if (children.has(s.id)) continue
    if (o.finished !== false ? s.status !== 'done' : s.status === 'running') continue
    const key = `${s.kind}|${s.target}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push(s)
  }
  return out
}
