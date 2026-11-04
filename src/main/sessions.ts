/**
 * Sessions: every test gets its own folder in ~/MacSec/sessions, so you can come back to it.
 *
 *   session.json   what ran, when, and the counts
 *   findings.json  every finding
 *   ai-report.md   the AI reviewer's write-up
 *   raw/           each scanner's own output
 *   code/          the private copy of a downloaded repository, deleted when the review ends
 *                  unless you chose to keep it
 */
import { EventEmitter } from 'events'
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'fs'
import { randomBytes } from 'crypto'
import { join, sep } from 'path'
import type { Finding, SessionDetail, SessionInfo, SessionKind } from '../shared/types'
import { dirs } from './paths'
import { countBySeverity } from './scanners/parse'

export const sessionEvents = new EventEmitter()

const SAFE_ID = /^[a-z0-9-]{8,80}$/

export function newSessionId(target: string, now = new Date()): string {
  const stamp = now.toISOString().slice(0, 19).replace(/[-:]/g, '').replace('T', '-')
  const slug = target.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(-30) || 'target'
  return `${stamp}-${slug}-${randomBytes(2).toString('hex')}`
}

export function sessionDir(id: string): string {
  if (!SAFE_ID.test(id)) throw new Error('That session does not exist.')
  return dirs.session(id)
}

export function createSession(kind: SessionKind, title: string, target: string): SessionInfo {
  const id = newSessionId(target)
  mkdirSync(join(sessionDir(id), 'raw'), { recursive: true, mode: 0o700 })
  const info: SessionInfo = { id, kind, title, target, createdAt: new Date().toISOString(), status: 'running', counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, steps: [] }
  saveSession(info)
  return info
}

export function saveSession(info: SessionInfo): void {
  // A session deleted while it was still finishing stays deleted.
  if (!existsSync(sessionDir(info.id))) return
  writeFileSync(join(sessionDir(info.id), 'session.json'), JSON.stringify(info, null, 2))
  sessionEvents.emit('updated', info)
}

export function saveFindings(id: string, findings: Finding[]): void {
  if (!existsSync(sessionDir(id))) return
  writeFileSync(join(sessionDir(id), 'findings.json'), JSON.stringify(findings, null, 2))
}

export function saveAiReport(id: string, md: string): void {
  writeFileSync(join(sessionDir(id), 'ai-report.md'), md)
}

export function readSession(id: string): SessionInfo {
  const f = join(sessionDir(id), 'session.json')
  if (!existsSync(f)) throw new Error('That session does not exist.')
  return JSON.parse(readFileSync(f, 'utf8')) as SessionInfo
}

export function sessionDetail(id: string): SessionDetail {
  const info = readSession(id)
  const dir = sessionDir(id)
  const findings = existsSync(join(dir, 'findings.json')) ? (JSON.parse(readFileSync(join(dir, 'findings.json'), 'utf8')) as Finding[]) : []
  const aiReport = existsSync(join(dir, 'ai-report.md')) ? readFileSync(join(dir, 'ai-report.md'), 'utf8') : undefined
  return { ...info, findings, ...(aiReport ? { aiReport } : {}) }
}

export function listSessions(): SessionInfo[] {
  if (!existsSync(dirs.sessions())) return []
  return readdirSync(dirs.sessions())
    .filter((d) => SAFE_ID.test(d))
    .map((d) => {
      try {
        return readSession(d)
      } catch {
        return null
      }
    })
    .filter((x): x is SessionInfo => !!x)
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
}

export function deleteSession(id: string): void {
  rmSync(sessionDir(id), { recursive: true, force: true })
}

/** The private copy of the code inside a session; only this folder is ever deleted by discardCode. */
export const sessionCodeDir = (id: string): string => join(sessionDir(id), 'code')

export function discardCode(id: string): void {
  const code = sessionCodeDir(id)
  if (!code.startsWith(dirs.sessions() + sep)) return
  rmSync(code, { recursive: true, force: true })
}

/** Sessions left "running" by a crash or a quit are marked as stopped when MacSec starts. */
export function recoverSessions(): void {
  for (const s of listSessions()) {
    if (s.status === 'running') {
      s.status = 'cancelled'
      s.error = 'MacSec closed before this finished.'
      s.steps = s.steps.map((st) => (st.status === 'running' || st.status === 'waiting' ? { ...st, status: 'skipped' } : st))
      saveSession(s)
    }
  }
}

/** The request that started a session, kept so the same test can be run again. */
export function saveRequest(id: string, channel: string, req: unknown): void {
  if (!existsSync(sessionDir(id))) return
  writeFileSync(join(sessionDir(id), 'request.json'), JSON.stringify({ channel, req }, null, 2), { mode: 0o600 })
}

export function readRequest(id: string): { channel: string; req: unknown } | null {
  const f = join(sessionDir(id), 'request.json')
  try {
    return existsSync(f) ? (JSON.parse(readFileSync(f, 'utf8')) as { channel: string; req: unknown }) : null
  } catch {
    return null
  }
}

/** Marks a finding fixed, accepted or not a problem (or open again); the counts follow. */
export function triageFinding(id: string, findingId: string, triage: Finding['triage'] | null): SessionDetail {
  const info = readSession(id)
  const f = join(sessionDir(id), 'findings.json')
  const list = existsSync(f) ? (JSON.parse(readFileSync(f, 'utf8')) as Finding[]) : []
  const item = list.find((x) => x.id === findingId)
  if (!item) throw new Error('That finding is not in this session.')
  if (triage) {
    item.triage = triage
    item.triagedAt = new Date().toISOString()
  } else {
    delete item.triage
    delete item.triagedAt
  }
  writeFileSync(f, JSON.stringify(list, null, 2))
  info.counts = countBySeverity(list.filter((x) => x.verdict !== 'false-positive'))
  saveSession(info)
  return sessionDetail(id)
}

/** A request without cookies, sign-in headers or API keys: those are never written to disk. */
export function stripSecrets(req: unknown): unknown {
  if (!req || typeof req !== 'object') return req
  const r = { ...(req as Record<string, unknown>) }
  delete r.headers
  delete r.token
  if (r.auth && typeof r.auth === 'object') r.auth = { kind: 'none' }
  return r
}
