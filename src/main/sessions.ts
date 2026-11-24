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
import { applyIgnored } from './ignored'
import { EventEmitter } from 'events'
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'fs'
import { randomBytes } from 'crypto'
import { join, sep } from 'path'
import type { Finding, SessionDetail, SessionInfo, SessionKind, ChecklistData } from '../shared/types'
import { dirs } from './paths'
import { countBySeverity } from './scanners/parse'
import { forgetSession, indexFindings, indexSessionRow } from './indexdb'

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
  void indexSessionRow(info)
  sessionEvents.emit('updated', info)
}

export function saveFindings(id: string, findings: Finding[]): void {
  if (!existsSync(sessionDir(id))) return
  applyIgnored(findings)
  writeFileSync(join(sessionDir(id), 'findings.json'), JSON.stringify(findings, null, 2))
  void indexFindings(id, findings, new Date().toISOString())
}

export function saveAiReport(id: string, md: string): void {
  writeFileSync(join(sessionDir(id), 'ai-report.md'), md)
}

export function savePlan(id: string, md: string): void {
  writeFileSync(join(sessionDir(id), 'test-plan.md'), md)
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
  const plan = existsSync(join(dir, 'test-plan.md')) ? readFileSync(join(dir, 'test-plan.md'), 'utf8') : undefined
  return { ...info, findings, ...(aiReport ? { aiReport } : {}), ...(plan ? { plan } : {}) }
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
  void forgetSession(id)
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
    delete item.remembered
  }
  writeFileSync(f, JSON.stringify(list, null, 2))
  info.counts = countBySeverity(list.filter((x) => x.verdict !== 'false-positive'))
  saveSession(info)
  return sessionDetail(id)
}

/** Store the independent verifier's answer beside one finding. It never changes confidence. */
export function setSecondOpinion(id: string, findingId: string, opinion: Finding['secondOpinion']): void {
  const f = join(sessionDir(id), 'findings.json')
  const list = existsSync(f) ? (JSON.parse(readFileSync(f, 'utf8')) as Finding[]) : []
  const item = list.find((x) => x.id === findingId)
  if (!item) throw new Error('That finding is not in this session.')
  item.secondOpinion = opinion
  writeFileSync(f, JSON.stringify(list, null, 2))
}

/**
 * Mark several findings at once. An owner and a due date are optional, and only kept while the
 * finding is triaged; clearing the triage clears them too.
 */
export function triageBulk(id: string, findingIds: string[], triage: Finding['triage'] | null, patch: { owner?: string; due?: string } = {}): SessionDetail {
  const info = readSession(id)
  const f = join(sessionDir(id), 'findings.json')
  const list = existsSync(f) ? (JSON.parse(readFileSync(f, 'utf8')) as Finding[]) : []
  const ids = new Set((Array.isArray(findingIds) ? findingIds : []).filter((x): x is string => typeof x === 'string').slice(0, 500))
  if (!ids.size) throw new Error('Choose at least one finding.')
  const owner = typeof patch.owner === 'string' ? patch.owner.trim().slice(0, 80) : undefined
  const due = typeof patch.due === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(patch.due) ? patch.due : undefined
  let changed = 0
  for (const item of list) {
    if (!ids.has(item.id)) continue
    changed++
    if (triage) {
      item.triage = triage
      item.triagedAt = new Date().toISOString()
      if (owner) item.owner = owner
      if (due) item.due = due
    } else {
      delete item.triage
      delete item.triagedAt
      delete item.owner
      delete item.due
      delete item.remembered
    }
  }
  if (!changed) throw new Error('Those findings are not in this session.')
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
  if (r.confirm && typeof r.confirm === 'object') {
    const c = { ...(r.confirm as Record<string, unknown>) }
    delete c.headersB
    r.confirm = c
  }
  if (r.auth && typeof r.auth === 'object') r.auth = { kind: 'none' }
  return r
}

// ---------------------------------------------------------------- The checklist walk

export type UserMark = { state: 'done' | 'problem' | 'na'; note?: string; at: string }
export type ChecklistFile = ChecklistData

export function saveChecklist(id: string, c: unknown): void {
  writeFileSync(join(sessionDir(id), 'checklist.json'), JSON.stringify(c))
}

export function readChecklist(id: string): ChecklistData {
  const dir = sessionDir(id)
  const read = (f: string): unknown => {
    try {
      return JSON.parse(readFileSync(join(dir, f), 'utf8'))
    } catch {
      return null
    }
  }
  return { checklist: read('checklist.json') as ChecklistData['checklist'], user: (read('checklist-user.json') as Record<string, UserMark> | null) ?? {} }
}

/** Your own answer on one item. Item ids look like 3.12; null takes your answer back. */
export function markChecklistItem(id: string, item: string, state: UserMark['state'] | null, note?: string): ChecklistData {
  if (!/^\d{1,3}\.\d{1,3}$/.test(item)) throw new Error('That checklist item does not exist.')
  const { user } = readChecklist(id)
  if (state) user[item] = { state, ...(note ? { note: note.slice(0, 500) } : {}), at: new Date().toISOString() }
  else delete user[item]
  writeFileSync(join(sessionDir(id), 'checklist-user.json'), JSON.stringify(user))
  return readChecklist(id)
}
