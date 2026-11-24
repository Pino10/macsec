/**
 * The session index: one SQLite file (node:sqlite, which ships with the runtime) so a search does
 * not read every findings.json on the Mac. If the runtime has no SQLite, every function here says
 * "not available" and search falls back to reading the sessions, so the app still works.
 */
import { join } from 'path'
import type { Finding, SessionInfo } from '../shared/types'
import { dirs } from './paths'
import { log } from './logs'

interface Stmt {
  all(...args: unknown[]): unknown[]
  run(...args: unknown[]): unknown
}
interface Db {
  exec(sql: string): void
  prepare(sql: string): Stmt
  close?(): void
}

export interface IndexedFinding {
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

let db: Db | null | undefined
let dbPath = ''
let opening: Promise<Db | null> | null = null

const file = (): string => join(dirs.config(), 'index.db')

function open(): Promise<Db | null> {
  const want = file()
  // Tests and the app both move the root; a handle for another file must not be reused.
  if (db !== undefined && dbPath !== want) {
    try {
      db?.close?.()
    } catch {
      /* already closed */
    }
    db = undefined
    opening = null
  }
  if (db !== undefined) return Promise.resolve(db)
  if (opening) return opening
  opening = (async () => {
    try {
      const mod = (await import('node:sqlite')) as unknown as { DatabaseSync: new (path: string) => Db }
      const instance = new mod.DatabaseSync(file())
      instance.exec(`
        CREATE TABLE IF NOT EXISTS sessions (session_id TEXT PRIMARY KEY, title TEXT, kind TEXT, at TEXT);
        CREATE TABLE IF NOT EXISTS findings (session_id TEXT, finding_id TEXT, title TEXT, tool TEXT, severity TEXT, where_ TEXT, check_id TEXT, at TEXT);
        CREATE INDEX IF NOT EXISTS findings_session ON findings (session_id);
        CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
      `)
      db = instance
      dbPath = want
      return db
    } catch (e) {
      db = null
      log('warn', `The session index is off (${(e as Error).message}), so search reads the sessions directly.`)
      return null
    }
  })()
  return opening
}

/** Closes the index so the next call opens the current root (used by tests). */
export function closeIndex(): void {
  try {
    db?.close?.()
  } catch {
    /* already closed */
  }
  db = undefined
  dbPath = ''
  opening = null
}

export async function sqliteAvailable(): Promise<boolean> {
  return (await open()) !== null
}

const escape = (s: string): string => s.replace(/[\\%_]/g, (c) => `\\${c}`)

export async function indexSessionRow(info: Pick<SessionInfo, 'id' | 'title' | 'kind' | 'createdAt'>): Promise<void> {
  const d = await open()
  if (!d) return
  try {
    d.prepare('INSERT OR REPLACE INTO sessions (session_id, title, kind, at) VALUES (?, ?, ?, ?)').run(info.id, info.title.slice(0, 300), info.kind, info.createdAt)
  } catch (e) {
    log('warn', `Index: ${(e as Error).message}`)
  }
}

export async function indexFindings(sessionId: string, findings: Finding[], at: string): Promise<void> {
  const d = await open()
  if (!d) return
  try {
    d.exec('BEGIN')
    d.prepare('DELETE FROM findings WHERE session_id = ?').run(sessionId)
    const insert = d.prepare('INSERT INTO findings (session_id, finding_id, title, tool, severity, where_, check_id, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    for (const f of findings) {
      const where = (f.file ?? f.url ?? '').slice(0, 500)
      insert.run(sessionId, f.id, f.title.slice(0, 300), f.tool, f.severity, where, f.checkId ?? '', at)
    }
    d.exec('COMMIT')
  } catch (e) {
    try {
      d.exec('ROLLBACK')
    } catch {
      /* nothing to roll back */
    }
    log('warn', `Index: ${(e as Error).message}`)
  }
}

export async function forgetSession(sessionId: string): Promise<void> {
  const d = await open()
  if (!d) return
  try {
    d.prepare('DELETE FROM findings WHERE session_id = ?').run(sessionId)
    d.prepare('DELETE FROM sessions WHERE session_id = ?').run(sessionId)
  } catch {
    // A row that is already gone is fine.
  }
}

/** Null means the index is unavailable; an empty list means the index really has no match. */
export async function searchIndex(term: string, limit = 80): Promise<IndexedFinding[] | null> {
  const d = await open()
  if (!d) return null
  const q = `%${escape(term)}%`
  try {
    const rows = d
      .prepare(
        `SELECT s.session_id AS sessionId, s.title AS sessionTitle, s.kind AS kind, s.at AS at,
                f.finding_id AS findingId, f.title AS title, f.severity AS severity, f.tool AS tool, f.where_ AS where_
         FROM findings f JOIN sessions s ON s.session_id = f.session_id
         WHERE f.title LIKE ? ESCAPE '\\' OR f.tool LIKE ? ESCAPE '\\' OR f.where_ LIKE ? ESCAPE '\\' OR f.check_id LIKE ? ESCAPE '\\'
         ORDER BY s.at DESC LIMIT ?`
      )
      .all(q, q, q, q, limit) as IndexedFinding[]
    return rows
  } catch (e) {
    log('warn', `Index search: ${(e as Error).message}`)
    return null
  }
}

export async function markBuilt(): Promise<void> {
  const d = await open()
  if (!d) return
  try {
    d.prepare('INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)').run('built', new Date().toISOString())
  } catch {
    // Not fatal.
  }
}

export async function isBuilt(): Promise<boolean> {
  const d = await open()
  if (!d) return false
  try {
    return d.prepare("SELECT v FROM meta WHERE k = 'built'").all().length > 0
  } catch {
    return false
  }
}

/** Removes rows for sessions older than the cutoff, after the folders are gone. */
export async function pruneIndex(cutoffIso: string): Promise<void> {
  const d = await open()
  if (!d) return
  try {
    d.prepare('DELETE FROM findings WHERE session_id IN (SELECT session_id FROM sessions WHERE at < ?)').run(cutoffIso)
    d.prepare('DELETE FROM sessions WHERE at < ?').run(cutoffIso)
  } catch {
    // The index can be rebuilt; a failed prune here is logged on the next search.
  }
}
