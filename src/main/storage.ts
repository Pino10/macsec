/**
 * How much MacSec keeps, and how to let some of it go. Sessions are the only thing that grows
 * without a limit, so cleaning up is by age and always says what it removed.
 */
import { execFile } from 'child_process'
import { rmSync } from 'fs'
import { listSessions, sessionDir } from './sessions'
import { dirs } from './paths'
import { log } from './logs'

export interface StorageInfo {
  bytes: number
  sessions: number
  findings: number
}

const folderBytes = (): Promise<number> =>
  new Promise((resolve) => {
    execFile('du', ['-sk', dirs.root()], { timeout: 20_000 }, (_e, out) => {
      const kb = Number(String(out ?? '').trim().split(/\s+/)[0])
      resolve(Number.isFinite(kb) ? kb * 1024 : 0)
    })
  })

export async function storageInfo(): Promise<StorageInfo> {
  const sessions = listSessions()
  const findings = sessions.reduce((n, s) => n + Object.values(s.counts).reduce((a, b) => a + b, 0), 0)
  return { bytes: await folderBytes(), sessions: sessions.length, findings }
}

/** Deletes sessions older than `days`. Returns what was removed, never a guess. */
export async function pruneSessions(days: number): Promise<{ removed: number; info: StorageInfo }> {
  const d = Math.round(Number(days))
  if (!Number.isFinite(d) || d < 7 || d > 3650) throw new Error('Choose between 7 and 3650 days.')
  const cutoff = Date.now() - d * 86400_000
  let removed = 0
  for (const s of listSessions()) {
    if (s.status === 'running') continue
    if (new Date(s.createdAt).getTime() >= cutoff) continue
    try {
      rmSync(sessionDir(s.id), { recursive: true, force: true })
      removed++
    } catch {
      // A folder that cannot be removed is left, and the count says so.
    }
  }
  log('info', `Removed ${removed} session${removed === 1 ? '' : 's'} older than ${d} days`)
  return { removed, info: await storageInfo() }
}
