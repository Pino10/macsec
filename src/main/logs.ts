import { EventEmitter } from 'events'
import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'fs'
import { join } from 'path'
import type { LogLine } from '../shared/types'
import { dirs } from './paths'

export const logEvents = new EventEmitter()
const file = (): string => join(dirs.logs(), 'macsec.log')
const recent: LogLine[] = []

/** Keeps tokens out of the log, whatever a tool prints. */
export function redact(text: string): string {
  return text
    .replace(/(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})/g, '[token]')
    .replace(/(authorization:\s*(?:basic|bearer)\s+)[^\s'"]+/gi, '$1[hidden]')
    .replace(/(https?:\/\/)[^\s/@:]+:[^\s/@]+@/g, '$1[hidden]@')
}

export function log(level: LogLine['level'], text: string, session?: string): void {
  const line: LogLine = { at: new Date().toISOString(), level, text: redact(text).slice(0, 2000), ...(session ? { session } : {}) }
  recent.push(line)
  if (recent.length > 2000) recent.splice(0, recent.length - 2000)
  try {
    appendFileSync(file(), `${line.at} ${level.toUpperCase()} ${session ? `[${session}] ` : ''}${line.text}\n`)
  } catch {
    // The logs folder is gone; nothing to do.
  }
  logEvents.emit('line', line)
}

export function listLogs(): LogLine[] {
  if (recent.length === 0 && existsSync(file())) {
    for (const l of readFileSync(file(), 'utf8').split('\n').slice(-500)) {
      const m = /^(\S+) (INFO|WARN|ERROR) (?:\[([^\]]+)\] )?(.*)$/.exec(l)
      if (m) recent.push({ at: m[1], level: m[2].toLowerCase() as LogLine['level'], text: m[4], ...(m[3] ? { session: m[3] } : {}) })
    }
  }
  return recent.slice(-1000)
}

export function clearLogs(): void {
  recent.length = 0
  writeFileSync(file(), '')
}
