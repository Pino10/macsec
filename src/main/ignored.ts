/**
 * "This is not it": what you told MacSec to stop reporting.
 *
 * A rule is kept in ~/MacSec/config/ignored.json and holds only what is needed to recognise the finding
 * again: its id, its title, the place and when you said so. Never a secret value.
 * "This site" matches the same finding (same id). "Everywhere" matches the same kind of finding by title.
 * An ignored finding is not deleted: it stays in the report, marked "Not a problem", and stops counting.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs'
import { join } from 'path'
import { dirs } from './paths'
import type { Finding } from '../shared/types'

export interface IgnoreRule {
  /** Random-looking but stable key: the finding id, or "title:" plus the title for everywhere. */
  key: string
  scope: 'site' | 'everywhere'
  /** The finding id (site) or the title with numbers removed (everywhere). */
  match: string
  title: string
  /** Where it was seen, for the list. */
  place?: string
  at: string
}

const file = (): string => join(dirs.config(), 'ignored.json')

export function readRules(): IgnoreRule[] {
  try {
    const list = JSON.parse(readFileSync(file(), 'utf8')) as IgnoreRule[]
    return Array.isArray(list) ? list.filter((r) => r && typeof r.key === 'string' && typeof r.match === 'string') : []
  } catch {
    return []
  }
}

function write(list: IgnoreRule[]): void {
  mkdirSync(dirs.config(), { recursive: true, mode: 0o700 })
  writeFileSync(file(), JSON.stringify(list, null, 2), { mode: 0o600 })
}

/** The same kind of finding on another site: numbers (counts, sizes) and the host name left out. */
export function kindOf(title: string): string {
  return title.replace(/\d+/g, '#').replace(/\s+/g, ' ').trim().toLowerCase()
}

export function addRule(f: Pick<Finding, 'id' | 'title' | 'file' | 'url'>, scope: 'site' | 'everywhere'): IgnoreRule[] {
  const match = scope === 'site' ? f.id : kindOf(f.title)
  const key = `${scope}:${match}`
  const list = readRules().filter((r) => r.key !== key)
  list.push({ key, scope, match, title: f.title.slice(0, 160), place: (f.file ?? f.url ?? '').slice(0, 200) || undefined, at: new Date().toISOString() })
  write(list)
  return list
}

export function removeRule(key: string): IgnoreRule[] {
  const list = readRules().filter((r) => r.key !== key)
  if (existsSync(file()) || list.length) write(list)
  return list
}

export function isIgnored(f: Pick<Finding, 'id' | 'title'>, rules = readRules()): boolean {
  const kind = kindOf(f.title)
  return rules.some((r) => (r.scope === 'site' ? r.match === f.id : r.match === kind))
}

/** Marks every finding that matches a rule as "Not a problem". Returns how many were marked. */
export function applyIgnored(findings: Finding[]): number {
  const rules = readRules()
  if (!rules.length) return 0
  let n = 0
  for (const f of findings) {
    if (f.triage || !isIgnored(f, rules)) continue
    f.triage = 'not-a-problem'
    f.triagedAt = new Date().toISOString()
    f.remembered = true
    n++
  }
  return n
}
