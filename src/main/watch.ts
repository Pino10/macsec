/**
 * Keeping watch, while MacSec is open:
 *
 *   Package alerts (daily, on by default): OSV-Scanner reads the lock files of the projects you
 *   reviewed on this Mac and asks osv.dev about the package versions (names and versions only:
 *   no code leaves the Mac). New critical or high flaws since the last check send a notification.
 *
 *   Weekly re-test (off by default): the newest code review of each project on this Mac runs
 *   again, and you hear about it only when it finds serious problems that were not there before.
 *
 * Both only read. State is in ~/MacSec/config/watch.json.
 */
import { execFile } from 'child_process'
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'fs'
import { join } from 'path'
import type { Finding, SessionInfo, WatchAlert, WatchInfo } from '../shared/types'
import { dirs } from './paths'
import { parseOsv } from './scanners/parse'
import { installTool, isInstalled, toolDef, toolEnv, toolPath } from './toolbox'
import { log } from './logs'

const DAY = 24 * 60 * 60_000

interface WatchState {
  packages: boolean
  retest: boolean
  lastPackages?: string
  lastRetest?: string
  /** Serious package flaws already reported, per project folder. */
  known: Record<string, string[]>
  alerts: WatchAlert[]
}

const file = (): string => join(dirs.config(), 'watch.json')

export function readWatch(): WatchState {
  const base: WatchState = { packages: true, retest: false, known: {}, alerts: [] }
  try {
    return { ...base, ...(JSON.parse(readFileSync(file(), 'utf8')) as Partial<WatchState>) }
  } catch {
    return base
  }
}

function writeWatch(s: WatchState): void {
  mkdirSync(dirs.config(), { recursive: true })
  writeFileSync(file(), JSON.stringify(s, null, 2), { mode: 0o600 })
}

export function setWatch(patch: { packages?: boolean; retest?: boolean }): WatchState {
  const s = readWatch()
  if (typeof patch.packages === 'boolean') s.packages = patch.packages
  if (typeof patch.retest === 'boolean') s.retest = patch.retest
  writeWatch(s)
  return s
}

/** The key that says "the same problem": tool, advisory or title, and the file. */
export const findingKey = (f: Pick<Finding, 'tool' | 'title' | 'file' | 'advisory'>): string => `${f.tool}|${f.advisory ?? f.title}|${f.file ?? ''}`

/** Serious findings in `next` that `prev` did not have (triaged ones do not count). */
export function newSerious(prev: Finding[], next: Finding[]): Finding[] {
  const had = new Set(prev.map(findingKey))
  return next.filter((f) => (f.severity === 'critical' || f.severity === 'high') && f.verdict !== 'false-positive' && !f.triage && !had.has(findingKey(f)))
}

/** The project folders on this Mac that have a code review: the ones worth watching. */
export function watchedProjects(sessions: SessionInfo[]): { path: string; title: string; session: string }[] {
  const seen = new Map<string, { path: string; title: string; session: string }>()
  for (const s of [...sessions].sort((a, b) => b.createdAt.localeCompare(a.createdAt))) {
    if (s.kind !== 'code-review' || s.status !== 'done' || !s.codePath || !existsSync(s.codePath)) continue
    // A downloaded copy that was kept is in the session folder; a local project is anywhere you chose.
    if (!seen.has(s.codePath)) seen.set(s.codePath, { path: s.codePath, title: s.title, session: s.id })
  }
  return [...seen.values()]
}

export function watchInfo(sessions: SessionInfo[]): WatchInfo {
  const s = readWatch()
  return { packages: s.packages, retest: s.retest, lastPackages: s.lastPackages ?? null, lastRetest: s.lastRetest ?? null, projects: watchedProjects(sessions).length, alerts: s.alerts.slice(0, 20) }
}

function osv(root: string): Promise<Finding[]> {
  const out = join(dirs.logs(), `watch-osv-${Date.now()}.json`)
  return new Promise((resolve) =>
    execFile(toolPath('osv-scanner'), ['scan', 'source', '-r', '--format', 'json', '--output', out, '.'], { cwd: root, timeout: 10 * 60_000, env: toolEnv(), maxBuffer: 50 * 1024 * 1024 }, () => {
      try {
        resolve(existsSync(out) ? parseOsv(readFileSync(out, 'utf8'), root) : [])
      } catch {
        resolve([])
      } finally {
        rmSync(out, { force: true })
      }
    })
  )
}

/** Checks the packages of every watched project now. Returns the new alerts. */
export async function checkPackages(sessions: SessionInfo[], notify: (title: string, body: string) => void): Promise<WatchAlert[]> {
  const def = toolDef('osv-scanner')
  if (def && !isInstalled(def)) await installTool('osv-scanner', () => undefined)
  const s = readWatch()
  const fresh: WatchAlert[] = []
  for (const p of watchedProjects(sessions)) {
    const found = (await osv(p.path)).filter((f) => f.severity === 'critical' || f.severity === 'high')
    const keys = found.map(findingKey)
    const known = new Set(s.known[p.path] ?? [])
    // The first check of a project only learns what is there: the review already showed it.
    const first = !(p.path in s.known)
    const added = first ? [] : found.filter((f) => !known.has(findingKey(f)))
    s.known[p.path] = keys
    if (added.length) {
      const a: WatchAlert = { at: new Date().toISOString(), kind: 'packages', project: p.title, session: p.session, count: added.length, titles: added.slice(0, 5).map((f) => f.title) }
      fresh.push(a)
      notify(`${p.title}: ${added.length} new package ${added.length === 1 ? 'flaw' : 'flaws'}`, added.slice(0, 2).map((f) => f.title).join('; '))
    }
  }
  s.lastPackages = new Date().toISOString()
  s.alerts = [...fresh, ...s.alerts].slice(0, 50)
  writeWatch(s)
  log('info', `Package watch: ${watchedProjects(sessions).length} projects checked, ${fresh.length} with new flaws`)
  return fresh
}

/** Sessions MacSec started for the weekly re-test, with the session they repeat. */
const autoRuns = new Map<string, string>()
export const isAutoRun = (id: string): boolean => autoRuns.has(id)

/** Re-runs the newest code review of each watched project. */
export async function weeklyRetest(sessions: SessionInfo[], rerun: (id: string) => Promise<SessionInfo>): Promise<number> {
  const s = readWatch()
  let n = 0
  for (const p of watchedProjects(sessions)) {
    // Only projects on this Mac: a kept download is a copy that does not change.
    if (p.path.startsWith(dirs.sessions())) continue
    try {
      const info = await rerun(p.session)
      autoRuns.set(info.id, p.session)
      n++
    } catch (e) {
      log('warn', `Weekly re-test of ${p.title}: ${(e as Error).message}`)
    }
  }
  s.lastRetest = new Date().toISOString()
  writeWatch(s)
  return n
}

/** When a weekly re-test finishes: an alert only for serious problems that are new. */
export function autoRunFinished(info: SessionInfo, findingsOf: (id: string) => Finding[], notify: (title: string, body: string) => void): void {
  const prev = autoRuns.get(info.id)
  if (!prev) return
  autoRuns.delete(info.id)
  if (info.status !== 'done') return
  const added = newSerious(findingsOf(prev), findingsOf(info.id))
  if (!added.length) return
  const s = readWatch()
  s.alerts = [{ at: new Date().toISOString(), kind: 'retest' as const, project: info.title, session: info.id, count: added.length, titles: added.slice(0, 5).map((f) => f.title) }, ...s.alerts].slice(0, 50)
  writeWatch(s)
  notify(`${info.title}: ${added.length} new serious ${added.length === 1 ? 'problem' : 'problems'}`, added.slice(0, 2).map((f) => f.title).join('; '))
}

/** Whether a check is due. */
export const due = (last: string | undefined, every: number, now = Date.now()): boolean => !last || now - Date.parse(last) >= every
export const EVERY = { packages: DAY, retest: 7 * DAY }

/** Checks once an hour whether a watch is due, and runs it. */
export function startWatch(o: { sessions: () => SessionInfo[]; rerun: (id: string) => Promise<SessionInfo>; notify: (title: string, body: string) => void; busy: () => boolean }): void {
  let running = false
  const tick = async (): Promise<void> => {
    if (running || o.busy()) return
    running = true
    try {
      const s = readWatch()
      if (s.packages && due(s.lastPackages, EVERY.packages)) await checkPackages(o.sessions(), o.notify)
      if (s.retest && due(s.lastRetest, EVERY.retest)) await weeklyRetest(o.sessions(), o.rerun)
    } catch (e) {
      log('warn', `Keeping watch: ${(e as Error).message}`)
    } finally {
      running = false
    }
  }
  setTimeout(() => void tick(), 90_000)
  setInterval(() => void tick(), 60 * 60_000)
}
