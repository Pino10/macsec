/**
 * Baselines: the findings a team has already seen and accepted, committed with the code, so a CI
 * run fails only on what is new. This module holds only the comparison, so it is easy to test.
 */
import { existsSync, readFileSync, writeFileSync } from 'fs'
import type { Finding, Severity } from '../shared/types'

export interface BaselineEntry {
  key: string
  title: string
  checkId?: string
  severity: Severity
}

export interface BaselineFile {
  version: 1
  tool: 'MacSec'
  target: string
  createdAt: string
  findings: BaselineEntry[]
}

const ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical']

/** A finding's identity across scans: the check that made it, and where it is. */
export const findingKey = (f: Finding): string => `${f.checkId ?? f.title}|${f.file ?? f.url ?? ''}`

export function baselineOf(findings: Finding[], target: string, now = new Date()): BaselineFile {
  const open = findings.filter((f) => f.verdict !== 'false-positive' && !f.triage && f.severity !== 'info')
  return {
    version: 1,
    tool: 'MacSec',
    target,
    createdAt: now.toISOString(),
    findings: open.map((f) => ({ key: findingKey(f), title: f.title.slice(0, 200), ...(f.checkId ? { checkId: f.checkId } : {}), severity: f.severity }))
  }
}

/** The findings that are not in the baseline: what a CI run may fail on. */
export function newFindings(findings: Finding[], baseline: BaselineFile | null): Finding[] {
  if (!baseline) return findings.filter((f) => f.verdict !== 'false-positive' && !f.triage && f.severity !== 'info')
  const known = new Set(baseline.findings.map((b) => b.key))
  return findings.filter((f) => f.verdict !== 'false-positive' && !f.triage && f.severity !== 'info' && !known.has(findingKey(f)))
}

/** The worst severity in a list, or null when there is none. */
export function worstOf(findings: Finding[]): Severity | null {
  let worst: Severity | null = null
  for (const f of findings) if (!worst || ORDER.indexOf(f.severity) > ORDER.indexOf(worst)) worst = f.severity
  return worst
}

/** 1 when a new finding reaches the threshold, 0 otherwise. */
export function exitCodeFor(findings: Finding[], failOn: Severity | 'none'): 0 | 1 {
  const open = findings.filter((f) => f.verdict !== 'false-positive' && !f.triage)
  if (failOn === 'none' || !open.length) return 0
  const worst = worstOf(open)
  return worst && ORDER.indexOf(worst) >= ORDER.indexOf(failOn) ? 1 : 0
}

export function readBaseline(path: string): BaselineFile | null {
  try {
    if (!existsSync(path)) return null
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as BaselineFile
    if (parsed?.version !== 1 || !Array.isArray(parsed.findings)) return null
    return parsed
  } catch {
    return null
  }
}

export function writeBaseline(path: string, b: BaselineFile): void {
  writeFileSync(path, `${JSON.stringify(b, null, 2)}\n`)
}
