import { EventEmitter } from 'events'
/**
 * The engine every test runs on: starts tools, tracks them so a session can be stopped, and
 * records each step of a session as it happens.
 */
import { spawn, type ChildProcess } from 'child_process'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs'
import { join } from 'path'
import type { Finding, SessionInfo, SessionStep } from '../shared/types'
import { countBySeverity, mergeFindings } from './scanners/parse'
import { readSession, saveFindings, saveSession, sessionDir } from './sessions'
import { toolEnv, toolPath } from './toolbox'
import { log, redact } from './logs'

export interface Op {
  children: Set<ChildProcess>
  cancelled: boolean
}
const ops = new Map<string, Op>()

export function beginOp(id: string): Op {
  const op: Op = { children: new Set(), cancelled: false }
  ops.set(id, op)
  return op
}
export const endOp = (id: string): void => void ops.delete(id)
export function cancelOp(id: string): void {
  const op = ops.get(id)
  if (!op) return
  op.cancelled = true
  for (const c of op.children) c.kill('SIGTERM')
}
export const isRunning = (id: string): boolean => ops.has(id)

export interface ToolRun {
  bin: string
  args: string[]
  cwd?: string
  timeoutMs: number
  /** Where the tool writes its report; stdout otherwise. */
  output?: string
  /** A name for the raw files kept in the session. */
  name: string
  env?: Record<string, string>
  /** An absolute path, for apps outside the toolbox (ZAP). */
  absolute?: boolean
}

/** Runs a scanner and returns its report. Raw output and errors are kept in the session's raw folder. */
/** Pulls a percentage out of a tool's progress output (Nuclei's -stats, Semgrep, Trivy and others). */
export function percentOf(line: string): number | null {
  const m = /"percent"\s*:\s*"?(\d{1,3})/.exec(line) ?? /\b(\d{1,3})%/.exec(line) ?? /\[(\d+)\/(\d+)\]/.exec(line)
  if (!m) return null
  const v = m[2] ? Math.round((Number(m[1]) / Math.max(1, Number(m[2]))) * 100) : Number(m[1])
  return v >= 0 && v <= 100 ? v : null
}

const n = (v: unknown): string => Number(v).toLocaleString('en-GB')

/** Turns a tool's status line into words: Nuclei and naabu print their progress as JSON. */
export function friendly(line: string): string {
  if (!line.startsWith('{')) return line.replace(/^\[(INF|WRN|ERR)\]\s*/, '')
  try {
    const j = JSON.parse(line) as Record<string, string | number>
    if (j.percent !== undefined) {
      const parts = [`${j.percent}% done`, j.templates && `${n(j.templates)} checks`, j.requests && `${n(j.requests)} requests sent`, j.matched !== undefined && `${n(j.matched)} found so far`, j.errors && Number(j.errors) > 0 && `${n(j.errors)} timeouts`]
      return parts.filter(Boolean).join(', ')
    }
    if (j.port && (j.ip || j.host)) return `Open: ${j.host || j.ip}:${j.port}`
    if (j.url || j.matched_at) return `Found: ${j['template-id'] ?? ''} ${j.matched_at ?? j.url}`.trim()
  } catch {
    // Not JSON after all.
  }
  return line.slice(0, 160)
}

/** Tells the app (webhooks, notifications) when a session ends. */
export const finishEvents = new EventEmitter()

export function runTool(run: ToolRun, op: Op, rawDir: string, onLine?: (l: string) => void): Promise<string> {
  return new Promise((resolve, reject) => {
    const env = toolEnv(run.env)
    mkdirSync(env.TMPDIR as string, { recursive: true })
    const child = spawn(run.absolute ? run.bin : toolPath(run.bin), run.args, { cwd: run.cwd, env, stdio: ['ignore', 'pipe', 'pipe'] })
    op.children.add(child)
    let out = ''
    let err = ''
    child.stdout.on('data', (d: Buffer) => {
      if (out.length < 100 * 1024 * 1024) out += d.toString()
      // With a report file, stdout is the tool's progress (Nuclei's stats, for example).
      if (onLine && run.output) {
        const last = d.toString().replace(/\x1b\[[0-9;]*m/g, '').trim().split('\n').filter(Boolean).pop()
        if (last) onLine(last.slice(0, 200))
      }
    })
    child.stderr.on('data', (d: Buffer) => {
      err += d.toString()
      if (err.length > 200_000) err = err.slice(-100_000)
      if (onLine) {
        // Strip colour codes; the window shows the latest line as it happens.
        const last = d.toString().replace(/\x1b\[[0-9;]*m/g, '').trim().split('\n').filter(Boolean).pop()
        if (last) onLine(last.slice(0, 200))
      }
    })
    const timer = setTimeout(() => child.kill('SIGTERM'), run.timeoutMs)
    child.on('error', (e) => {
      clearTimeout(timer)
      op.children.delete(child)
      reject(e)
    })
    child.on('exit', (code, signal) => {
      clearTimeout(timer)
      op.children.delete(child)
      writeFileSync(join(rawDir, `${run.name}.log`), err.slice(-60_000))
      if (op.cancelled) return reject(new Error('Stopped.'))
      const report = run.output && existsSync(run.output) ? readFileSync(run.output, 'utf8') : out
      if (!run.output) writeFileSync(join(rawDir, `${run.name}.out`), out)
      // A timeout keeps what the tool found so far.
      if (signal && !report.trim()) return reject(new Error('It took too long and was stopped.'))
      if (!report.trim() && code !== 0) return reject(new Error(err.trim().split('\n').filter(Boolean).slice(-2).join(' ') || `Stopped with code ${code}.`))
      resolve(report)
    })
  })
}

/** One session while it runs: its steps and findings, saved as they change. */
export class SessionRun {
  info: SessionInfo
  findings: Finding[] = []
  readonly raw: string
  constructor(
    id: string,
    readonly op: Op
  ) {
    this.info = readSession(id)
    this.raw = join(sessionDir(id), 'raw')
    mkdirSync(this.raw, { recursive: true })
  }
  get cancelled(): boolean {
    return this.op.cancelled
  }
  step(id: string, label: string, status: SessionStep['status'] = 'waiting'): SessionStep {
    const s: SessionStep = { id, label, status }
    this.info.steps.push(s)
    saveSession(this.info)
    return s
  }
  set(s: SessionStep, patch: Partial<SessionStep>): void {
    Object.assign(s, patch)
    saveSession(this.info)
  }
  add(found: Finding[]): void {
    this.findings = mergeFindings([...this.findings, ...found])
    this.info.counts = countBySeverity(this.findings.filter((f) => f.verdict !== 'false-positive'))
    saveFindings(this.info.id, this.findings)
    saveSession(this.info)
  }
  private lastPush = 0
  /** A tool's latest output line, shown live (saved at most twice a second). */
  line(s: SessionStep, raw: string): void {
    // Tool output can contain keys: it is redacted before it is shown or saved.
    const text = redact(raw)
    const p = percentOf(text)
    s.lastLine = friendly(text)
    if (p !== null) s.progress = p
    log('info', friendly(text), this.info.id, true)
    if (Date.now() - this.lastPush > 500) {
      this.lastPush = Date.now()
      saveSession(this.info)
    }
  }
  /** Runs one step; a failure is recorded and the session carries on. */
  async run(s: SessionStep, fn: (note: (detail: string) => void, line: (text: string) => void) => Promise<Finding[] | void>): Promise<void> {
    if (this.cancelled) return this.set(s, { status: 'skipped' })
    const t = Date.now()
    this.set(s, { status: 'running', startedAt: new Date().toISOString() })
    try {
      const found = (await fn((detail) => this.set(s, { detail }), (text) => this.line(s, text))) ?? []
      this.add(found)
      this.set(s, { status: 'done', progress: 100, lastLine: undefined, ms: Date.now() - t, findings: found.length, detail: s.detail && found.length === 0 ? s.detail : found.length ? `${found.length} found` : s.detail ?? 'Nothing found' })
    } catch (e) {
      this.set(s, { status: this.cancelled ? 'skipped' : 'failed', ms: Date.now() - t, detail: (e as Error).message.slice(0, 300) })
    }
  }
  finish(error?: string): void {
    this.info.status = this.cancelled ? 'cancelled' : error ? 'failed' : 'done'
    if (error) this.info.error = error
    this.info.finishedAt = new Date().toISOString()
    this.info.steps = this.info.steps.map((s) => (s.status === 'running' || s.status === 'waiting' ? { ...s, status: 'skipped' } : s))
    this.info.counts = countBySeverity(this.findings.filter((f) => f.verdict !== 'false-positive'))
    saveFindings(this.info.id, this.findings)
    saveSession(this.info)
    finishEvents.emit('finished', this.info)
  }
}
