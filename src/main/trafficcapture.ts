/**
 * Watching an app's traffic with mitmproxy (free), on the person's own test phone or emulator.
 *
 * MacSec only starts and stops the listener on this Mac. It never touches the phone: the person sets the
 * phone's proxy and installs the capture certificate (from http://mitm.it on the phone) themselves.
 *   - mitmdump is started with an argument array, on 127.0.0.1 or one of this Mac's own network addresses.
 *   - `block_global` stays on, so only devices on the local network can use it.
 *   - It only listens and writes a HAR file under ~/MacSec; nothing is changed or replayed.
 *   - The HAR can hold tokens and passwords, so it is deleted as soon as it has been read.
 */
import { spawn, type ChildProcess } from 'child_process'
import { existsSync, mkdirSync, readFileSync, rmSync, statSync } from 'fs'
import { createServer } from 'net'
import { networkInterfaces } from 'os'
import { join } from 'path'
import type { SessionInfo, TrafficCaptureInfo } from '../shared/types'
import { beginOp, endOp, SessionRun } from './engine'
import { dirs } from './paths'
import { createSession } from './sessions'
import { toolEnv, toolPath } from './toolbox'
import { analyzeHar } from './traffic'
import { log } from './logs'

const MAX_HAR = 200 * 1024 * 1024

/** This Mac's own IPv4 addresses on the local network (never a public address). */
export function lanAddresses(ifs: ReturnType<typeof networkInterfaces> = networkInterfaces()): string[] {
  const out: string[] = []
  for (const list of Object.values(ifs))
    for (const a of list ?? []) if (a.family === 'IPv4' && !a.internal && /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(a.address)) out.push(a.address)
  return [...new Set(out)]
}

/** A listen address is accepted only if it is the Mac itself or one of its own local network addresses. */
export function validListen(host: unknown, lan: string[] = lanAddresses()): host is string {
  return typeof host === 'string' && (host === '127.0.0.1' || lan.includes(host))
}

export const captureArgs = (host: string, port: number, har: string, confdir: string): string[] => [
  '--listen-host', host,
  '--listen-port', String(port),
  '--set', `hardump=${har}`,
  '--set', `confdir=${confdir}`,
  '--set', 'block_global=true',
  '-q'
]

const freePort = (): Promise<number> =>
  new Promise((resolve, reject) => {
    const s = createServer()
    s.once('error', reject)
    s.listen(0, '127.0.0.1', () => {
      const p = (s.address() as { port: number }).port
      s.close(() => resolve(p))
    })
  })

interface Running {
  proc: ChildProcess
  har: string
  info: TrafficCaptureInfo
  exited: Promise<number | null>
  error: string
}
let current: Running | null = null

export function captureStatus(): TrafficCaptureInfo & { installed: boolean; lan: string[] } {
  return { ...(current?.info ?? { running: false, host: '', port: 0 }), installed: existsSync(toolPath('mitmdump')), lan: lanAddresses() }
}

export async function startCapture(host: unknown): Promise<TrafficCaptureInfo> {
  if (current) throw new Error('A capture is already running. Stop it first.')
  if (!validListen(host)) throw new Error('Choose this Mac (127.0.0.1) or one of its network addresses.')
  if (!existsSync(toolPath('mitmdump'))) throw new Error('Install mitmproxy first (the button above).')
  const port = await freePort()
  const dir = join(dirs.root(), 'captures')
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  const har = join(dir, `capture-${Date.now()}.har`)
  const proc = spawn(toolPath('mitmdump'), captureArgs(host, port, har, join(dirs.config(), 'mitmproxy')), { env: toolEnv(), stdio: ['ignore', 'ignore', 'pipe'] })
  let error = ''
  proc.stderr?.on('data', (d: Buffer) => {
    error = (error + d.toString()).slice(-600)
  })
  const exited = new Promise<number | null>((resolve) => proc.once('exit', (c) => resolve(c)))
  proc.once('error', (e) => {
    error = e.message
  })
  const info: TrafficCaptureInfo = { running: true, host, port }
  current = { proc, har, info, exited, error }
  // A bad option or a busy port shows up within a moment: report it instead of pretending to listen.
  const early = await Promise.race([exited.then((c) => c ?? -1), new Promise<null>((r) => setTimeout(() => r(null), 2500))])
  if (early !== null) {
    const why = error.trim().split('\n').pop() || 'it stopped right away'
    current = null
    throw new Error(`mitmproxy did not start: ${why}`)
  }
  current.error = error
  log('info', `Traffic capture listening on ${host}:${port}`)
  return info
}

/** Stops the listener, reads the HAR it wrote, and turns it into a session. */
export async function stopCapture(title: string): Promise<SessionInfo> {
  const c = current
  if (!c) throw new Error('No capture is running.')
  current = null
  c.proc.kill('SIGTERM')
  const done = await Promise.race([c.exited.then(() => true), new Promise<boolean>((r) => setTimeout(() => r(false), 15_000))])
  if (!done) c.proc.kill('SIGKILL')
  try {
    // mitmdump writes the file when it shuts down. No file after a clean stop means nothing passed through.
    const text = existsSync(c.har) && statSync(c.har).size <= MAX_HAR ? readFileSync(c.har, 'utf8') : '{"log":{"entries":[]}}'
    return await sessionFromHar(text, title)
  } finally {
    rmSync(c.har, { force: true })
  }
}

export function stopCaptureQuietly(): void {
  if (!current) return
  current.proc.kill('SIGTERM')
  rmSync(current.har, { force: true })
  current = null
}

/** Reads a HAR (from the capture or one the person picked) into a mobile session. The file itself is not copied. */
export async function sessionFromHar(text: string, title: string): Promise<SessionInfo> {
  const result = analyzeHar(text)
  const info = createSession('mobile-scan', (title || 'App traffic').slice(0, 80), 'traffic capture')
  const op = beginOp(info.id)
  const run = new SessionRun(info.id, op)
  try {
    const st = run.step('traffic', 'Read what the app sent on the network', 'running')
    run.add(result.findings)
    run.set(st, { status: 'done', findings: result.findings.length, detail: `${result.requests} requests to ${result.hosts.length} servers` })
    run.finish()
  } catch (e) {
    run.finish((e as Error).message)
  } finally {
    endOp(info.id)
  }
  return run.info
}
