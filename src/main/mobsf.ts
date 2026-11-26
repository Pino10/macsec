/**
 * Full MobSF, local only, opened in its own MacSec window. MacSec does not reimplement MobSF. It can use:
 *   1. a MobSF that is already running on this Mac (started by you, on 127.0.0.1 port 8000 or 8765): MacSec just opens it
 *      and never stops it;
 *   2. your own MobSF folder (for example ~/Mobile-Security-Framework-MobSF, set up with its setup.sh): MacSec starts
 *      its own gunicorn on 127.0.0.1:8765 with an argument array and stops it again;
 *   3. the official Docker image, as a disposable container on 127.0.0.1:8765 with a named volume for reports.
 * Everything listens on 127.0.0.1 only. MobSF keeps its own data where it always does (its folder or ~/.MobSF).
 */
import { execFile, spawn, type ChildProcess } from 'child_process'
import { existsSync, realpathSync, statSync } from 'fs'
import { homedir } from 'os'
import { isAbsolute, join, resolve } from 'path'
import type { MobsfStatus } from '../shared/types'
import { dockerBin, dockerEnv } from './containerruntime'
import { dirs } from './paths'
import { getSettings, setSettings } from './settings'

const CONTAINER = 'macsec-mobsf'
const IMAGE = 'opensecurity/mobile-security-framework-mobsf:latest'
const VOLUME = 'macsec-mobsf-data'
const PORT = 8765
const OUTSIDE_PORTS = [8765, 8000]
const USER = 'mobsf'
const PASS = 'mobsf'
const urlOf = (port: number): string => `http://127.0.0.1:${port}`

const run = (args: string[], timeout = 60_000): Promise<{ ok: boolean; out: string; err: string }> =>
  new Promise((done) => {
    execFile(dockerBin(), args, { timeout, maxBuffer: 8 * 1024 * 1024, env: dockerEnv() }, (e, stdout, stderr) => done({ ok: !e, out: String(stdout ?? ''), err: String(stderr || e?.message || '') }))
  })

/** True only when the answer really is MobSF, so another program on the same port is never taken for it. */
export async function isMobsf(port: number, fetchImpl: typeof fetch = fetch): Promise<boolean> {
  try {
    const r = await fetchImpl(urlOf(port), { signal: AbortSignal.timeout(2500), redirect: 'follow' })
    if (r.status >= 500) return false
    return /MobSF|Mobile Security Framework/i.test((await r.text()).slice(0, 200_000))
  } catch {
    return false
  }
}

/** A MobSF folder is usable when it has its code and its own Python environment (made by its setup.sh). */
export function folderProblem(dir: string): string | null {
  if (!dir || !isAbsolute(dir) || resolve(dir) !== dir) return 'Choose the MobSF folder itself (the one with manage.py).'
  try {
    if (!statSync(dir).isDirectory()) return 'That is not a folder.'
  } catch {
    return 'That folder does not exist.'
  }
  if (!existsSync(join(dir, 'manage.py')) || !existsSync(join(dir, 'mobsf', 'MobSF', 'wsgi.py'))) return 'That folder is not a MobSF checkout (manage.py and mobsf/MobSF are missing).'
  if (!existsSync(join(dir, 'scripts', 'gunicorn_config.py'))) return 'This MobSF is too old or incomplete (scripts/gunicorn_config.py is missing).'
  if (!existsSync(join(dir, 'venv', 'bin', 'gunicorn'))) return 'MobSF is not set up in that folder yet. Open Terminal in it and run ./setup.sh once, then try again.'
  return null
}

export function candidateFolders(saved = getSettings().mobsf?.path, home = homedir()): string[] {
  return [...new Set([saved, join(home, 'Mobile-Security-Framework-MobSF'), join(home, 'MobSF'), join(dirs.root(), 'tools', 'MobSF')].filter((x): x is string => !!x))]
}

export function findFolder(candidates = candidateFolders()): string {
  for (const c of candidates) {
    let real = c
    try {
      real = realpathSync(c)
    } catch {
      continue
    }
    if (!folderProblem(real)) return real
  }
  return ''
}

export function gunicornArgs(): string[] {
  return ['--config', 'scripts/gunicorn_config.py', '-b', `127.0.0.1:${PORT}`, 'mobsf.MobSF.wsgi:application', '--workers=1', '--threads=10', '--timeout=3600', '--log-level=critical', '--log-file=-', '--access-logfile=-', '--error-logfile=-', '--capture-output']
}

let child: ChildProcess | null = null
let childTail = ''

const dockerState = async (): Promise<{ exists: boolean; running: boolean }> => {
  const r = await run(['inspect', '-f', '{{.State.Running}}', CONTAINER], 10_000)
  return r.ok ? { exists: true, running: r.out.trim() === 'true' } : { exists: false, running: false }
}

export async function mobsfStatus(): Promise<MobsfStatus> {
  const folder = findFolder()
  const base = { container: CONTAINER, image: IMAGE, username: USER, password: PASS, folder }
  if (child && child.exitCode === null && (await isMobsf(PORT))) return { ...base, mode: 'folder', installed: true, running: true, url: urlOf(PORT), detail: 'Running from your MobSF folder.' }
  const d = await dockerState()
  if (d.running && (await isMobsf(PORT))) return { ...base, mode: 'docker', installed: true, running: true, url: urlOf(PORT), detail: 'Running in Docker.' }
  for (const p of OUTSIDE_PORTS) if (!(child && p === PORT) && (await isMobsf(p))) return { ...base, mode: 'outside', installed: true, running: true, url: urlOf(p), detail: 'A MobSF you started yourself is already running. MacSec will open it but never stops it.' }
  const detail = folder ? `Ready to start from ${folder}.` : d.exists ? 'The MobSF container is stopped.' : 'No MobSF found yet. Choose your MobSF folder, or use Docker.'
  return { ...base, mode: 'none', installed: !!folder || d.exists, running: false, url: urlOf(PORT), detail }
}

const waitFor = async (port: number, alive: () => boolean): Promise<boolean> => {
  for (let i = 0; i < 180; i++) {
    if (!alive()) return false
    if (await isMobsf(port)) return true
    await new Promise((r) => setTimeout(r, 1000))
  }
  return false
}

async function startFolder(folder: string): Promise<void> {
  if (await isMobsf(PORT)) throw new Error('Something named MobSF already answers on port 8765. Stop it first, or use it as it is.')
  child = spawn(join(folder, 'venv', 'bin', 'gunicorn'), gunicornArgs(), {
    cwd: folder,
    // Same login as the container, so the page says one thing. OBJC_... stops macOS killing gunicorn's forked workers.
    env: { ...process.env, MOBSF_USERNAME: USER, MOBSF_PASSWORD: PASS, OBJC_DISABLE_INITIALIZE_FORK_SAFETY: 'YES' },
    stdio: ['ignore', 'ignore', 'pipe']
  })
  childTail = ''
  child.stderr?.on('data', (d: Buffer) => {
    childTail = (childTail + d.toString()).slice(-800)
  })
  const mine = child
  const up = await waitFor(PORT, () => mine.exitCode === null && mine.signalCode === null)
  if (!up) {
    const why = childTail.trim().split('\n').slice(-2).join(' ') || 'it did not answer in time'
    mine.kill('SIGTERM')
    child = null
    throw new Error(`MobSF did not start from your folder: ${why}`)
  }
}

async function startDocker(): Promise<void> {
  const info = await run(['info', '--format', '{{.ServerVersion}}'], 15_000)
  if (!info.ok) throw new Error('Docker is not running on this Mac. Choose your own MobSF folder instead, or start Docker or Colima (Tools, Container runtime).')
  const i = await dockerState()
  // The image is pulled only when it is missing, so the first start can take a while.
  if (!(await run(['image', 'inspect', IMAGE], 10_000)).ok) {
    const pull = await run(['pull', IMAGE], 15 * 60_000)
    if (!pull.ok) throw new Error(`MobSF's image could not be pulled: ${pull.err.trim().split('\n').slice(-2).join(' ')}`)
  }
  if (i.exists) await run(['rm', '-f', CONTAINER], 30_000)
  // No restart policy: the container is disposable and must not come back by itself after a reboot.
  const start = await run(['run', '-d', '--name', CONTAINER, '-p', `127.0.0.1:${PORT}:8000`, '-e', `MOBSF_USERNAME=${USER}`, '-e', `MOBSF_PASSWORD=${PASS}`, '-v', `${VOLUME}:/home/mobsf/.MobSF`, IMAGE], 2 * 60_000)
  if (!start.ok) throw new Error(`MobSF could not start: ${start.err.trim().split('\n').slice(-2).join(' ')}`)
  if (!(await waitFor(PORT, () => true))) throw new Error('MobSF started but did not answer on 127.0.0.1:8765 yet. Open it in a moment; the first start can take longer.')
}

export async function startMobsf(): Promise<MobsfStatus> {
  const now = await mobsfStatus()
  if (now.running) return now
  const folder = findFolder()
  if (folder) await startFolder(folder)
  else await startDocker()
  return mobsfStatus()
}

export async function stopMobsf(): Promise<MobsfStatus> {
  const now = await mobsfStatus()
  if (now.mode === 'outside') throw new Error('This MobSF was started outside MacSec, so MacSec will not stop it. Stop it where you started it.')
  if (now.mode === 'folder' && child) {
    const c = child
    child = null
    c.kill('SIGTERM')
    await new Promise<void>((r) => (c.exitCode !== null ? r() : (c.once('exit', () => r()), setTimeout(r, 8000))))
    if (c.exitCode === null) c.kill('SIGKILL')
  } else if (now.mode === 'docker') await run(['stop', CONTAINER], 60_000)
  return mobsfStatus()
}

export function stopMobsfQuietly(): void {
  if (child && child.exitCode === null) child.kill('SIGTERM')
  child = null
}

export async function removeMobsf(confirmed: boolean, removeReports = false, removeImage = false): Promise<MobsfStatus> {
  if (!confirmed) throw new Error('Confirm that you want to remove the MobSF container.')
  await run(['rm', '-f', CONTAINER], 60_000)
  if (removeReports) await run(['volume', 'rm', VOLUME], 30_000)
  if (removeImage) await run(['rmi', IMAGE], 2 * 60_000)
  return mobsfStatus()
}

/** Remembers the person's own MobSF folder, after checking it really is one. Nothing is written inside it. */
export async function chooseMobsfFolder(path: unknown): Promise<MobsfStatus> {
  if (typeof path !== 'string') throw new Error('Choose the MobSF folder.')
  let real: string
  try {
    real = realpathSync(resolve(path))
  } catch {
    throw new Error('That folder does not exist.')
  }
  const problem = folderProblem(real)
  if (problem) throw new Error(problem)
  setSettings({ mobsf: { path: real } })
  return mobsfStatus()
}
