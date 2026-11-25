/**
 * The optional container runtime (Docker + Colima) used by the plugin runner. MacSec can point at
 * an existing install, start/stop Colima and clear its own link. It deletes files only from a
 * directory it manages; an external Homebrew install is left for the person to remove.
 */
import { execFile } from 'child_process'
import { existsSync, rmSync } from 'fs'
import { join, resolve, sep } from 'path'
import type { ContainerStatus } from '../shared/types'
import { dirs } from './paths'
import { getSettings, setSettings } from './settings'

export const dockerEnv = (): NodeJS.ProcessEnv => {
  const c = getSettings().container ?? {}
  return { ...process.env, ...(c.dockerHost ? { DOCKER_HOST: c.dockerHost } : {}), ...(c.home ? { HOME: c.home } : {}), ...(c.colimaHome ? { COLIMA_HOME: c.colimaHome } : {}), ...(c.limaHome ? { LIMA_HOME: c.limaHome } : {}), ...(c.dockerPath ? { MACSEC_DOCKER: c.dockerPath } : {}) }
}
export const dockerBin = (): string => getSettings().container?.dockerPath || process.env.MACSEC_DOCKER || [join(dirs.root(), 'tools', 'bin', 'docker'), '/opt/homebrew/bin/docker', '/usr/local/bin/docker', '/usr/bin/docker'].find((p) => existsSync(p)) || 'docker'
const colima = (): string => {
  const d = dockerBin()
  const besides = d.replace(/\/docker$/, '/colima')
  if (existsSync(besides)) return besides
  return ['/opt/homebrew/bin/colima', '/usr/local/bin/colima'].find((p) => existsSync(p)) || 'colima'
}
const run = (bin: string, args: string[], timeout = 20_000): Promise<{ ok: boolean; out: string; err: string }> =>
  new Promise((resolvePromise) => {
    execFile(bin, args, { timeout, maxBuffer: 4 * 1024 * 1024, env: dockerEnv() }, (e, stdout, stderr) => resolvePromise({ ok: !e, out: String(stdout ?? ''), err: String(stderr ?? e?.message ?? '') }))
  })

export async function containerStatus(): Promise<ContainerStatus> {
  const c = getSettings().container ?? {}
  const info = await run(dockerBin(), ['info', '--format', '{{.ServerVersion}}'], 15_000)
  const cl = await run(colima(), ['status'], 10_000)
  return {
    dockerPath: dockerBin(),
    dockerHost: c.dockerHost ?? '',
    home: c.home ?? '',
    colimaPath: colima(),
    colima: cl.ok,
    running: info.ok,
    version: info.ok ? info.out.trim() : '',
    managed: c.managedDir ?? '',
    detail: info.ok ? '' : info.err.trim().split('\n').pop() ?? ''
  }
}

export async function configureContainer(input: { dockerPath?: string; dockerHost?: string; home?: string; colimaHome?: string; limaHome?: string; managedDir?: string }): Promise<ContainerStatus> {
  const dockerPath = (input.dockerPath ?? '').trim()
  if (dockerPath && (!dockerPath.startsWith('/') || !existsSync(dockerPath))) throw new Error('The Docker binary must be an absolute path that exists.')
  const dockerHost = (input.dockerHost ?? '').trim()
  if (dockerHost && !/^unix:\/\/|^tcp:\/\//.test(dockerHost)) throw new Error('The Docker host must start with unix:// or tcp://.')
  const current = getSettings().container ?? {}
  setSettings({ container: { ...current, dockerPath: dockerPath || undefined, dockerHost: dockerHost || undefined, home: (input.home ?? '').trim() || undefined, colimaHome: (input.colimaHome ?? '').trim() || undefined, limaHome: (input.limaHome ?? '').trim() || undefined, managedDir: (input.managedDir ?? '').trim() || undefined } })
  return containerStatus()
}

export async function startContainer(): Promise<ContainerStatus> {
  const r = await run(colima(), ['start'], 5 * 60_000)
  if (!r.ok) throw new Error(`Colima did not start: ${r.err.trim().split('\n').slice(-2).join(' ')}`)
  return containerStatus()
}

export async function stopContainer(): Promise<ContainerStatus> {
  const r = await run(colima(), ['stop'], 2 * 60_000)
  if (!r.ok) throw new Error(`Colima did not stop: ${r.err.trim().split('\n').slice(-2).join(' ')}`)
  return containerStatus()
}

export async function uninstallContainer(confirmed: boolean): Promise<{ removed: boolean; note: string }> {
  if (!confirmed) throw new Error('Confirm that you want to remove the container runtime link.')
  await run(colima(), ['stop'], 2 * 60_000).catch(() => undefined)
  const c = getSettings().container ?? {}
  const managed = c.managedDir ? resolve(c.managedDir) : ''
  const root = resolve(dirs.root()) + sep
  // Delete a folder MacSec manages, or one that is clearly a runtime bundle the person pointed at
  // and confirmed. Never delete /opt/homebrew, /usr/local or an arbitrary folder without markers.
  const looksLikeRuntime = !!managed && existsSync(join(managed, 'bin', 'docker')) && (existsSync(join(managed, 'bin', 'colima')) || existsSync(join(managed, 'colima')))
  let removed = false
  if (managed && (managed.startsWith(root) || looksLikeRuntime)) {
    rmSync(managed, { recursive: true, force: true })
    removed = true
  }
  setSettings({ container: undefined })
  return { removed, note: removed ? 'The managed runtime folder was deleted.' : 'The runtime was external, so its files were left in place; only the MacSec link was cleared.' }
}
