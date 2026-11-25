/**
 * Full MobSF, run locally as a Docker container and opened in its own MacSec window. It is the
 * official image; MacSec does not reimplement the UI. Local only, fixed port, disposable container,
 * named volume for reports.
 */
import { execFile } from 'child_process'
import type { MobsfStatus } from '../shared/types'
import { dockerBin, dockerEnv } from './containerruntime'

const CONTAINER = 'macsec-mobsf'
const IMAGE = 'opensecurity/mobile-security-framework-mobsf:latest'
const VOLUME = 'macsec-mobsf-data'
const PORT = 8765
const URL = `http://127.0.0.1:${PORT}`
const USER = 'mobsf'
const PASS = 'mobsf'

const run = (args: string[], timeout = 60_000): Promise<{ ok: boolean; out: string; err: string }> =>
  new Promise((resolve) => {
    execFile(dockerBin(), args, { timeout, maxBuffer: 8 * 1024 * 1024, env: dockerEnv() }, (e, stdout, stderr) => resolve({ ok: !e, out: String(stdout ?? ''), err: String(stderr ?? e?.message ?? '') }))
  })

const inspect = async (): Promise<{ exists: boolean; running: boolean }> => {
  const r = await run(['inspect', '-f', '{{.State.Running}}', CONTAINER], 10_000)
  if (!r.ok) return { exists: false, running: false }
  return { exists: true, running: r.out.trim() === 'true' }
}

const waitForHttp = async (): Promise<boolean> => {
  for (let i = 0; i < 120; i++) {
    try {
      const r = await fetch(URL, { signal: AbortSignal.timeout(2500), redirect: 'manual' })
      if (r.status < 500) return true
    } catch {
      // Not up yet.
    }
    await new Promise((r) => setTimeout(r, 1000))
  }
  return false
}

export async function mobsfStatus(): Promise<MobsfStatus> {
  const i = await inspect()
  return { installed: i.exists, running: i.running, url: URL, container: CONTAINER, image: IMAGE, username: USER, password: PASS, detail: i.exists ? '' : 'The MobSF container is not created yet.' }
}

export async function startMobsf(): Promise<MobsfStatus> {
  const i = await inspect()
  if (i.running) return mobsfStatus()
  // The image is pulled only when it is missing, so the first start can take a while.
  const hasImage = await run(['image', 'inspect', IMAGE], 10_000)
  if (!hasImage.ok) {
    const pull = await run(['pull', IMAGE], 15 * 60_000)
    if (!pull.ok) throw new Error(`MobSF's image could not be pulled: ${pull.err.trim().split('\n').slice(-2).join(' ')}`)
  }
  if (i.exists) await run(['rm', '-f', CONTAINER], 30_000)
  const start = await run(
    ['run', '-d', '--name', CONTAINER, '--restart', 'unless-stopped', '-p', `127.0.0.1:${PORT}:8000`, '-e', `MOBSF_USERNAME=${USER}`, '-e', `MOBSF_PASSWORD=${PASS}`, '-v', `${VOLUME}:/home/mobsf/.MobSF`, IMAGE],
    2 * 60_000
  )
  if (!start.ok) throw new Error(`MobSF could not start: ${start.err.trim().split('\n').slice(-2).join(' ')}`)
  if (!(await waitForHttp())) throw new Error('MobSF started but did not answer on 127.0.0.1:8765 yet. Open it in a moment; the first start can take longer.')
  return mobsfStatus()
}

export async function stopMobsf(): Promise<MobsfStatus> {
  const i = await inspect()
  if (i.running) await run(['stop', CONTAINER], 60_000)
  return mobsfStatus()
}

export async function removeMobsf(confirmed: boolean, removeReports = false, removeImage = false): Promise<MobsfStatus> {
  if (!confirmed) throw new Error('Confirm that you want to remove the MobSF container.')
  await run(['rm', '-f', CONTAINER], 60_000)
  if (removeReports) await run(['volume', 'rm', VOLUME], 30_000)
  if (removeImage) await run(['rmi', IMAGE], 2 * 60_000)
  return mobsfStatus()
}
