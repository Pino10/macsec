/**
 * MacSec updates itself: it checks GitHub for a newer release, downloads the DMG for this Mac,
 * checks it against the release's SHA256SUMS.txt and its code signature, swaps it in place of the
 * running copy and restarts. Sessions, tools and settings live in ~/MacSec and are untouched.
 */
import { ownNotes, releasesWithFallback } from './seckit/ghapi'
import { app } from 'electron'
import { execFile } from 'child_process'
import { existsSync, mkdtempSync, renameSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { dirname, join, resolve } from 'path'
import type { ReleaseNote, UpdateInfo, UpdateStatus } from '../shared/types'
import { downloadFile, sha256File, USER_AGENT } from './download'
import { dirs } from './paths'
import { hashFor, newer } from './toolbox'

const REPO = 'Pino10/macsec'

export interface Release {
  tag_name: string
  draft: boolean
  prerelease?: boolean
  body: string | null
  published_at: string
  html_url: string
  assets: { name: string; browser_download_url: string }[]
}

export const dmgArch = (): string => (process.arch === 'arm64' ? 'arm64' : 'x64')

/** The newest release (tags like v1.2.3) newer than `current`, with a DMG for this Mac and checksums. */
export function pickUpdate(releases: Release[], current: string, arch = dmgArch()): { info: UpdateInfo; dmg: string; sums: string } | null {
  let best: Release | null = null
  for (const r of releases) {
    // MacSec's releases up to 0.8.1 were published as pre-releases: they count too.
    if (r.draft || !/^v\d+\.\d+\.\d+$/.test(r.tag_name)) continue
    if (!newer(r.tag_name, current)) continue
    if (!best || newer(r.tag_name, best.tag_name)) best = r
  }
  if (!best) return null
  const version = best.tag_name.slice(1)
  const dmg = best.assets.find((a) => a.name === `MacSec-${version}-${arch}.dmg`)
  const sums = best.assets.find((a) => a.name === 'SHA256SUMS.txt')
  // Without a checksum list the download cannot be verified, so it is not offered.
  if (!dmg || !sums) return null
  return { info: { version, current, notes: ownNotes(best.body), publishedAt: best.published_at, url: best.html_url }, dmg: dmg.browser_download_url, sums: sums.browser_download_url }
}

function run(cmd: string, args: string[]): Promise<string> {
  return new Promise((res, rej) => execFile(cmd, args, { maxBuffer: 8 * 1024 * 1024 }, (err, out, errOut) => (err ? rej(new Error(String(errOut).trim() || err.message)) : res(String(out)))))
}

let pending: { info: UpdateInfo; dmg: string; sums: string } | null = null

let lastReleases: Release[] = []
let checkedAt: number | null = null
let lastError: string | null = null

/** What the Updates page shows: the version you have, what is newer, when it was checked. */
export function updateStatus(): UpdateStatus {
  return { current: app.getVersion(), update: pending?.info ?? null, checkedAt, error: lastError }
}

/** Every MacSec release, newest first, each with its own notes. */
export async function releaseNotes(): Promise<ReleaseNote[]> {
  if (!lastReleases.length) await checkForUpdate().catch(() => undefined)
  return lastReleases
    .filter((r) => !r.draft && /^v\d+\.\d+\.\d+$/.test(r.tag_name))
    .map((r) => ({ version: r.tag_name.slice(1), notes: ownNotes(r.body), publishedAt: r.published_at, url: r.html_url }))
    .sort((a, b) => (newer(`v${a.version}`, `v${b.version}`) ? -1 : 1))
}

export async function checkForUpdate(): Promise<UpdateInfo | null> {
  // Through the shared GitHub client: your sign-in when there is one, answers kept for a while, and
  // GitHub's release feed when its hourly limit is used up.
  try {
    lastReleases = (await releasesWithFallback(REPO, (v) => [`MacSec-${v}-arm64.dmg`, `MacSec-${v}-x64.dmg`, 'SHA256SUMS.txt'])) as Release[]
    lastError = null
  } catch (e) {
    lastError = (e as Error).message
    throw e
  } finally {
    checkedAt = Date.now()
  }
  pending = pickUpdate(lastReleases, app.getVersion())
  return pending?.info ?? null
}

/** The .app bundle this process runs from. */
const currentBundle = (): string => resolve(dirname(app.getPath('exe')), '..', '..')

export async function installUpdate(update: (pct: number | null, label?: string) => void): Promise<void> {
  if (!pending) await checkForUpdate()
  if (!pending) throw new Error('MacSec is up to date.')
  const { info, dmg, sums } = pending
  const bundle = currentBundle()
  if (!bundle.endsWith('.app') || bundle.includes('/AppTranslocation/') || bundle.startsWith('/Volumes/')) throw new Error('Move MacSec to your Applications folder first, then update.')

  const name = `MacSec-${info.version}-${dmgArch()}.dmg`
  const file = join(dirs.downloads(), name)
  await downloadFile(dmg, file, (p) => update(p, `Downloading MacSec ${info.version}`))
  update(null, 'Checking the download')
  const list = await (await fetch(sums, { headers: { 'User-Agent': USER_AGENT } })).text()
  const expected = hashFor(list, name)
  if (!expected || (await sha256File(file)) !== expected) {
    rmSync(file, { force: true })
    throw new Error('The update did not match its published checksum and was deleted.')
  }

  const mount = mkdtempSync(join(tmpdir(), 'macsec-update-'))
  await run('hdiutil', ['attach', '-nobrowse', '-readonly', '-noautoopen', '-mountpoint', mount, file])
  try {
    const fresh = join(mount, 'MacSec.app')
    if (!existsSync(fresh)) throw new Error('The update does not contain MacSec.app.')
    await run('codesign', ['--verify', '--deep', '--strict', fresh])
    const id = (await run('/usr/libexec/PlistBuddy', ['-c', 'Print :CFBundleIdentifier', join(fresh, 'Contents', 'Info.plist')])).trim()
    if (id !== 'dev.macsec.app') throw new Error('The update is not a MacSec build.')
    update(null, 'Installing the update')
    const incoming = `${bundle}.new`
    const previous = `${bundle}.old`
    rmSync(incoming, { recursive: true, force: true })
    rmSync(previous, { recursive: true, force: true })
    await run('ditto', [fresh, incoming])
    // Already verified above: clear the download flag so macOS does not ask again.
    await run('xattr', ['-dr', 'com.apple.quarantine', incoming]).catch(() => '')
    renameSync(bundle, previous)
    try {
      renameSync(incoming, bundle)
    } catch (err) {
      renameSync(previous, bundle)
      throw err
    }
    rmSync(previous, { recursive: true, force: true })
  } finally {
    await run('hdiutil', ['detach', mount, '-quiet']).catch(() => undefined)
    rmSync(file, { force: true })
  }
  update(100, 'Restarting')
  app.relaunch()
  app.quit()
}
