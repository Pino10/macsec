import { createReadStream, createWriteStream, existsSync, mkdirSync, renameSync, rmSync } from 'fs'
import { createHash } from 'crypto'
import { dirname } from 'path'
import { execFile } from 'child_process'
import { Readable } from 'stream'
import { pipeline } from 'stream/promises'

/** Some download servers block anonymous clients; identify the app honestly. */
export const USER_AGENT = 'MacSec (+https://github.com/Pino10/macsec)'

export type ProgressFn = (percent: number | null, note?: string) => void

/**
 * Downloads a URL to a file, following redirects, reporting progress.
 * Writes to a temporary file first so a cancelled download never leaves a corrupt file.
 */
export async function downloadFile(
  url: string,
  dest: string,
  onProgress?: ProgressFn
): Promise<void> {
  mkdirSync(dirname(dest), { recursive: true })
  const res = await fetch(url, { headers: { 'User-Agent': USER_AGENT }, redirect: 'follow' })
  if (!res.ok || !res.body) throw new Error(`Download failed (${res.status}) for ${url}`)

  const total = Number(res.headers.get('content-length')) || 0
  let received = 0
  const tmp = `${dest}.part`

  const source = Readable.fromWeb(res.body as never)
  source.on('data', (chunk: Buffer) => {
    received += chunk.length
    onProgress?.(total ? Math.min(99, Math.round((received / total) * 100)) : null)
  })

  try {
    await pipeline(source, createWriteStream(tmp))
    renameSync(tmp, dest)
  } catch (err) {
    rmSync(tmp, { force: true })
    throw err
  }
  onProgress?.(100)
}

function run(cmd: string, args: string[], cwd?: string): Promise<void> {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { cwd, maxBuffer: 1024 * 1024 * 32 }, (err, _out, stderr) => {
      if (err) reject(new Error(`${cmd} failed: ${stderr || err.message}`))
      else resolve()
    })
  })
}

/** Extracts .tar.gz / .tgz / .zip using the system tools that ship with macOS. */
export async function extract(archive: string, destDir: string): Promise<void> {
  mkdirSync(destDir, { recursive: true })
  if (archive.endsWith('.zip')) await run('unzip', ['-q', '-o', archive, '-d', destDir])
  else await run('tar', ['-xf', archive, '-C', destDir])
}

/** Cheap check that a URL exists, used to probe for versions we cannot list. */
export async function urlExists(url: string): Promise<boolean> {
  try {
    const res = await fetch(url, { headers: { Range: 'bytes=0-0', 'User-Agent': USER_AGENT }, redirect: 'follow' })
    const ok = res.status === 200 || res.status === 206
    await res.body?.cancel()
    return ok && !(res.headers.get('content-type') ?? '').includes('text/html')
  } catch {
    return false
  }
}

export function sha256File(path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256')
    createReadStream(path)
      .on('data', (c) => hash.update(c))
      .on('error', reject)
      .on('end', () => resolve(hash.digest('hex')))
  })
}

/** Reads the first SHA-256 hex digest from a checksum file's text. */
export function parseSha256(text: string): string | null {
  const m = /\b([a-f0-9]{64})\b/i.exec(text)
  return m ? m[1].toLowerCase() : null
}

/**
 * Checks a download against the checksum its publisher serves next to it.
 * Deletes the file and throws when they differ, so a tampered download is never used.
 */
export async function verifySha256(file: string, checksumUrl: string): Promise<void> {
  const res = await fetch(checksumUrl, { redirect: 'follow' })
  if (!res.ok) throw new Error(`Could not fetch the checksum for ${file} (${res.status}).`)
  const expected = parseSha256(await res.text())
  if (!expected) throw new Error('The published checksum could not be read.')
  const actual = await sha256File(file)
  if (actual !== expected) {
    rmSync(file, { force: true })
    throw new Error('The download did not match its published checksum and was deleted.')
  }
}

export function makeExecutable(path: string): Promise<void> {
  return run('chmod', ['+x', path])
}

export function removeQuarantine(path: string): Promise<void> {
  // Binaries downloaded by the app are not quarantined, but this keeps archives from elsewhere safe.
  return run('xattr', ['-dr', 'com.apple.quarantine', path]).catch(() => undefined)
}

export function fileExists(path: string): boolean {
  return existsSync(path)
}
