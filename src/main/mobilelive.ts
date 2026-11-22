/**
 * Live phone test for Android apps. It runs the app on an emulator or a phone you own and watches
 * what it does, so a finding is something that was seen, not guessed:
 *
 *   Network    hosts the app talks to at start-up, and any request sent over plain HTTP
 *   Pinning    whether the app checks the server's certificate against a pinned one (Frida, observe only)
 *   Root       whether the app looks for a rooted phone (Frida, observe only)
 *   Logs       passwords and tokens the app writes to the phone's log
 *   Storage    passwords and tokens the app keeps in its own files in plain text
 *
 * Rules (see CLAUDE.md): needs the person's confirmation for that device; only the app under test
 * is touched; Frida only watches (it never changes what the app does); no taps or typing are sent
 * to the app, so nothing is bought, posted or deleted; secret values are never saved, only their
 * kind, file and name; an app MacSec installed is removed again afterwards.
 */
import { execFile } from 'child_process'
import { createHash } from 'crypto'
import { existsSync, mkdirSync, renameSync, rmSync, writeFileSync } from 'fs'
import { homedir } from 'os'
import { join } from 'path'
import type { AndroidDevice as Device, Finding, LiveSetupInfo as LiveSetup } from '../shared/types'
import type { Proof } from './seckit/confirm'
import { fid } from './scanners/parse'
import { downloadFile, sha256File, USER_AGENT } from './download'
import { dirs } from './paths'
import { toolEnv } from './toolbox'

// ---------------------------------------------------------------- Running commands

export type Exec = (bin: string, args: string[], o?: { timeout?: number; input?: string }) => Promise<Buffer>

/** Runs a program with an argument list (never through a shell). A failure keeps what it printed. */
export const realExec: Exec = (bin, args, o = {}) =>
  new Promise((resolve, reject) => {
    const p = execFile(bin, args, { timeout: o.timeout ?? 30_000, maxBuffer: 30 * 1024 * 1024, encoding: 'buffer', env: toolEnv() }, (err, stdout) => (err ? reject(Object.assign(err, { stdout })) : resolve(stdout)))
    if (o.input !== undefined) p.stdin?.end(o.input)
  })

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))

// ---------------------------------------------------------------- Checking what is given

export const validSerial = (s: unknown): s is string => typeof s === 'string' && /^[A-Za-z0-9._:-]{1,64}$/.test(s)
export const validPackage = (p: unknown): p is string => typeof p === 'string' && p.length <= 150 && /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/.test(p)
export const validAvd = (s: unknown): s is string => typeof s === 'string' && /^[A-Za-z0-9._-]{1,64}$/.test(s)

/** `adb devices -l` */
export function parseDevices(text: string): Device[] {
  const out: Device[] = []
  for (const line of text.split('\n').slice(1)) {
    const m = /^(\S+)\s+(device|offline|unauthorized|authorizing|no permissions)\b(.*)$/.exec(line.trim())
    if (!m || !validSerial(m[1])) continue
    out.push({ serial: m[1], state: m[2], model: /model:(\S+)/.exec(m[3])?.[1]?.replace(/_/g, ' ') ?? '', kind: m[1].startsWith('emulator-') ? 'emulator' : 'phone' })
  }
  return out
}

/** The name Frida uses for a phone's processor, from Android's ABI name. */
export function fridaArch(abi: string): 'arm64' | 'arm' | 'x86' | 'x86_64' | null {
  const a = abi.trim()
  return a === 'arm64-v8a' ? 'arm64' : a === 'armeabi-v7a' || a === 'armeabi' ? 'arm' : a === 'x86_64' ? 'x86_64' : a === 'x86' ? 'x86' : null
}

export function packageFromManifest(xml: string): string | null {
  const p = /<manifest\b[^>]*?\spackage\s*=\s*["']([^"']+)["']/i.exec(xml)?.[1]
  return validPackage(p) ? p : null
}

export interface ReleaseAsset {
  name: string
  browser_download_url: string
  digest?: string | null
}

/** The Frida server file for this phone, and the checksum GitHub publishes for it. */
export function pickFridaServer(assets: ReleaseAsset[], version: string, arch: string): { url: string; sha256: string } | null {
  const a = assets.find((x) => x.name === `frida-server-${version}-android-${arch}.xz`)
  const sha = a?.digest && /^sha256:([0-9a-f]{64})$/i.exec(a.digest)?.[1]
  return a && sha ? { url: a.browser_download_url, sha256: sha.toLowerCase() } : null
}

// ---------------------------------------------------------------- Finding tools on this Mac

const sdkCandidates = (env: NodeJS.ProcessEnv): string[] => [env.ANDROID_HOME, env.ANDROID_SDK_ROOT, join(env.HOME || homedir(), 'Library/Android/sdk')].filter(Boolean) as string[]

export function findAdb(env: NodeJS.ProcessEnv = process.env): string | null {
  const roots = sdkCandidates(env)
  const list = [...roots.map((r) => join(r, 'platform-tools/adb')), '/opt/homebrew/bin/adb', '/usr/local/bin/adb']
  return list.find((p) => existsSync(p)) ?? null
}

export function sdkRoot(env: NodeJS.ProcessEnv = process.env): string | null {
  return sdkCandidates(env).find((r) => existsSync(r)) ?? null
}

const sdkTool = (rel: string[]): string | null => {
  const r = sdkRoot()
  if (!r) return null
  for (const p of rel) if (existsSync(join(r, p))) return join(r, p)
  return null
}

export const findEmulator = (): string | null => sdkTool(['emulator/emulator'])
export const findAvdManager = (): string | null => sdkTool(['cmdline-tools/latest/bin/avdmanager', 'cmdline-tools/bin/avdmanager'])
export const findSdkManager = (): string | null => sdkTool(['cmdline-tools/latest/bin/sdkmanager', 'cmdline-tools/bin/sdkmanager'])

export type { Device, LiveSetup }

export async function liveSetup(exec: Exec = realExec): Promise<LiveSetup> {
  const adb = findAdb()
  const emu = findEmulator()
  let devices: Device[] = []
  let avds: string[] = []
  if (adb) devices = parseDevices((await exec(adb, ['devices', '-l'], { timeout: 15000 }).catch(() => Buffer.from(''))).toString('utf8'))
  if (emu) avds = (await exec(emu, ['-list-avds'], { timeout: 15000 }).catch(() => Buffer.from(''))).toString('utf8').split('\n').map((x) => x.trim()).filter(validAvd)
  return { adb, emulator: !!emu, canCreate: !!findAvdManager() && !!findSdkManager(), devices, avds }
}

/** Starts a test phone. It keeps running after MacSec's request ends. */
export function startAvd(name: string): void {
  const emu = findEmulator()
  if (!emu) throw new Error('The Android emulator is not installed. It comes with Android Studio.')
  if (!validAvd(name)) throw new Error('That test phone name is not valid.')
  const p = execFile(emu, ['-avd', name, '-no-snapshot-save', '-netdelay', 'none', '-netspeed', 'full'], { env: toolEnv() }, () => undefined)
  p.unref()
}

/** Builds a test phone from a system image that is already installed (one with Google APIs, which allows root). */
export async function createAvd(exec: Exec = realExec, note: (d: string) => void = () => undefined, hostArm = process.arch === 'arm64'): Promise<string> {
  const sdk = findSdkManager()
  const avd = findAvdManager()
  if (!sdk || !avd) throw new Error('Android’s command line tools were not found. Install Android Studio once (it is free), open it, and MacSec can build the test phone.')
  const abi = hostArm ? 'arm64-v8a' : 'x86_64'
  const image = `system-images;android-34;google_apis;${abi}`
  const have = (await exec(sdk, ['--list_installed'], { timeout: 120_000 })).toString('utf8')
  if (!have.includes(image)) {
    note('Downloading the test phone’s system image (about 1 GB). This can take a while')
    await exec(sdk, ['--install', image], { timeout: 45 * 60_000, input: 'y\n'.repeat(20) })
  }
  note('Building the test phone')
  const name = 'macsec-test'
  await exec(avd, ['create', 'avd', '-n', name, '-k', image, '-d', 'pixel_6', '--force'], { timeout: 120_000, input: 'no\n' })
  return name
}

// ---------------------------------------------------------------- What Frida watches

/** The Frida script. It only observes: every hook calls the original method and returns its answer unchanged. */
export const WATCH_SCRIPT = `'use strict';
function out(o) { console.log('[macsec] ' + JSON.stringify(o)); }
function tryHook(what, fn) { try { fn(); } catch (e) { out({ t: 'skip', what: what }); } }
Java.perform(function () {
  tryHook('okhttp', function () {
    var CP = Java.use('okhttp3.CertificatePinner');
    CP.check.overload('java.lang.String', 'java.util.List').implementation = function (host, peers) {
      out({ t: 'pin', lib: 'okhttp', host: String(host) });
      return this.check(host, peers);
    };
  });
  tryHook('conscrypt', function () {
    var TM = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TM.verifyChain.implementation = function () {
      out({ t: 'tls', lib: 'system' });
      return this.verifyChain.apply(this, arguments);
    };
  });
  tryHook('trustmanagers', function () {
    var SC = Java.use('javax.net.ssl.SSLContext');
    SC.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function (k, t, r) {
      try {
        if (t) { var names = []; for (var i = 0; i < t.length; i++) names.push(String(t[i].$className)); out({ t: 'tm', classes: names }); }
      } catch (e) {}
      return this.init(k, t, r);
    };
  });
  tryHook('urls', function () {
    var U = Java.use('java.net.URL');
    U.$init.overload('java.lang.String').implementation = function (s) {
      try {
        var m = /^(https?):\\/\\/([^\\/:?#]+)/i.exec(String(s));
        if (m) out({ t: 'url', scheme: m[1].toLowerCase(), host: m[2].toLowerCase() });
      } catch (e) {}
      return this.$init(s);
    };
  });
  tryHook('root-files', function () {
    var F = Java.use('java.io.File');
    F.exists.implementation = function () {
      try {
        var p = String(this.getAbsolutePath());
        if (/(^|\\/)(su|busybox|magisk|Superuser\\.apk)$/i.test(p)) out({ t: 'root', how: 'looked for a file', what: p });
      } catch (e) {}
      return this.exists();
    };
  });
  tryHook('root-exec', function () {
    var R = Java.use('java.lang.Runtime');
    R.exec.overload('java.lang.String').implementation = function (c) {
      try { if (/(^|\\s|\\/)su(\\s|$)/.test(String(c))) out({ t: 'root', how: 'ran a command', what: String(c).slice(0, 40) }); } catch (e) {}
      return this.exec(c);
    };
  });
  out({ t: 'ready' });
});
`

export type LiveEvent =
  | { t: 'pin'; lib: string; host?: string }
  | { t: 'tls'; lib: string }
  | { t: 'tm'; classes: string[] }
  | { t: 'url'; scheme: 'http' | 'https'; host: string }
  | { t: 'root'; how: string; what: string }
  | { t: 'skip'; what: string }
  | { t: 'ready' }

/** Reads Frida's output: lines that carry "[macsec] {json}", whatever Frida puts in front of them. */
export function parseEvents(text: string): LiveEvent[] {
  const out: LiveEvent[] = []
  for (const line of text.split('\n')) {
    const i = line.indexOf('[macsec] ')
    if (i < 0) continue
    try {
      const o = JSON.parse(line.slice(i + 9)) as LiveEvent
      if (o && typeof o === 'object' && typeof o.t === 'string') out.push(o)
    } catch {
      // Not ours.
    }
  }
  return out
}

// ---------------------------------------------------------------- Looking for secrets that were seen

export interface Seen {
  kind: string
  where: string
  /** A short sample with the secret itself hidden. */
  sample: string
  severity: 'high' | 'medium'
}

const LOG_RULES: { kind: string; re: RegExp; sev: 'high' | 'medium' }[] = [
  { kind: 'an Authorization header', re: /authorization\s*[:=]\s*(?:bearer|basic)\s+(\S{8,})/i, sev: 'medium' },
  { kind: 'a sign-in token (JWT)', re: /\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})/, sev: 'medium' },
  { kind: 'a password', re: /\b(?:password|passwd|pwd)["']?\s*[:=]\s*["']?([^\s"'&,}]{4,})/i, sev: 'high' },
  { kind: 'a token or key', re: /\b(?:access_token|refresh_token|api[_-]?key|apikey|client_secret|secret|session(?:id)?)["']?\s*[:=]\s*["']?([A-Za-z0-9._~+/=-]{12,})/i, sev: 'medium' }
]

/** Secrets the app wrote to the phone's log. Only the kind and the line number are kept, never the value. */
export function scanLog(text: string): Seen[] {
  const out: Seen[] = []
  const lines = text.split('\n')
  for (const [i, l] of lines.entries()) {
    for (const r of LOG_RULES) {
      const m = r.re.exec(l)
      if (!m) continue
      out.push({ kind: r.kind, where: `log line ${i + 1}`, sample: l.replace(m[1], '[hidden]').trim().slice(0, 160), severity: r.sev })
      break
    }
    if (out.length >= 20) break
  }
  return out
}

const KEY = /(token|secret|passw|pwd|api_?key|auth|session|jwt|bearer|credential)/i

/** Printable text inside a binary file, like the `strings` tool. */
export function printable(buf: Buffer): string {
  return (buf.toString('latin1').match(/[\x20-\x7e]{6,}/g) ?? []).join('\n')
}

/** Secrets an app keeps in a file of its own. Only the kind, the key's name and the file are kept. */
export function scanStored(file: string, buf: Buffer): Seen[] {
  const text = /\.(db|sqlite|sqlite3)$/i.test(file) ? printable(buf) : buf.toString('utf8')
  const out: Seen[] = []
  const seen = new Set<string>()
  const add = (name: string, val: string): void => {
    if (/androidx_security|keyset|__androidx/i.test(name) || val.length < 8 || seen.has(name)) return
    seen.add(name)
    const pw = /passw|pwd/i.test(name)
    out.push({ kind: pw ? 'a password' : 'a token or key', where: `${file}, "${name}"`, sample: `${name} = [hidden, ${val.length} characters]`, severity: pw ? 'high' : 'medium' })
  }
  for (const m of text.matchAll(/<string\s+name="([^"]+)">([^<]{8,})<\/string>/g)) if (KEY.test(m[1])) add(m[1], m[2])
  for (const m of text.matchAll(/"([A-Za-z0-9_.-]*(?:token|secret|passw\w*|pwd|api_?key|jwt|bearer)[A-Za-z0-9_.-]*)"\s*:\s*"([^"]{8,})"/gi)) add(m[1], m[2])
  for (const m of text.matchAll(/\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})/g)) add('a JWT', m[1])
  return out
}

// ---------------------------------------------------------------- The test itself

export interface LiveCtx {
  exec: Exec
  adb: string
  frida: string | null
  serial: string
  apk: string
  pkg: string
  /** The person confirmed this phone is theirs to test. Required for anything that is not an emulator. */
  confirmed: boolean
  note: (d: string) => void
  /** Returns the path of a Frida server file for this phone, after checking its checksum. */
  fridaServer: (arch: string) => Promise<string>
  scriptPath: string
  seconds?: number
  pause?: (ms: number) => Promise<void>
  cancelled?: () => boolean
}

const fnd = (x: Omit<Finding, 'id' | 'tool' | 'category' | 'confidence'> & { confidence?: 'confirmed' | 'possible' }, key: string): Finding => ({ id: fid('live', x.title, x.file ?? '', key), tool: 'MacSec live test', category: 'mobile', confidence: 'confirmed', ...x })

const proof = (serial: string, cmd: string, shows: string[], bytes = 0, body = ''): Proof => ({ request: `adb -s ${serial} ${cmd}`, reproduce: `adb -s ${serial} ${cmd}`, status: 0, bytes, sha256: createHash('sha256').update(body).digest('hex'), at: new Date().toISOString(), shows: shows.slice(0, 12).map((s) => s.slice(0, 200)) })

const LOCAL_HOST = /^(localhost|127\.|10\.0\.2\.2$|10\.0\.3\.2$|192\.168\.|10\.|0\.0\.0\.0$)/

export async function liveTest(c: LiveCtx): Promise<Finding[]> {
  if (!validSerial(c.serial)) throw new Error('That device name is not valid.')
  if (!validPackage(c.pkg)) throw new Error('The app’s package name looks wrong, so the live test was not started.')
  const pause = c.pause ?? sleep
  const adb = (args: string[], timeout = 30_000): Promise<Buffer> => c.exec(c.adb, ['-s', c.serial, ...args], { timeout })
  const sh = async (cmd: string, timeout = 30_000): Promise<string> => (await adb(['shell', cmd], timeout)).toString('utf8')
  const out: Finding[] = []

  const state = (await adb(['get-state'], 15_000).catch(() => Buffer.from(''))).toString('utf8').trim()
  if (state !== 'device') throw new Error('The phone is not ready. Unlock it, accept the USB prompt on its screen, or wait for the emulator to finish starting.')
  const isEmu = c.serial.startsWith('emulator-') || (await sh('getprop ro.kernel.qemu')).trim() === '1'
  if (!isEmu && !c.confirmed) throw new Error('This is a real phone. Confirm that it is yours to test first.')
  const abi = (await sh('getprop ro.product.cpu.abi')).trim()

  // Root: an emulator image with Google APIs lets adb restart as root. A rooted phone can answer "su".
  let rooted = false
  let viaSu = false
  if (isEmu) {
    await c.exec(c.adb, ['-s', c.serial, 'root'], { timeout: 20_000 }).catch(() => Buffer.from(''))
    await pause(2000)
    rooted = (await sh('id -u').catch(() => '')).trim() === '0'
  } else {
    viaSu = (await sh('su -c id -u').catch(() => '')).trim() === '0'
    rooted = viaSu
  }
  const asRoot = (cmd: string, timeout?: number): Promise<string> => sh(viaSu ? `su -c '${cmd}'` : cmd, timeout)

  const installedBefore = (await sh(`pm list packages ${c.pkg}`)).split('\n').some((l) => l.trim() === `package:${c.pkg}`)
  let installedByUs = false
  let server = false
  try {
    if (!installedBefore) {
      c.note('Installing the app on the test phone')
      const r = (await adb(['install', '-r', '-t', c.apk], 180_000)).toString('utf8')
      if (!/Success/i.test(r)) throw new Error(`The app would not install: ${r.trim().split('\n').pop()?.slice(0, 120) ?? 'unknown reason'}`)
      installedByUs = true
    }
    await sh('logcat -c').catch(() => '')

    // Frida needs the phone to be rooted. Without it the app is only launched and the log and files are read.
    let events: LiveEvent[] = []
    const secs = c.seconds ?? 25
    let watched = false
    if (rooted && c.frida) {
      const arch = fridaArch(abi)
      if (!arch) c.note(`This phone's processor (${abi}) is not one Frida supports, so only the log and files will be checked`)
      else {
        const running = (await asRoot('pidof macsec-frida-server').catch(() => '')).trim()
        if (!running) {
          c.note('Putting Frida’s server on the test phone')
          const local = await c.fridaServer(arch)
          await adb(['push', local, '/data/local/tmp/macsec-frida-server'], 120_000)
          await asRoot('chmod 755 /data/local/tmp/macsec-frida-server')
          await asRoot('/data/local/tmp/macsec-frida-server -D', 20_000).catch(() => '')
          await pause(1500)
        }
        server = !!(await asRoot('pidof macsec-frida-server').catch(() => '')).trim()
        if (server) {
          writeFileSync(c.scriptPath, WATCH_SCRIPT)
          c.note(`Watching the app for ${secs} seconds`)
          let text = ''
          try {
            text = (await c.exec(c.frida, ['-D', c.serial, '-f', c.pkg, '-l', c.scriptPath, '-q', '-t', String(secs)], { timeout: (secs + 90) * 1000 })).toString('utf8')
          } catch (e) {
            text = ((e as { stdout?: Buffer }).stdout ?? Buffer.from('')).toString('utf8')
          }
          events = parseEvents(text)
          watched = events.some((e) => e.t === 'ready')
        }
      }
    } else c.note(rooted ? 'Frida is not installed, so only the log and files will be checked' : 'The phone is not rooted, so Frida cannot watch the app. Only the log and files will be checked where allowed')
    if (!watched) {
      await sh(`monkey -p ${c.pkg} -c android.intent.category.LAUNCHER 1`).catch(() => '')
      c.note(`Letting the app run for ${secs} seconds`)
      await pause(secs * 1000)
    }
    if (c.cancelled?.()) return out

    // The phone's log, for this app's own process.
    const pid = (await sh(`pidof ${c.pkg}`).catch(() => '')).trim().split(/\s+/)[0]
    const log = (await adb(['logcat', '-d', '-v', 'threadtime'], 60_000).catch(() => Buffer.from(''))).toString('utf8')
    const mine = pid ? log.split('\n').filter((l) => new RegExp(`\\s${pid}\\s`).test(l)).join('\n') : ''
    for (const s of scanLog(mine).slice(0, 8))
      out.push(fnd({ severity: s.severity, title: `The app writes ${s.kind} to the phone’s log`, file: s.where, cwe: 'CWE-532', description: 'Anything in the log can be read by someone with the phone connected, by other tools on a rooted phone, and by bug-report files people send around.', fix: 'Remove the log line, or log only in debug builds. Never log passwords, tokens or full request headers.', proof: proof(c.serial, `logcat -d -v threadtime`, [`${s.where}: ${s.sample}`, 'the value is hidden here and is not saved by MacSec']) }, `${s.where}${s.kind}`))

    // Files the app keeps for itself. Reading another app's folder needs root.
    if (rooted) {
      const dirs = [`/data/data/${c.pkg}`, `/sdcard/Android/data/${c.pkg}`]
      let read = 0
      for (const d of dirs) {
        const list = (await asRoot(`find ${d} -type f -size -600k`).catch(() => '')).split('\n').map((x) => x.trim()).filter((x) => x.startsWith(d) && !/[\s'"`$;|&<>\\]/.test(x))
        for (const file of list.filter((f) => /\/(shared_prefs|databases|files|app_flutter|datastore)\//.test(f)).slice(0, 60)) {
          const buf = await adb(['shell', viaSu ? `su -c 'cat ${file}'` : `cat ${file}`], 30_000).catch(() => Buffer.alloc(0))
          read++
          const rel = file.replace(`/data/data/${c.pkg}/`, '').replace(`/sdcard/Android/data/${c.pkg}/`, 'sdcard/')
          for (const s of scanStored(rel, buf)) out.push(fnd({ severity: s.severity, title: `The app keeps ${s.kind} in plain text: ${rel}`, file: rel, cwe: 'CWE-312', description: 'The value is stored unencrypted in the app’s own files. It is protected from other apps, but anyone with a rooted phone, a backup or the files can read it.', fix: 'Keep secrets in the Android Keystore (or EncryptedSharedPreferences), and keep tokens short-lived.', proof: proof(c.serial, `shell su -c 'cat ${file}'`, [s.sample, `found in ${rel}`, 'the value is hidden here and is not saved by MacSec'], buf.length, buf.toString('latin1').replace(/[\x00-\x08]/g, '')) }, s.where))
        }
      }
      c.note(`${read} of the app’s files read`)
    }

    // What Frida saw.
    const urls = events.filter((e): e is Extract<LiveEvent, { t: 'url' }> => e.t === 'url')
    const hosts = [...new Set(urls.map((u) => u.host))].filter((h) => !LOCAL_HOST.test(h))
    for (const h of [...new Set(urls.filter((u) => u.scheme === 'http' && !LOCAL_HOST.test(u.host)).map((u) => u.host))])
      out.push(fnd({ severity: 'medium', title: `The app sent a request over plain HTTP to ${h}`, file: h, cwe: 'CWE-319', description: 'Plain HTTP is not encrypted, so anyone on the same network can read and change what is sent. It was seen while the app started, not guessed from its settings.', fix: 'Use HTTPS for every request, and turn cleartext traffic off in the app’s network security config.', proof: proof(c.serial, `shell frida-observed`, [`the app opened an http:// address on ${h}`, 'seen with Frida while the app started', 'only the host is kept, not the path or query']) }, `http${h}`))
    if (hosts.length)
      out.push(fnd({ severity: 'info', title: `Servers the app talked to at start-up: ${hosts.length}`, file: hosts[0], description: `${hosts.slice(0, 30).join(', ')}${hosts.length > 30 ? ', and more' : ''}. Only the first ${secs} seconds were watched and nothing was tapped, so the app may talk to more servers later. Each one is worth testing.`, proof: proof(c.serial, 'shell frida-observed', hosts.slice(0, 12).map((h) => `connected to ${h}`)) }, 'hosts'))

    const pins = events.filter((e): e is Extract<LiveEvent, { t: 'pin' }> => e.t === 'pin')
    const tms = events.filter((e): e is Extract<LiveEvent, { t: 'tm' }> => e.t === 'tm').flatMap((e) => e.classes).filter((n) => !/^(com\.android\.org\.conscrypt|android\.|java\.|javax\.|org\.conscrypt|null$)/.test(n))
    const https = urls.some((u) => u.scheme === 'https') || events.some((e) => e.t === 'tls')
    if (pins.length)
      out.push(fnd({ severity: 'info', title: 'Certificate pinning is in use', description: `The app checked a pinned certificate at run time (${[...new Set(pins.map((p) => p.lib))].join(', ')}${pins[0].host ? `, for example for ${pins[0].host}` : ''}). Pinning makes it harder to read the app's traffic with a proxy.`, proof: proof(c.serial, 'shell frida-observed', pins.slice(0, 6).map((p) => `${p.lib} pin check ran${p.host ? ` for ${p.host}` : ''}`)) }, 'pin'))
    else if (watched && https)
      out.push(fnd({ severity: 'low', confidence: 'possible', title: 'No certificate pinning was seen at run time', description: `The app made secure connections but no pinning check ran in the first ${secs} seconds. Pinning would stop someone on the same network from reading the traffic with their own certificate. The app may pin later, or in a way this test does not watch.`, fix: 'Pin the server certificate or its public key (Android’s network security config supports this), and plan for key rotation.', proof: proof(c.serial, 'shell frida-observed', ['secure connections were seen', 'no OkHttp pinning check ran', 'only the start-up was watched']) }, 'nopin'))
    if (tms.length)
      out.push(fnd({ severity: 'info', title: 'The app installs its own certificate check', description: `It supplies its own trust manager (${[...new Set(tms)].slice(0, 4).join(', ')}). That is how some apps pin, and how some apps accept every certificate. Read that class.`, proof: proof(c.serial, 'shell frida-observed', [...new Set(tms)].slice(0, 6).map((n) => `custom trust manager: ${n}`)) }, 'tm'))

    const roots = events.filter((e): e is Extract<LiveEvent, { t: 'root' }> => e.t === 'root')
    if (roots.length)
      out.push(fnd({ severity: 'info', title: 'The app looks for a rooted phone', description: 'It checks for root files or runs “su” at start-up. That slows down casual tampering but can be bypassed, so it is not a replacement for server-side checks.', proof: proof(c.serial, 'shell frida-observed', roots.slice(0, 6).map((r) => `${r.how}: ${r.what}`)) }, 'root'))
    else if (watched && rooted)
      out.push(fnd({ severity: 'info', confidence: 'possible', title: 'The app did not react to a rooted phone at start-up', description: 'This phone is rooted and no root check was seen in the first seconds. Root detection is optional, but banking, payment and health apps usually have it.', proof: proof(c.serial, 'shell frida-observed', ['no root file or su check was seen']) }, 'noroot'))
  } finally {
    await sh(`am force-stop ${c.pkg}`).catch(() => '')
    if (server) await asRoot('pkill -f macsec-frida-server').catch(() => '')
    if (installedByUs) await adb(['uninstall', c.pkg], 60_000).catch(() => Buffer.from(''))
  }
  return out
}

// ---------------------------------------------------------------- Frida's server file

/**
 * The Frida server file that matches the installed Frida, for this phone's processor. It comes
 * from Frida's own GitHub release, and is only used if its SHA-256 matches the one GitHub lists.
 */
export async function getFridaServer(exec: Exec, frida: string, arch: string, note: (d: string) => void, fetchImpl: typeof fetch = fetch): Promise<string> {
  const version = (await exec(frida, ['--version'], { timeout: 20_000 })).toString('utf8').trim()
  if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error('Could not tell which version of Frida is installed.')
  if (!/^(arm64|arm|x86|x86_64)$/.test(arch)) throw new Error('That processor is not supported.')
  const dir = join(dirs.tools(), 'frida-server')
  mkdirSync(dir, { recursive: true })
  const final = join(dir, `${version}-${arch}`)
  if (existsSync(final)) return final
  note(`Getting Frida ${version} for the test phone`)
  const res = await fetchImpl(`https://api.github.com/repos/frida/frida/releases/tags/${version}`, { headers: { 'User-Agent': USER_AGENT, Accept: 'application/vnd.github+json' } })
  if (!res.ok) throw new Error(`GitHub did not list Frida ${version} (${res.status}). If it says the limit was reached, try again in an hour.`)
  const pick = pickFridaServer(((await res.json()) as { assets?: ReleaseAsset[] }).assets ?? [], version, arch)
  if (!pick) throw new Error('GitHub did not give a checksum for that Frida server file, so it was not downloaded.')
  const xz = join(dir, `${version}-${arch}.xz`)
  await downloadFile(pick.url, xz)
  if ((await sha256File(xz)) !== pick.sha256) {
    rmSync(xz, { force: true })
    throw new Error('The Frida server file did not match its checksum, so it was thrown away.')
  }
  note('Unpacking Frida’s server')
  const raw = join(dir, `${version}-${arch}.raw`)
  try {
    await exec('/usr/bin/xz', ['-dkc', xz], { timeout: 120_000 }).then((b) => writeFileSync(raw, b))
  } catch {
    await exec('python3', ['-I', '-c', 'import lzma,sys,shutil\nwith lzma.open(sys.argv[1]) as a, open(sys.argv[2],"wb") as b: shutil.copyfileobj(a,b)', xz, raw], { timeout: 120_000 })
  }
  renameSync(raw, final)
  rmSync(xz, { force: true })
  return final
}
