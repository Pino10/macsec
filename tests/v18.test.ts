import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { afterAll, describe, expect, it } from 'vitest'
import { createAvd, fridaArch, liveTest, packageFromManifest, parseDevices, parseEvents, pickFridaServer, printable, scanLog, scanStored, validAvd, validPackage, validSerial, WATCH_SCRIPT, type Exec } from '../src/main/mobilelive'

const dir = mkdtempSync(join(tmpdir(), 'macsec-live-'))
afterAll(() => rmSync(dir, { recursive: true, force: true }))

describe('what is given to adb', () => {
  it('accepts real names and refuses anything that could be a command', () => {
    expect(validSerial('emulator-5554')).toBe(true)
    expect(validSerial('R58M123ABC')).toBe(true)
    expect(validSerial('192.168.1.5:5555')).toBe(true)
    for (const bad of ['', 'a b', 'x;rm -rf /', '$(id)', 'a'.repeat(70), '`x`', 'a|b']) expect(validSerial(bad)).toBe(false)
    expect(validPackage('com.example.app')).toBe(true)
    for (const bad of ['app', 'com.example;ls', 'com..x', '1com.x', "com.x'y", 'com.example.app\nrm']) expect(validPackage(bad)).toBe(false)
    expect(validAvd('Pixel_6_API_34')).toBe(true)
    expect(validAvd('a b')).toBe(false)
  })
  it('reads adb devices -l', () => {
    const text = 'List of devices attached\nemulator-5554          device product:sdk_gphone64 model:sdk_gphone64_arm64 device:emu64a transport_id:1\nR58M123ABC             unauthorized usb:1-1 transport_id:2\n\n'
    expect(parseDevices(text)).toEqual([
      { serial: 'emulator-5554', state: 'device', model: 'sdk gphone64 arm64', kind: 'emulator' },
      { serial: 'R58M123ABC', state: 'unauthorized', model: '', kind: 'phone' }
    ])
    expect(parseDevices('List of devices attached\n* daemon started\n')).toEqual([])
  })
  it('maps processors and reads the package name', () => {
    expect(fridaArch('arm64-v8a')).toBe('arm64')
    expect(fridaArch('x86_64\n')).toBe('x86_64')
    expect(fridaArch('mips')).toBeNull()
    expect(packageFromManifest('<?xml version="1.0"?><manifest xmlns:android="x" android:versionCode="1" package="com.example.shop"><application/></manifest>')).toBe('com.example.shop')
    expect(packageFromManifest('<manifest package="bad;name"/>')).toBeNull()
  })
  it('only trusts a Frida server file that has a published checksum', () => {
    const sha = 'a'.repeat(64)
    const assets = [
      { name: 'frida-server-16.5.9-android-arm64.xz', browser_download_url: 'https://github.com/x/arm64.xz', digest: `sha256:${sha}` },
      { name: 'frida-server-16.5.9-android-x86_64.xz', browser_download_url: 'https://github.com/x/x86.xz', digest: null }
    ]
    expect(pickFridaServer(assets, '16.5.9', 'arm64')).toEqual({ url: 'https://github.com/x/arm64.xz', sha256: sha })
    expect(pickFridaServer(assets, '16.5.9', 'x86_64')).toBeNull()
    expect(pickFridaServer(assets, '16.5.8', 'arm64')).toBeNull()
  })
})

describe('what Frida reports', () => {
  it('reads events whatever Frida prints in front of them', () => {
    const text = ['Spawned `com.example.shop`. Resuming main thread!', '[Android Emulator 5554::com.example.shop ]-> [macsec] {"t":"ready"}', '[macsec] {"t":"url","scheme":"http","host":"api.example.com"}', '[macsec] {not json', 'noise'].join('\n')
    expect(parseEvents(text)).toEqual([{ t: 'ready' }, { t: 'url', scheme: 'http', host: 'api.example.com' }])
  })
  it('only watches: every hook calls the original', () => {
    expect(WATCH_SCRIPT).not.toMatch(/return (true|false|null)\s*;/)
    for (const call of ['this.check(host, peers)', 'this.verifyChain.apply', 'this.init(k, t, r)', 'this.$init(s)', 'this.exists()', 'this.exec(c)']) expect(WATCH_SCRIPT).toContain(call)
    expect(WATCH_SCRIPT).not.toMatch(/Interceptor\.replace|\.implementation = function \(\) \{\s*return/)
  })
})

describe('secrets that were seen are never kept', () => {
  it('finds them in a log with the value hidden', () => {
    const log = ['D/Net( 123): GET /items 200', 'D/Net( 123): Authorization: Bearer abcdef1234567890SECRETVALUE', 'D/Auth( 123): login password=hunter2hunter2 user=bob', 'I/x( 123): token eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4fw ok'].join('\n')
    const found = scanLog(log)
    expect(found.map((f) => f.kind)).toEqual(['an Authorization header', 'a password', 'a sign-in token (JWT)'])
    expect(found[1].severity).toBe('high')
    expect(JSON.stringify(found)).not.toMatch(/SECRETVALUE|hunter2|SflKxwRJ/)
    expect(scanLog('D/App: started ok, 12 items loaded')).toEqual([])
  })
  it('finds them in the app’s own files, by key name only', () => {
    const xml = '<map><string name="access_token">ya29.A0ARrdaMsecretsecret</string><string name="theme">dark-and-long-enough</string><string name="user_password">pa55w0rd-long</string><string name="__androidx_security_crypto_encrypted_prefs_key_keyset__">12ab34cd56ef7890</string></map>'
    const found = scanStored('shared_prefs/auth.xml', Buffer.from(xml))
    expect(found.map((f) => f.where)).toEqual(['shared_prefs/auth.xml, "access_token"', 'shared_prefs/auth.xml, "user_password"'])
    expect(found[1].severity).toBe('high')
    expect(JSON.stringify(found)).not.toMatch(/ya29|secretsecret|pa55w0rd/)
    const json = scanStored('files/session.json', Buffer.from('{"refresh_token":"abcdefghijklmnop","name":"bob"}'))
    expect(json).toHaveLength(1)
  })
  it('reads text inside a database file', () => {
    const buf = Buffer.concat([Buffer.from([0, 1, 2, 3]), Buffer.from('{"api_key":"ABCDEFGH12345678"}'), Buffer.from([0, 0, 9])])
    expect(printable(buf)).toContain('api_key')
    expect(scanStored('databases/app.db', buf)).toHaveLength(1)
  })
})

/** A pretend phone: answers the way adb would, and keeps a record of every command. */
function phone(o: { emulator?: boolean; rooted?: boolean; installed?: boolean; frida?: string; log?: string; files?: Record<string, string>; state?: string } = {}): { exec: Exec; calls: string[] } {
  const calls: string[] = []
  const files = o.files ?? {}
  const rooted = o.rooted ?? true
  const exec: Exec = async (bin, args) => {
    calls.push(`${bin.split('/').pop()} ${args.join(' ')}`)
    const b = (s: string): Buffer => Buffer.from(s)
    if (bin.endsWith('frida')) {
      if (o.frida === 'fail') throw Object.assign(new Error('exit 1'), { stdout: b(o.frida ?? '') })
      return b(o.frida ?? '')
    }
    const i = args.indexOf('-s')
    const rest = args.slice(i + 2)
    if (rest[0] === 'get-state') return b(o.state ?? 'device')
    if (rest[0] === 'root') return b('restarting adbd as root')
    if (rest[0] === 'install') return b('Performing Streamed Install\nSuccess')
    if (rest[0] === 'uninstall') return b('Success')
    if (rest[0] === 'push') return b('1 file pushed')
    if (rest[0] === 'logcat') return b(o.log ?? '')
    if (rest[0] === 'shell') {
      const cmd = rest.slice(1).join(' ')
      if (cmd.startsWith('getprop ro.kernel.qemu')) return b(o.emulator === false ? '' : '1')
      if (cmd.startsWith('getprop ro.product.cpu.abi')) return b('arm64-v8a')
      if (cmd === 'id -u') return b(rooted ? '0' : '2000')
      if (cmd.startsWith('su -c')) return b('')
      if (cmd.startsWith('pm list packages')) return b(o.installed ? 'package:com.example.shop' : '')
      if (cmd.startsWith('pidof macsec-frida-server')) return b(calls.some((c) => c.includes('macsec-frida-server -D')) ? '777' : '')
      if (cmd.startsWith('pidof com.example.shop')) return b('4242')
      if (cmd.startsWith('find ')) return b(Object.keys(files).join('\n'))
      if (cmd.startsWith('cat ')) return b(files[cmd.slice(4)] ?? '')
      return b('')
    }
    return b('')
  }
  return { exec, calls }
}

const ctx = (p: { exec: Exec }, extra: Partial<Parameters<typeof liveTest>[0]> = {}): Parameters<typeof liveTest>[0] => ({
  exec: p.exec,
  adb: '/sdk/adb',
  frida: '/tools/frida',
  serial: 'emulator-5554',
  apk: '/tmp/app.apk',
  pkg: 'com.example.shop',
  confirmed: true,
  note: () => undefined,
  fridaServer: async () => '/tmp/frida-server-file',
  scriptPath: join(dir, 'watch.js'),
  seconds: 1,
  pause: async () => undefined,
  ...extra
})

describe('the live test', () => {
  const frida = ['[macsec] {"t":"ready"}', '[macsec] {"t":"url","scheme":"https","host":"api.example.com"}', '[macsec] {"t":"url","scheme":"http","host":"track.example.net"}', '[macsec] {"t":"url","scheme":"http","host":"10.0.2.2"}', '[macsec] {"t":"tls","lib":"system"}', '[macsec] {"t":"root","how":"looked for a file","what":"/system/xbin/su"}'].join('\n')

  it('reports what it saw, with proof, and cleans up after itself', async () => {
    const p = phone({
      frida,
      log: ['04-01 10:00:00.000  4242  4242 D Net: Authorization: Bearer abcdef1234567890SECRETVALUE', '04-01 10:00:00.100  999  999 D Other: password=shouldnotcount1'].join('\n'),
      files: { '/data/data/com.example.shop/shared_prefs/auth.xml': '<map><string name="access_token">ya29.A0ARrdaMsecretsecret</string></map>' }
    })
    const out = await liveTest(ctx(p))
    const titles = out.map((f) => f.title)
    expect(titles).toContain('The app sent a request over plain HTTP to track.example.net')
    expect(titles.some((t) => t.includes('10.0.2.2'))).toBe(false)
    expect(titles).toContain('The app writes an Authorization header to the phone’s log')
    expect(titles.filter((t) => t.includes('writes a password'))).toEqual([])
    expect(titles).toContain('The app keeps a token or key in plain text: shared_prefs/auth.xml')
    expect(titles).toContain('The app looks for a rooted phone')
    expect(titles).toContain('Servers the app talked to at start-up: 2')
    expect(titles).toContain('No certificate pinning was seen at run time')
    expect(out.every((f) => f.proof && f.proof.reproduce.startsWith('adb -s emulator-5554'))).toBe(true)
    expect(JSON.stringify(out)).not.toMatch(/SECRETVALUE|ya29|secretsecret|shouldnotcount/)
    // Cleaned up: the app is stopped, removed (MacSec installed it), and the Frida server is stopped.
    const all = p.calls.join('\n')
    expect(all).toContain('uninstall com.example.shop')
    expect(all).toContain('am force-stop com.example.shop')
    expect(all).toContain('pkill -f macsec-frida-server')
    expect(readFileSync(join(dir, 'watch.js'), 'utf8')).toContain('Java.perform')
  })
  it('does not remove an app that was already on the phone', async () => {
    const p = phone({ installed: true, frida })
    await liveTest(ctx(p))
    expect(p.calls.join('\n')).not.toContain('uninstall')
    expect(p.calls.join('\n')).not.toContain(' install ')
  })
  it('reports pinning as in use when a pin check ran, and sends no taps or typing', async () => {
    const p = phone({ frida: [frida, '[macsec] {"t":"pin","lib":"okhttp","host":"api.example.com"}'].join('\n') })
    const out = await liveTest(ctx(p))
    expect(out.map((f) => f.title)).toContain('Certificate pinning is in use')
    expect(out.map((f) => f.title)).not.toContain('No certificate pinning was seen at run time')
    expect(p.calls.join('\n')).not.toMatch(/input (tap|text|swipe)|monkey .*--/)
  })
  it('on a phone that is not rooted it only launches the app and reads the log', async () => {
    const p = phone({ emulator: false, rooted: false, log: '04-01 10:00:00.000  4242  4242 D A: password=abcd1234' })
    const out = await liveTest(ctx(p, { serial: 'R58M123ABC' }))
    expect(p.calls.join('\n')).not.toContain('macsec-frida-server')
    expect(p.calls.join('\n')).toContain('monkey -p com.example.shop -c android.intent.category.LAUNCHER 1')
    expect(out.map((f) => f.title)).toContain('The app writes a password to the phone’s log')
    expect(out.some((f) => /pinning/.test(f.title))).toBe(false)
  })
  it('refuses a real phone that was not confirmed, and a phone that is not ready', async () => {
    await expect(liveTest(ctx(phone({ emulator: false }), { serial: 'R58M123ABC', confirmed: false }))).rejects.toThrow(/Confirm that it is yours/)
    await expect(liveTest(ctx(phone({ state: 'offline' })))).rejects.toThrow(/not ready/)
    await expect(liveTest(ctx(phone(), { pkg: 'com.x;rm -rf /' }))).rejects.toThrow(/package name/)
    await expect(liveTest(ctx(phone(), { serial: 'a b' }))).rejects.toThrow(/device name/)
  })
  it('keeps going when Frida exits with an error but printed what it saw', async () => {
    const p = phone({ frida: 'fail' })
    const out = await liveTest(ctx(p))
    expect(Array.isArray(out)).toBe(true)
  })
})

describe('building a test phone', () => {
  it('installs the missing system image, then creates the phone, with argument lists only', async () => {
    const sdk = mkdtempSync(join(tmpdir(), 'macsec-sdk-'))
    mkdirSync(join(sdk, 'cmdline-tools/latest/bin'), { recursive: true })
    writeFileSync(join(sdk, 'cmdline-tools/latest/bin/sdkmanager'), '')
    writeFileSync(join(sdk, 'cmdline-tools/latest/bin/avdmanager'), '')
    const old = process.env.ANDROID_HOME
    process.env.ANDROID_HOME = sdk
    const calls: string[] = []
    try {
      const name = await createAvd(async (bin, args) => {
        calls.push(`${bin.split('/').pop()} ${args.join(' ')}`)
        return Buffer.from(args[0] === '--list_installed' ? 'Installed packages:\n  platform-tools | 35 |' : '')
      }, () => undefined, true)
      expect(name).toBe('macsec-test')
      expect(calls).toEqual([
        'sdkmanager --list_installed',
        'sdkmanager --install system-images;android-34;google_apis;arm64-v8a',
        'avdmanager create avd -n macsec-test -k system-images;android-34;google_apis;arm64-v8a -d pixel_6 --force'
      ])
    } finally {
      if (old === undefined) delete process.env.ANDROID_HOME
      else process.env.ANDROID_HOME = old
      rmSync(sdk, { recursive: true, force: true })
    }
  })
  it('says what to install when Android’s tools are missing', async () => {
    const old = process.env.ANDROID_HOME
    const oldS = process.env.ANDROID_SDK_ROOT
    const oldHome = process.env.HOME
    process.env.ANDROID_HOME = '/nonexistent-sdk'
    process.env.ANDROID_SDK_ROOT = '/nonexistent-sdk'
    process.env.HOME = mkdtempSync(join(tmpdir(), 'macsec-home-'))
    try {
      await expect(createAvd(async () => Buffer.from(''), () => undefined, true)).rejects.toThrow(/Android Studio/)
    } finally {
      if (old === undefined) delete process.env.ANDROID_HOME
      else process.env.ANDROID_HOME = old
      if (oldS === undefined) delete process.env.ANDROID_SDK_ROOT
      else process.env.ANDROID_SDK_ROOT = oldS
      rmSync(process.env.HOME!, { recursive: true, force: true })
      process.env.HOME = oldHome
    }
  })
})
