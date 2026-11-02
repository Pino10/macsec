/**
 * Mobile apps: mobsfscan's results on source code, and MacSec's own read-only checks of a built
 * app's settings (the Android manifest, the iOS Info.plist) and of its compiled code's hardening.
 */
import type { Finding, Severity } from '../../shared/types'
import { fid, sev } from './parse'

// ---------------------------------------------------------------- mobsfscan

interface MobsfFile {
  file_path: string
  match_lines?: [number, number]
}
interface MobsfRule {
  files?: MobsfFile[]
  metadata?: { description?: string; severity?: string; cwe?: string; masvs?: string; 'owasp-mobile'?: string; reference?: string }
}

export function parseMobsfscan(text: string, root: string): Finding[] {
  let data: { results?: Record<string, MobsfRule> }
  try {
    data = JSON.parse(text)
  } catch {
    return []
  }
  const out: Finding[] = []
  for (const [rule, r] of Object.entries(data.results ?? {})) {
    const m = r.metadata ?? {}
    // INFO rules with no file are "the app does not do X" suggestions (pinning, root detection).
    const severity: Severity = /^info$/i.test(m.severity ?? '') ? (r.files?.length ? 'low' : 'info') : sev(m.severity)
    // mobsfscan's descriptions are paragraphs: the first sentence is the title.
    const title = ((m.description ?? rule).split('\n')[0].split(/(?<=\.)\s/)[0] ?? rule).replace(/\.$/, '').slice(0, 140)
    const cwe = /CWE-\d+/.exec(m.cwe ?? '')?.[0]
    const extra = [m['owasp-mobile'] && `OWASP Mobile: ${m['owasp-mobile']}`, m.masvs && `MASVS: ${m.masvs}`].filter(Boolean).join('. ')
    const files = r.files?.length ? r.files : [{ file_path: '' }]
    for (const f of files) {
      const file = f.file_path ? f.file_path.replace(root.replace(/\/$/, '') + '/', '') : undefined
      out.push({
        id: fid('mobsf', rule, file, f.match_lines?.[0]),
        tool: 'mobsfscan',
        category: 'mobile',
        severity,
        title,
        file,
        line: f.match_lines?.[0],
        cwe,
        description: [m.description, extra].filter(Boolean).join('\n\n'),
        url: m.reference
      })
    }
  }
  return out
}

// ---------------------------------------------------------------- Android manifest

/** MacSec's own checks that mobsfscan also makes, by its rule name: when mobsfscan ran, its finding is kept. */
export const SAME_AS_MOBSF: Record<string, string> = {
  debuggable: 'android_manifest_debugging_enabled',
  backup: 'android_manifest_allow_backup',
  cleartext: 'android_manifest_usescleartext',
  minsdk: 'android_manifest_insecure_minsdk',
  ats: 'ios_ats_arbitrary_loads'
}
const covered = (key: string, mobsf: Set<string>): boolean => !!SAME_AS_MOBSF[key] && [...mobsf].some((r) => r.startsWith(SAME_AS_MOBSF[key]))

const attr = (tag: string, name: string): string | undefined => new RegExp(`(?:android:)?${name}\\s*=\\s*"([^"]*)"`).exec(tag)?.[1]

const DANGEROUS = ['READ_SMS', 'SEND_SMS', 'RECEIVE_SMS', 'READ_CONTACTS', 'READ_CALL_LOG', 'RECORD_AUDIO', 'CAMERA', 'ACCESS_FINE_LOCATION', 'ACCESS_BACKGROUND_LOCATION', 'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'MANAGE_EXTERNAL_STORAGE', 'REQUEST_INSTALL_PACKAGES', 'SYSTEM_ALERT_WINDOW', 'BIND_ACCESSIBILITY_SERVICE', 'READ_PHONE_STATE', 'QUERY_ALL_PACKAGES']

/** Reads AndroidManifest.xml (as source, or decoded from an .apk) for risky settings. */
export function checkAndroidManifest(xml: string, file = 'AndroidManifest.xml', mobsf = new Set<string>()): Finding[] {
  const out: Finding[] = []
  const add = (key: string, severity: Severity, title: string, description: string, fix: string): void => {
    if (!covered(key, mobsf)) out.push({ id: fid('manifest', key), tool: 'MacSec manifest check', category: 'mobile', severity, title, file, description, fix })
  }
  const app = /<application\b[^>]*>/s.exec(xml)?.[0] ?? ''
  if (attr(app, 'debuggable') === 'true') add('debuggable', 'high', 'The app is built as debuggable', 'Anyone with the phone can attach a debugger, read its memory and run code inside the app.', 'Remove android:debuggable, or set it to false, in release builds.')
  if (attr(app, 'testOnly') === 'true') add('testonly', 'medium', 'The app is marked test-only', 'Test-only builds are meant for development and should not be released.', 'Remove android:testOnly from the release manifest.')
  if (attr(app, 'allowBackup') === 'true') add('backup', 'low', 'App data can be copied off the phone by backup', 'With USB debugging, adb backup can copy the app’s private files, including tokens.', 'Set android:allowBackup="false", or use backup rules that leave out sensitive files.')
  if (attr(app, 'usesCleartextTraffic') === 'true') add('cleartext', 'medium', 'The app allows unencrypted HTTP', 'Traffic sent over plain HTTP can be read and changed on public Wi-Fi.', 'Remove android:usesCleartextTraffic="true" and use HTTPS everywhere, or allow HTTP only for named test domains in a network security config.')
  const minSdk = Number(attr(/<uses-sdk\b[^>]*>/s.exec(xml)?.[0] ?? '', 'minSdkVersion') ?? NaN)
  if (minSdk && minSdk < 23) add('minsdk', 'low', `Runs on very old Android (minimum API ${minSdk})`, 'Android versions before 6.0 miss many security fixes and runtime permissions.', 'Raise minSdkVersion to at least 23 if your users allow it.')

  const target = Number(attr(/<uses-sdk\b[^>]*>/s.exec(xml)?.[0] ?? '', 'targetSdkVersion') ?? NaN)
  const comps = xml.matchAll(/<(activity|activity-alias|service|receiver|provider)\b([^>]*?)(\/>|>([\s\S]*?)<\/\1>)/g)
  for (const c of comps) {
    const [, kind, attrs, , body = ''] = c
    const name = attr(attrs, 'name') ?? '(unnamed)'
    const exported = attr(attrs, 'exported')
    const perm = attr(attrs, 'permission') ?? (kind === 'provider' ? (attr(attrs, 'readPermission') ?? attr(attrs, 'writePermission')) : undefined)
    const filtered = /<intent-filter/.test(body)
    const isLauncher = /android\.intent\.category\.LAUNCHER/.test(body)
    const open = exported === 'true' || (exported === undefined && filtered && (!target || target < 31)) || (kind === 'provider' && exported === undefined && (!target || target < 17))
    if (!open || perm || isLauncher) continue
    add(`exp-${kind}-${name}`, kind === 'provider' ? 'high' : 'medium', `Other apps can open the ${kind} ${name.split('.').pop()}`, `${name} is exported without a permission, so any app on the phone can start it${kind === 'provider' ? ' and read or change its data' : ''}. Check it treats everything it receives as untrusted.`, `Set android:exported="false" if only your app uses it, or protect it with android:permission (signature level).`)
  }
  const dangerous = [...xml.matchAll(/<uses-permission\b[^>]*?name\s*=\s*"android\.permission\.([A-Z_]+)"/g)].map((m) => m[1]).filter((p) => DANGEROUS.includes(p))
  if (dangerous.length) add('perms', 'info', `Asks for ${dangerous.length} sensitive ${dangerous.length === 1 ? 'permission' : 'permissions'}`, `${dangerous.join(', ')}. Each one should be needed for a feature the user can see.`, 'Remove permissions the app does not need.')
  return out
}

// ---------------------------------------------------------------- iOS Info.plist

const plistTrue = (xml: string, key: string): boolean => new RegExp(`<key>${key}</key>\\s*<true\\s*/>`).test(xml)

/** Reads an Info.plist (XML form) for risky settings. */
export function checkInfoPlist(xml: string, file = 'Info.plist', mobsf = new Set<string>()): Finding[] {
  const out: Finding[] = []
  const add = (key: string, severity: Severity, title: string, description: string, fix: string): void => {
    if (!covered(key, mobsf)) out.push({ id: fid('plist', key), tool: 'MacSec Info.plist check', category: 'mobile', severity, title, file, description, fix })
  }
  if (plistTrue(xml, 'NSAllowsArbitraryLoads')) add('ats', 'high', 'App Transport Security is turned off', 'NSAllowsArbitraryLoads lets the app use plain HTTP and weak TLS with any server, so traffic can be read or changed.', 'Remove NSAllowsArbitraryLoads and use HTTPS. If one server cannot, add an exception for that domain only.')
  else if (plistTrue(xml, 'NSAllowsArbitraryLoadsInWebContent')) add('ats-web', 'medium', 'Web views may load insecure pages', 'NSAllowsArbitraryLoadsInWebContent turns off HTTPS rules inside web views.', 'Remove it unless the app must show arbitrary websites.')
  if (plistTrue(xml, 'NSExceptionAllowsInsecureHTTPLoads') || plistTrue(xml, 'NSTemporaryExceptionAllowsInsecureHTTPLoads')) add('ats-exc', 'medium', 'Some servers are allowed over plain HTTP', 'An ATS exception allows unencrypted HTTP to at least one domain.', 'Move those servers to HTTPS and remove the exception.')
  if (plistTrue(xml, 'UIFileSharingEnabled')) add('sharing', 'low', 'The app’s Documents folder is visible in Finder', 'UIFileSharingEnabled lets anyone with the unlocked phone and a cable copy the Documents folder.', 'Turn it off, or keep nothing sensitive in Documents.')
  const schemes = [...xml.matchAll(/<key>CFBundleURLSchemes<\/key>\s*<array>([\s\S]*?)<\/array>/g)].flatMap((m) => [...m[1].matchAll(/<string>([^<]+)<\/string>/g)].map((s) => s[1]))
  if (schemes.length) add('schemes', 'info', `Opens links with ${schemes.map((s) => `${s}://`).join(', ')}`, 'Any website or app can open these links with any data. Universal links are safer for sign-in and payments.', 'Check every value that arrives through these links before acting on it.')
  return out
}

// ---------------------------------------------------------------- Binary hardening (checksec-style)

export interface Hardening {
  format: 'mach-o' | 'elf' | 'unknown'
  pie?: boolean
  canary: boolean
  nx?: boolean
  relro?: 'full' | 'partial' | 'none'
  arc?: boolean
  encrypted?: boolean
  sharedLib?: boolean
}

const has = (b: Buffer, s: string): boolean => b.includes(Buffer.from(s, 'latin1'))

/** PIE, stack canaries, NX, RELRO, ARC and encryption, read from the file's headers. */
export function hardening(buf: Buffer): Hardening {
  const canary = has(buf, '__stack_chk_fail') || has(buf, '__stack_chk_guard')
  // Mach-O, possibly a universal ("fat") file: look at its first slice.
  let off = 0
  if (buf.length > 8 && buf.readUInt32BE(0) === 0xcafebabe) off = buf.readUInt32BE(8 + 8)
  if (buf.length > off + 32 && (buf.readUInt32LE(off) === 0xfeedfacf || buf.readUInt32LE(off) === 0xfeedface)) {
    const is64 = buf.readUInt32LE(off) === 0xfeedfacf
    const ncmds = buf.readUInt32LE(off + 16)
    const flags = buf.readUInt32LE(off + 24)
    let p = off + (is64 ? 32 : 28)
    let encrypted = false
    for (let i = 0; i < ncmds && p + 8 <= buf.length; i++) {
      const cmd = buf.readUInt32LE(p)
      const size = buf.readUInt32LE(p + 4)
      if ((cmd === 0x2c || cmd === 0x21) && p + 20 <= buf.length) encrypted = buf.readUInt32LE(p + 16) !== 0
      if (size < 8) break
      p += size
    }
    return { format: 'mach-o', pie: (flags & 0x200000) !== 0, canary, arc: has(buf, '_objc_release') || has(buf, 'swift_release'), encrypted }
  }
  if (buf.length > 64 && buf.readUInt32BE(0) === 0x7f454c46) {
    const is64 = buf[4] === 2
    const le = buf[5] === 1
    const u16 = (o: number): number => (le ? buf.readUInt16LE(o) : buf.readUInt16BE(o))
    const u32 = (o: number): number => (le ? buf.readUInt32LE(o) : buf.readUInt32BE(o))
    const type = u16(16)
    const phoff = is64 ? Number(le ? buf.readBigUInt64LE(32) : buf.readBigUInt64BE(32)) : u32(28)
    const phent = u16(is64 ? 54 : 42)
    const phnum = u16(is64 ? 56 : 44)
    let nx = false
    let relro = false
    for (let i = 0; i < phnum; i++) {
      const o = phoff + i * phent
      if (o + phent > buf.length) break
      const pt = u32(o)
      const pflags = is64 ? u32(o + 4) : u32(o + 24)
      if (pt === 0x6474e551) nx = (pflags & 1) === 0
      if (pt === 0x6474e552) relro = true
    }
    return { format: 'elf', pie: type === 3, sharedLib: type === 3 && !has(buf, '.interp'), canary, nx, relro: relro ? 'partial' : 'none' }
  }
  return { format: 'unknown', canary }
}

/** Findings for a set of compiled files, grouped so one missing setting is one finding. */
export function hardeningFindings(list: { file: string; h: Hardening }[], tool = 'MacSec binary check'): Finding[] {
  const out: Finding[] = []
  const group = (key: string, severity: Severity, title: string, description: string, fix: string, bad: (h: Hardening) => boolean): void => {
    const files = list.filter((x) => bad(x.h)).map((x) => x.file)
    if (!files.length) return
    out.push({ id: fid('bin', key), tool, category: 'binary', severity, title: files.length > 1 ? `${title} (${files.length} files)` : title, file: files[0], description: `${description}\n\nFiles: ${files.slice(0, 20).join(', ')}${files.length > 20 ? ` and ${files.length - 20} more` : ''}`, fix })
  }
  group('nx', 'high', 'Compiled code with an executable stack', 'Without NX, a memory bug can be turned into running attacker code much more easily.', 'Build with -z noexecstack (the default in current Android NDK and Xcode).', (h) => h.format === 'elf' && h.nx === false)
  group('pie', 'medium', 'Compiled code without PIE (fixed addresses)', 'Without position-independent code, address randomisation (ASLR) cannot protect the app.', 'Build with -fPIE -pie (Xcode and the NDK do this by default; check custom build flags).', (h) => h.format !== 'unknown' && h.pie === false && !h.sharedLib)
  group('canary', 'low', 'Compiled code without stack protection', 'Stack canaries stop many buffer overflows from being exploitable. Pure Swift code may not need them.', 'Build with -fstack-protector-strong.', (h) => h.format !== 'unknown' && !h.canary)
  group('relro', 'low', 'Native libraries without RELRO', 'Without RELRO, a memory bug can overwrite function pointers the program trusts.', 'Link with -Wl,-z,relro,-z,now.', (h) => h.format === 'elf' && h.relro === 'none')
  group('arc', 'low', 'iOS binary without ARC', 'Without Automatic Reference Counting, memory mistakes (use after free) are more likely.', 'Turn on ARC (CLANG_ENABLE_OBJC_ARC).', (h) => h.format === 'mach-o' && h.arc === false && !h.sharedLib)
  return out
}
