/**
 * A security check-up of this Mac. Everything here only reads: settings through Apple's own
 * command-line tools, the files that start programs at login, the ports programs listen on,
 * your SSH keys (only whether each is protected, never their contents) and the browser
 * extensions you installed. Nothing is changed and nothing leaves the Mac.
 */
import { execFile } from 'child_process'
import { existsSync, readdirSync, readFileSync, statSync } from 'fs'
import { homedir } from 'os'
import { join } from 'path'

export type CheckStatus = 'ok' | 'warn' | 'bad' | 'info'

export interface Check {
  id: string
  title: string
  status: CheckStatus
  detail: string
  fix?: string
}

export interface LoginItem {
  plist: string
  label: string
  program: string | null
  where: 'you' | 'all users' | 'system-wide daemon'
  signer: string | null
  status: CheckStatus
  note: string
}

export interface ListeningPort {
  command: string
  pid: number
  address: string
  port: number
  everyone: boolean
}

export interface SshKey {
  file: string
  kind: string
  protectedByPassphrase: boolean | null
  permissionsOk: boolean
}

export interface BrowserExtension {
  browser: string
  id: string
  name: string
  version: string
  risky: string[]
}

export interface CheckupResult {
  at: string
  macos: string
  checks: Check[]
  loginItems: LoginItem[]
  ports: ListeningPort[]
  sshKeys: SshKey[]
  extensions: BrowserExtension[]
  score: number
}

// ---------------------------------------------------------------- Parsers (tested with real output)

export function fileVault(out: string): Check {
  const on = /FileVault is On/i.test(out)
  return { id: 'filevault', title: 'Disk encryption (FileVault)', status: on ? 'ok' : 'bad', detail: on ? 'Your disk is encrypted: a lost or stolen Mac does not give away your files.' : 'Your disk is not encrypted. Anyone with the Mac can read your files, keys and passwords.', fix: on ? undefined : 'System Settings, Privacy & Security, FileVault, Turn On.' }
}

export function firewall(global: string, stealth: string): Check {
  const on = /enabled|State = [12]/i.test(global) && !/disabled/i.test(global)
  const st = /stealth mode enabled|is on/i.test(stealth) && !/disabled|is off/i.test(stealth)
  return { id: 'firewall', title: 'Firewall', status: on ? (st ? 'ok' : 'warn') : 'warn', detail: on ? (st ? 'On, in stealth mode: the Mac does not answer probes from the network.' : 'On, but not in stealth mode, so the Mac answers pings and probes.') : 'Off: apps can accept connections from your network without asking.', fix: on && st ? undefined : 'System Settings, Network, Firewall: turn it on, then Options, Enable stealth mode.' }
}

export function gatekeeper(out: string): Check {
  const on = /assessments enabled/i.test(out)
  return { id: 'gatekeeper', title: 'Gatekeeper', status: on ? 'ok' : 'bad', detail: on ? 'Apps from unknown developers are checked before they open.' : 'Gatekeeper is off: any downloaded app opens without checks.', fix: on ? undefined : 'In Terminal: sudo spctl --master-enable' }
}

export function sip(out: string): Check {
  const on = /status: enabled/i.test(out)
  return { id: 'sip', title: 'System Integrity Protection', status: on ? 'ok' : 'bad', detail: on ? 'macOS protects its own files, even from administrators.' : 'System Integrity Protection is off, so malware with admin rights can change macOS itself.', fix: on ? undefined : 'Restart into Recovery, open Terminal and run csrutil enable.' }
}

export function autoUpdates(installMacOS: string, critical: string): Check {
  const os = installMacOS.trim() === '1'
  const sec = critical.trim() !== '0'
  return { id: 'updates', title: 'Automatic security updates', status: os && sec ? 'ok' : sec ? 'warn' : 'bad', detail: sec ? (os ? 'macOS updates and security responses install on their own.' : 'Security responses install on their own; macOS updates wait for you.') : 'Security responses do not install on their own.', fix: os && sec ? undefined : 'System Settings, General, Software Update, Automatic updates (i): turn on "Install Security Responses and system files" and "Install macOS updates".' }
}

/** `lsof -nP -iTCP -sTCP:LISTEN`: programs waiting for connections. */
export function parseLsof(out: string): ListeningPort[] {
  const seen = new Set<string>()
  const ports: ListeningPort[] = []
  for (const line of out.split('\n').slice(1)) {
    const p = line.trim().split(/\s+/)
    if (p.length < 9) continue
    const name = p[p.length - 2] === '(LISTEN)' ? p[p.length - 3] : p[p.length - 1] === '(LISTEN)' ? p[p.length - 2] : p[p.length - 1]
    const m = /^(.*):(\d+)$/.exec(name)
    if (!m) continue
    const address = m[1]
    const port = Number(m[2])
    const key = `${p[0]}|${port}|${address}`
    if (seen.has(key)) continue
    seen.add(key)
    ports.push({ command: p[0].replace(/\\x20/g, ' '), pid: Number(p[1]), address, port, everyone: address === '*' || address === '0.0.0.0' || address === '[::]' })
  }
  return ports.sort((a, b) => Number(b.everyone) - Number(a.everyone) || a.port - b.port)
}

/** Whether a private key file is protected by a passphrase, from its header only. */
export function sshKeyProtected(text: string): boolean | null {
  if (/Proc-Type: 4,ENCRYPTED|BEGIN ENCRYPTED PRIVATE KEY/.test(text)) return true
  if (/BEGIN (RSA|EC|DSA) PRIVATE KEY|BEGIN PRIVATE KEY/.test(text)) return false
  const m = /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]+?)-----END OPENSSH PRIVATE KEY-----/.exec(text)
  if (!m) return null
  const head = Buffer.from(m[1].replace(/\s+/g, ''), 'base64').subarray(0, 64)
  // openssh-key-v1\0, then the cipher name as a length-prefixed string: "none" means no passphrase.
  const magic = 'openssh-key-v1\0'
  if (head.subarray(0, magic.length).toString('latin1') !== magic) return null
  const len = head.readUInt32BE(magic.length)
  return head.subarray(magic.length + 4, magic.length + 4 + len).toString('latin1') !== 'none'
}

const RISKY = ['<all_urls>', 'webRequest', 'webRequestBlocking', 'cookies', 'debugger', 'nativeMessaging', 'history', 'clipboardRead', 'proxy', 'management', 'declarativeNetRequestWithHostAccess', 'scripting', 'privacy', 'downloads']

/** What a browser extension may do that deserves a second look. */
export function extensionRisk(manifest: { permissions?: unknown[]; host_permissions?: unknown[]; content_scripts?: { matches?: string[] }[] }): string[] {
  const perms = [...(manifest.permissions ?? []), ...(manifest.host_permissions ?? [])].filter((p): p is string => typeof p === 'string')
  const out = perms.filter((p) => RISKY.includes(p))
  if (perms.some((p) => /^(\*|https?):\/\/\*\/\*$|^\*:\/\/\*\//.test(p)) || (manifest.content_scripts ?? []).some((c) => (c.matches ?? []).some((m) => m === '<all_urls>' || /^\*:\/\/\*\//.test(m)))) out.push('reads every site')
  return [...new Set(out.map((p) => (p === '<all_urls>' ? 'reads every site' : p)))]
}

/** A login item's program, from its launchd plist (as JSON from plutil). */
export function launchProgram(plist: { Program?: string; ProgramArguments?: string[]; Label?: string; BundleProgram?: string }): string | null {
  return plist.Program ?? plist.ProgramArguments?.[0] ?? plist.BundleProgram ?? null
}

/** `codesign -dv` output (stderr): who signed it. */
export function signerOf(out: string): string | null {
  const team = /TeamIdentifier=(\S+)/.exec(out)?.[1]
  const auth = /Authority=(.+)/.exec(out)?.[1]?.trim()
  if (/code object is not signed/i.test(out)) return null
  if (auth) return team && team !== 'not set' ? `${auth} (${team})` : auth
  if (/Signature=adhoc/.test(out)) return 'ad-hoc (no developer)'
  return null
}

// ---------------------------------------------------------------- Running it

function run(cmd: string, args: string[], timeout = 15000): Promise<string> {
  return new Promise((resolve) => execFile(cmd, args, { timeout, maxBuffer: 8 * 1024 * 1024 }, (_e, out, err) => resolve(`${String(out)}${String(err)}`)))
}

const list = (dir: string): string[] => {
  try {
    return readdirSync(dir)
  } catch {
    return []
  }
}

async function loginItems(): Promise<LoginItem[]> {
  const out: LoginItem[] = []
  const where: [string, LoginItem['where']][] = [
    [join(homedir(), 'Library', 'LaunchAgents'), 'you'],
    ['/Library/LaunchAgents', 'all users'],
    ['/Library/LaunchDaemons', 'system-wide daemon']
  ]
  for (const [dir, w] of where) {
    for (const f of list(dir).filter((n) => n.endsWith('.plist')).slice(0, 200)) {
      const path = join(dir, f)
      let plist: Parameters<typeof launchProgram>[0] = {}
      try {
        plist = JSON.parse(await run('/usr/bin/plutil', ['-convert', 'json', '-o', '-', path], 5000))
      } catch {
        plist = {}
      }
      const program = launchProgram(plist)
      let signer: string | null = null
      let status: CheckStatus = 'info'
      let note = ''
      if (!program) note = 'No program listed.'
      else if (!existsSync(program)) {
        status = 'warn'
        note = 'Its program is missing: a leftover from something you removed.'
      } else {
        signer = signerOf(await run('/usr/bin/codesign', ['-dv', '--verbose=2', program], 8000))
        if (!signer) {
          status = 'warn'
          note = 'Not signed by a developer. Make sure you know what it is.'
        } else if (/adhoc|ad-hoc/.test(signer)) {
          status = 'warn'
          note = 'Signed ad hoc, without an identified developer.'
        } else {
          status = 'ok'
          note = signer
        }
      }
      out.push({ plist: path, label: plist.Label ?? f.replace(/\.plist$/, ''), program, where: w, signer, status, note })
    }
  }
  return out
}

function sshKeys(): SshKey[] {
  const dir = join(homedir(), '.ssh')
  const out: SshKey[] = []
  for (const f of list(dir)) {
    const path = join(dir, f)
    if (f.endsWith('.pub') || ['known_hosts', 'known_hosts.old', 'config', 'authorized_keys'].includes(f)) continue
    let st
    try {
      st = statSync(path)
    } catch {
      continue
    }
    if (!st.isFile() || st.size > 64 * 1024) continue
    let head = ''
    try {
      // Only the header matters; the key itself is never stored or shown.
      head = readFileSync(path, 'utf8').slice(0, 4000)
    } catch {
      continue
    }
    if (!/PRIVATE KEY/.test(head)) continue
    const kind = /BEGIN (RSA|EC|DSA|OPENSSH|ENCRYPTED)? ?PRIVATE KEY/.exec(head)?.[1] ?? 'private'
    out.push({ file: `~/.ssh/${f}`, kind, protectedByPassphrase: sshKeyProtected(head), permissionsOk: (st.mode & 0o077) === 0 })
  }
  return out
}

function extensions(): BrowserExtension[] {
  const base = join(homedir(), 'Library', 'Application Support')
  const browsers: [string, string][] = [
    ['Chrome', join(base, 'Google', 'Chrome')],
    ['Brave', join(base, 'BraveSoftware', 'Brave-Browser')],
    ['Edge', join(base, 'Microsoft Edge')],
    ['Arc', join(base, 'Arc', 'User Data')],
    ['Vivaldi', join(base, 'Vivaldi')]
  ]
  const out: BrowserExtension[] = []
  for (const [browser, root] of browsers) {
    for (const profile of list(root).filter((p) => p === 'Default' || /^Profile \d+$/.test(p))) {
      const extDir = join(root, profile, 'Extensions')
      for (const id of list(extDir)) {
        const version = list(join(extDir, id)).sort().pop()
        if (!version) continue
        const dir = join(extDir, id, version)
        try {
          const m = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8')) as { name?: string; version?: string; default_locale?: string; permissions?: unknown[]; host_permissions?: unknown[] }
          let name = m.name ?? id
          const msg = /^__MSG_(.+)__$/.exec(name)?.[1]
          if (msg) {
            try {
              const loc = JSON.parse(readFileSync(join(dir, '_locales', m.default_locale ?? 'en', 'messages.json'), 'utf8')) as Record<string, { message: string }>
              name = Object.entries(loc).find(([k]) => k.toLowerCase() === msg.toLowerCase())?.[1].message ?? name
            } catch {
              // Keep the raw name.
            }
          }
          // Chrome's own components are not extensions you installed.
          if (/^(Chrome|Google) (Web Store|Docs Offline)|^Chrome PDF/.test(name)) continue
          if (!out.some((e) => e.browser === browser && e.id === id)) out.push({ browser, id, name, version: m.version ?? version, risky: extensionRisk(m as never) })
        } catch {
          // Not readable; skip it.
        }
      }
    }
  }
  return out.sort((a, b) => b.risky.length - a.risky.length || a.name.localeCompare(b.name))
}

export function scoreOf(r: Omit<CheckupResult, 'score'>): number {
  let s = 100
  for (const c of r.checks) s -= c.status === 'bad' ? 20 : c.status === 'warn' ? 7 : 0
  s -= Math.min(15, r.loginItems.filter((l) => l.status === 'warn').length * 3)
  s -= Math.min(15, r.sshKeys.filter((k) => k.protectedByPassphrase === false || !k.permissionsOk).length * 5)
  s -= Math.min(10, r.ports.filter((p) => p.everyone).length * 2)
  s -= Math.min(10, r.extensions.filter((e) => e.risky.includes('reads every site')).length * 2)
  return Math.max(0, Math.round(s))
}

export async function runCheckup(): Promise<CheckupResult> {
  const [fv, fwG, fwS, gk, sp, upOs, upCrit, ver, lsof, items] = await Promise.all([
    run('/usr/bin/fdesetup', ['status']),
    run('/usr/libexec/ApplicationFirewall/socketfilterfw', ['--getglobalstate']),
    run('/usr/libexec/ApplicationFirewall/socketfilterfw', ['--getstealthmode']),
    run('/usr/sbin/spctl', ['--status']),
    run('/usr/bin/csrutil', ['status']),
    run('/usr/bin/defaults', ['read', '/Library/Preferences/com.apple.SoftwareUpdate', 'AutomaticallyInstallMacOSUpdates']),
    run('/usr/bin/defaults', ['read', '/Library/Preferences/com.apple.SoftwareUpdate', 'CriticalUpdateInstall']),
    run('/usr/bin/sw_vers', ['-productVersion']),
    run('/usr/sbin/lsof', ['-nP', '-iTCP', '-sTCP:LISTEN'], 20000),
    loginItems()
  ])
  const keys = sshKeys()
  const ext = extensions()
  const ports = parseLsof(lsof)
  const checks: Check[] = [fileVault(fv), firewall(fwG, fwS), gatekeeper(gk), sip(sp), autoUpdates(/does not exist/.test(upOs) ? '1' : upOs, /does not exist/.test(upCrit) ? '1' : upCrit)]
  const open = ports.filter((p) => p.everyone)
  checks.push({ id: 'ports', title: 'Programs reachable from your network', status: open.length ? 'warn' : 'ok', detail: open.length ? `${open.length} listen on every network address: ${[...new Set(open.map((p) => `${p.command} (${p.port})`))].slice(0, 8).join(', ')}.` : 'Nothing listens on your network, only on this Mac.', fix: open.length ? 'Turn off sharing you do not use (System Settings, General, Sharing), and bind development servers to 127.0.0.1.' : undefined })
  const weakKeys = keys.filter((k) => k.protectedByPassphrase === false)
  checks.push({ id: 'ssh', title: 'SSH keys', status: keys.some((k) => !k.permissionsOk) ? 'bad' : weakKeys.length ? 'warn' : 'ok', detail: keys.length ? `${keys.length} private ${keys.length === 1 ? 'key' : 'keys'}${weakKeys.length ? `, ${weakKeys.length} without a passphrase` : ''}${keys.some((k) => !k.permissionsOk) ? ', some readable by other users' : ''}.` : 'No private keys in ~/.ssh.', fix: weakKeys.length || keys.some((k) => !k.permissionsOk) ? 'Add a passphrase with ssh-keygen -p -f <key> (macOS can keep it in the Keychain), and chmod 600 every private key.' : undefined })
  const everySite = ext.filter((e) => e.risky.includes('reads every site'))
  checks.push({ id: 'extensions', title: 'Browser extensions', status: everySite.length > 3 ? 'warn' : 'info', detail: ext.length ? `${ext.length} installed; ${everySite.length} can read every website you open.` : 'No extensions found in Chrome, Brave, Edge, Arc or Vivaldi.', fix: everySite.length ? 'Remove the ones you do not use: an extension that reads every site sees your passwords and sessions.' : undefined })
  const unknown = items.filter((i) => i.status === 'warn')
  checks.push({ id: 'login', title: 'Programs that start on their own', status: unknown.length ? 'warn' : 'ok', detail: `${items.length} launch agents and daemons${unknown.length ? `, ${unknown.length} unsigned or pointing at missing programs` : ', all signed'}. Malware often hides here.`, fix: unknown.length ? 'Look at each one marked below. If you do not recognise it, search its name before removing it.' : undefined })
  const base = { at: new Date().toISOString(), macos: ver.trim(), checks, loginItems: items, ports, sshKeys: keys, extensions: ext }
  return { ...base, score: scoreOf(base) }
}
