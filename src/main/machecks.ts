/**
 * More checks for This Mac. Every one only reads: a setting through Apple's own tools, a file you
 * can already read, or the list of ports from the check-up. Nothing is changed. Each answer says
 * what it found and, when something needs attention, how you can fix it yourself in System Settings.
 */
import { execFile } from 'child_process'
import { readFileSync, statSync } from 'fs'
import type { Check, ListeningPort } from './checkup'

const missing = (out: string): boolean => /does not exist|No such file|not found|error/i.test(out) && !/^\s*\d/.test(out)

export function screenLock(out: string): Check {
  const text = out.trim()
  const off = /\boff\b|disabled|never/i.test(text)
  const known = /immediate|\d+\s*(second|minute|hour)|\boff\b|disabled|never/i.test(text)
  if (!known) return { id: 'screenlock', title: 'Password after the screen locks', status: 'info', detail: 'MacSec could not read this setting. Check it in System Settings, Lock Screen.' }
  return { id: 'screenlock', title: 'Password after the screen locks', status: off ? 'bad' : /immediate|\b([0-9]|1[0-5])\s*(second|minute)/i.test(text) ? 'ok' : 'warn', detail: off ? 'No password is asked when the screen locks or the Mac sleeps. Anyone who opens the lid is in.' : `A password is asked (${text.replace(/^.*screenLock\s*/i, '').trim() || 'after the screen locks'}).`, fix: off ? 'System Settings, Lock Screen: "Require password after screen saver begins or display is turned off" set to Immediately.' : undefined }
}

export function guestAccount(out: string): Check {
  const on = out.trim() === '1'
  return { id: 'guest', title: 'Guest account', status: on ? 'warn' : 'ok', detail: on ? 'The guest user is on, so anyone can sit down and use the Mac without a password.' : 'The guest user is off.', fix: on ? 'System Settings, Users & Groups, Guest User: turn it off.' : undefined }
}

export function autoLogin(out: string): Check {
  const user = out.trim()
  const on = !!user && !missing(out)
  return { id: 'autologin', title: 'Automatic login', status: on ? 'bad' : 'ok', detail: on ? `The Mac logs in as ${user} by itself at start-up, without asking for a password.` : 'You have to type your password to log in.', fix: on ? 'System Settings, Users & Groups: set "Automatically log in as" to Off.' : undefined }
}

export function airdrop(out: string): Check {
  const v = out.trim()
  const everyone = /everyone/i.test(v)
  return { id: 'airdrop', title: 'AirDrop visibility', status: everyone ? 'warn' : 'ok', detail: everyone ? 'AirDrop is open to Everyone, so strangers nearby can see this Mac and send files to it.' : /off/i.test(v) ? 'AirDrop is off.' : 'AirDrop only shows this Mac to your contacts.', fix: everyone ? 'Finder, AirDrop (or Control Centre): choose "Contacts Only" or "No One".' : undefined }
}

export function findMy(nvram: string): Check {
  const on = /^fmm-mobileme-token-FMM/m.test(nvram)
  return { id: 'findmy', title: 'Find My Mac', status: on ? 'ok' : 'warn', detail: on ? 'Find My is on: you can locate, lock or wipe a lost Mac.' : 'Find My Mac does not look switched on, so a lost or stolen Mac cannot be located or locked remotely.', fix: on ? undefined : 'System Settings, your name, iCloud, Find My Mac: turn it on.' }
}

export function timeMachine(out: string): Check {
  const none = /No destinations configured/i.test(out)
  const unknown = !none && !/Name\s*:/.test(out)
  if (unknown) return { id: 'backup', title: 'Backups (Time Machine)', status: 'info', detail: 'MacSec could not read the backup setting. If you use another backup tool, that is fine.' }
  return { id: 'backup', title: 'Backups (Time Machine)', status: none ? 'warn' : 'ok', detail: none ? 'No Time Machine disk is set up. If your files are lost or locked by ransomware, there is nothing to restore from (unless you use another backup).' : 'A backup disk is set up.', fix: none ? 'System Settings, General, Time Machine: add a backup disk. Or use an online backup you trust.' : undefined }
}

/** `scutil --proxy`: a proxy you did not set up sends your web traffic somewhere else. */
export function proxies(out: string): Check {
  const found: string[] = []
  const on = (key: string): boolean => new RegExp(`${key}\\s*:\\s*1`).test(out)
  const val = (key: string): string => new RegExp(`${key}\\s*:\\s*(\\S+)`).exec(out)?.[1] ?? ''
  if (on('HTTPEnable')) found.push(`web proxy ${val('HTTPProxy')}:${val('HTTPPort')}`)
  if (on('HTTPSEnable')) found.push(`secure web proxy ${val('HTTPSProxy')}:${val('HTTPSPort')}`)
  if (on('SOCKSEnable')) found.push(`SOCKS proxy ${val('SOCKSProxy')}:${val('SOCKSPort')}`)
  if (on('ProxyAutoConfigEnable')) found.push(`automatic proxy file ${val('ProxyAutoConfigURLString')}`)
  return { id: 'proxy', title: 'Network proxy', status: found.length ? 'warn' : 'ok', detail: found.length ? `Your web traffic goes through: ${found.join('; ')}. That is normal for a work network or a tool you installed, and a way for malware to watch traffic if you do not know it.` : 'No proxy is set: your traffic goes straight out.', fix: found.length ? 'System Settings, Network, your connection, Details, Proxies. Remove any you do not recognise.' : undefined }
}

/** /etc/hosts: lines that point real websites somewhere else. */
export function hostsFile(text: string): Check {
  const odd: string[] = []
  for (const raw of text.split('\n')) {
    const line = raw.replace(/#.*/, '').trim()
    if (!line) continue
    const [ip, ...names] = line.split(/\s+/)
    for (const n of names) {
      if (/^(localhost|broadcasthost|ip6-localhost|ip6-loopback|local|kubernetes\.docker\.internal|host\.docker\.internal|gateway\.docker\.internal)$/i.test(n)) continue
      // Development sites that point at this Mac are normal.
      if ((ip === '127.0.0.1' || ip === '::1') && /\.(test|local|localhost|dev|lan)$/i.test(n)) continue
      if (ip === '0.0.0.0' || ip === '127.0.0.1') continue // blocking an address
      odd.push(`${n} → ${ip}`)
    }
  }
  return { id: 'hosts', title: 'Hosts file', status: odd.length ? 'warn' : 'ok', detail: odd.length ? `${odd.length} ${odd.length === 1 ? 'name points' : 'names point'} to another address: ${odd.slice(0, 6).join(', ')}. Malware uses this to send you to fake sites.` : 'Nothing in the hosts file sends a website somewhere unexpected.', fix: odd.length ? 'If you did not add these, edit /etc/hosts (needs your password) and remove them.' : undefined }
}

/** `security dump-trust-settings`: certificates you chose to trust. A wrong one lets someone read your secure traffic. */
export function trustedCerts(user: string, admin: string): Check {
  const count = (s: string): number => Number(/Number of trusted certs\s*=\s*(\d+)/i.exec(s)?.[1] ?? 0)
  const names = (s: string): string[] => [...s.matchAll(/Cert \d+:\s*(.+)/g)].map((m) => m[1].trim())
  const n = count(user) + count(admin)
  const list = [...names(user), ...names(admin)]
  return { id: 'certs', title: 'Extra trusted certificates', status: n ? 'info' : 'ok', detail: n ? `${n} certificate${n === 1 ? ' was' : 's were'} added to your trust settings: ${list.slice(0, 5).join(', ')}${n > 5 ? ' and more' : ''}. Development tools and work networks add these. A certificate you do not know lets someone read your secure traffic.` : 'You added no extra trusted certificates.', fix: n ? 'Keychain Access, open each one, and remove the ones you do not recognise.' : undefined }
}

export function mdm(out: string): Check {
  const on = /MDM enrollment:\s*Yes/i.test(out)
  const dep = /Enrolled via DEP:\s*Yes/i.test(out)
  return { id: 'mdm', title: 'Managed by an organisation', status: 'info', detail: on || dep ? 'This Mac is managed by an organisation (device management). Its administrators can see and change settings on it.' : 'This Mac is not enrolled in any device management.' }
}

export function lastUpdateCheck(out: string, now = Date.now()): Check {
  const m = /(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})/.exec(out)
  if (!m) return { id: 'updatecheck', title: 'Last software update check', status: 'info', detail: 'macOS has not recorded when it last looked for updates.' }
  const days = Math.floor((now - new Date(`${m[1]}T${m[2]}Z`).getTime()) / 86_400_000)
  return { id: 'updatecheck', title: 'Last software update check', status: days > 30 ? 'bad' : days > 10 ? 'warn' : 'ok', detail: days <= 0 ? 'macOS looked for updates today.' : `macOS last looked for updates ${days} ${days === 1 ? 'day' : 'days'} ago.`, fix: days > 10 ? 'System Settings, General, Software Update: check now and install what it finds.' : undefined }
}

const SHARING: { ports: number[]; name: string }[] = [
  { ports: [22], name: 'Remote Login (SSH)' },
  { ports: [5900, 3283], name: 'Screen Sharing or Remote Management' },
  { ports: [445, 548], name: 'File Sharing' },
  { ports: [631], name: 'Printer Sharing' },
  { ports: [3689], name: 'Media Sharing' },
  { ports: [88], name: 'Kerberos' }
]
const OPEN_SERVICES: { port: number; name: string; bad: boolean }[] = [
  { port: 2375, name: 'Docker without a password', bad: true },
  { port: 3306, name: 'MySQL or MariaDB', bad: false },
  { port: 5432, name: 'PostgreSQL', bad: false },
  { port: 6379, name: 'Redis', bad: true },
  { port: 27017, name: 'MongoDB', bad: true },
  { port: 9200, name: 'Elasticsearch', bad: true },
  { port: 11211, name: 'Memcached', bad: true }
]

/** Sharing switched on, worked out from what listens on the network. */
export function sharingFrom(ports: ListeningPort[]): Check {
  const open = (p: number): boolean => ports.some((x) => x.port === p && x.everyone)
  const on = SHARING.filter((s) => s.ports.some(open)).map((s) => s.name)
  return { id: 'sharing', title: 'Sharing services', status: on.some((n) => /SSH|Screen/.test(n)) ? 'warn' : on.length ? 'info' : 'ok', detail: on.length ? `On: ${on.join(', ')}. Each one is a door into this Mac from your network.` : 'No sharing service answers from your network.', fix: on.length ? 'System Settings, General, Sharing: turn off what you do not use.' : undefined }
}

/** Databases and caches that answer to the whole network. Often meant for development, rarely safe. */
export function openServices(ports: ListeningPort[]): Check {
  const hits = OPEN_SERVICES.filter((s) => ports.some((p) => p.port === s.port && p.everyone))
  const worst = hits.some((h) => h.bad)
  return { id: 'openservices', title: 'Databases open to the network', status: hits.length ? (worst ? 'bad' : 'warn') : 'ok', detail: hits.length ? `${hits.map((h) => `${h.name} (port ${h.port})`).join(', ')} ${hits.length === 1 ? 'answers' : 'answer'} to everyone on your network. Most of these have no password by default.` : 'No database or cache answers to your network.', fix: hits.length ? 'Set the server to listen on 127.0.0.1 only (bind-address / listen_addresses), then restart it.' : undefined }
}

/** Folders in PATH that anyone can write to: a program there would run as you. */
export function pathDirs(path: string, stat: (p: string) => number | null = (p) => { try { return statSync(p).mode } catch { return null } }): Check {
  const bad = [...new Set(path.split(':').filter(Boolean))].filter((d) => {
    const m = stat(d)
    return m !== null && (m & 0o002) !== 0 && (m & 0o1000) === 0
  })
  return { id: 'pathdirs', title: 'Folders your commands run from', status: bad.length ? 'bad' : 'ok', detail: bad.length ? `Anyone on this Mac can add programs to: ${bad.join(', ')}. A planted program there runs as you.` : 'None of the folders on your PATH can be written to by other users.', fix: bad.length ? 'chmod go-w on each folder (and its parents), or remove it from PATH.' : undefined }
}

function run(cmd: string, args: string[], timeout = 8000): Promise<string> {
  return new Promise((resolve) => execFile(cmd, args, { timeout, maxBuffer: 4 * 1024 * 1024 }, (_e, out, err) => resolve(`${String(out)}${String(err)}`)))
}

/** All the extra checks, each grouped so the page reads in sections. */
export async function runMoreChecks(ports: ListeningPort[]): Promise<Check[]> {
  const [lock, guest, auto, drop, nvram, tm, prox, userTrust, adminTrust, enroll, upd] = await Promise.all([
    run('/usr/sbin/sysadminctl', ['-screenLock', 'status']),
    run('/usr/bin/defaults', ['read', '/Library/Preferences/com.apple.loginwindow', 'GuestEnabled']),
    run('/usr/bin/defaults', ['read', '/Library/Preferences/com.apple.loginwindow', 'autoLoginUser']),
    run('/usr/bin/defaults', ['read', 'com.apple.sharingd', 'DiscoverableMode']),
    run('/usr/sbin/nvram', ['-p']),
    run('/usr/bin/tmutil', ['destinationinfo']),
    run('/usr/sbin/scutil', ['--proxy']),
    run('/usr/bin/security', ['dump-trust-settings']),
    run('/usr/bin/security', ['dump-trust-settings', '-d']),
    run('/usr/bin/profiles', ['status', '-type', 'enrollment']),
    run('/usr/bin/defaults', ['read', '/Library/Preferences/com.apple.SoftwareUpdate', 'LastSuccessfulDate'])
  ])
  let hosts = ''
  try {
    hosts = readFileSync('/etc/hosts', 'utf8')
  } catch {
    hosts = ''
  }
  const g = (group: string, c: Check): Check => ({ ...c, group })
  return [
    g('Logging in and locking', screenLock(lock)),
    g('Logging in and locking', guestAccount(guest)),
    g('Logging in and locking', autoLogin(auto)),
    g('If the Mac is lost', findMy(nvram)),
    g('If the Mac is lost', timeMachine(tm)),
    g('Reachable from other devices', airdrop(drop)),
    g('Reachable from other devices', sharingFrom(ports)),
    g('Reachable from other devices', openServices(ports)),
    g('Where your traffic goes', proxies(prox)),
    g('Where your traffic goes', hostsFile(hosts)),
    g('Where your traffic goes', trustedCerts(userTrust, adminTrust)),
    g('Updates and management', lastUpdateCheck(upd)),
    g('Updates and management', mdm(enroll)),
    g('Programs and commands', pathDirs(process.env.PATH ?? ''))
  ]
}
