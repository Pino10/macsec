/**
 * Deeper checks for This Mac, in five new sections. Everything only reads: a setting through
 * Apple's own tools, a file this user can already read, or a list of names. Secrets are never
 * stored or shown: for a file that holds keys, MacSec records that it exists, what kind of key it
 * holds and who can read it, and nothing else. Each check says what it found and how to fix it.
 */
import { execFile } from 'child_process'
import { existsSync, lstatSync, readdirSync, readFileSync, statSync } from 'fs'
import { homedir } from 'os'
import { join } from 'path'
import type { Check } from './checkup'

type Group = 'Accounts and passwords' | 'Secrets left on this Mac' | 'Software on this Mac' | 'Network and Wi-Fi' | 'Programs and commands'
const g = (group: Group, c: Check): Check => ({ ...c, group })

// ---------------------------------------------------------------- Accounts and passwords

/** Whether the root account has a password set (and so can be signed in to). */
export function rootAccount(out: string): Check {
  const on = /ShadowHash|SecureToken|;Kerberosv5;/i.test(out) && !/No such key/i.test(out)
  return { id: 'rootaccount', title: 'The root account', status: on ? 'bad' : 'ok', detail: on ? 'The root account is switched on. It has full power and its password is a prize for anyone who guesses it.' : 'The root account is off, which is how macOS ships.', ...(on ? { fix: 'Open Directory Utility, choose Edit, then Disable Root User. Or run: dsenableroot -d' } : {}) }
}

/** The people who are administrators. Day-to-day use as an administrator makes every mistake and every bad download more powerful. */
export function adminAccounts(out: string, me = process.env.USER ?? ''): Check {
  const names = (/GroupMembership:\s*(.*)/.exec(out)?.[1] ?? '').split(/\s+/).filter((n) => n && n !== 'root')
  if (!names.length) return { id: 'admins', title: 'Administrator accounts', status: 'info', detail: 'MacSec could not read who the administrators are.' }
  const mineIsAdmin = names.includes(me)
  return { id: 'admins', title: 'Administrator accounts', status: names.length > 2 ? 'warn' : mineIsAdmin ? 'info' : 'ok', detail: `Administrators: ${names.join(', ')}.${mineIsAdmin ? ' You are one, so a bad download you open can change the whole Mac.' : ''}${names.length > 2 ? ' That is more than most Macs need.' : ''}`, ...(mineIsAdmin || names.length > 2 ? { fix: 'Use a standard account for daily work and keep one separate administrator account for installs. System Settings, Users and Groups.' } : {}) }
}

/** How long until the screen saver or sleep, in seconds, and whether a password is asked straight away. */
export function idleLock(idle: string, delay: string): Check {
  const n = Number.parseInt(idle.trim(), 10)
  if (!Number.isFinite(n)) return { id: 'idlelock', title: 'Screen saver and password delay', status: 'info', detail: 'MacSec could not read the screen saver delay. Check System Settings, Lock Screen.' }
  const d = Number.parseInt(delay.trim(), 10)
  const slow = n === 0 || n > 600
  const late = Number.isFinite(d) && d > 60
  return { id: 'idlelock', title: 'Screen saver and password delay', status: slow || late ? 'warn' : 'ok', detail: `${n === 0 ? 'The screen saver never starts' : `The screen saver starts after ${Math.round(n / 60)} min`}${Number.isFinite(d) ? `, and the password is asked ${d === 0 ? 'at once' : `after ${d} seconds`}` : ''}.`, ...(slow || late ? { fix: 'Start the screen saver within 5 minutes and ask for the password at once. System Settings, Lock Screen.' } : {}) }
}

/** The login window showing every user's name makes the account name easy to find. */
export function loginWindow(showFull: string): Check {
  const on = showFull.trim() === '1'
  return { id: 'loginwindow', title: 'Login window shows names', status: on ? 'info' : 'ok', detail: on ? 'The login window shows a name and password box, not a list of users. That is the safer layout.' : 'The login window shows a list of users, so a visitor learns the account names.', ...(on ? {} : { fix: 'System Settings, Lock Screen, set "Login window shows" to Name and password.' }) }
}

// ---------------------------------------------------------------- Secrets left on this Mac

export interface SecretFile {
  file: string
  kind: string
  /** Octal mode, for example 0600. */
  mode: number
}

const KEY_FILES: { rel: string; kind: string; re: RegExp }[] = [
  { rel: '.aws/credentials', kind: 'AWS access keys', re: /aws_secret_access_key\s*=/i },
  { rel: '.netrc', kind: 'a stored password (netrc)', re: /\bpassword\s+\S+/i },
  { rel: '.git-credentials', kind: 'Git passwords in plain text', re: /https?:\/\/[^\s:@]+:[^\s@]+@/ },
  { rel: '.npmrc', kind: 'an npm token', re: /_authToken\s*=\s*\S+/ },
  { rel: '.pypirc', kind: 'a PyPI password or token', re: /(password|token)\s*[:=]\s*\S+/i },
  { rel: '.docker/config.json', kind: 'a Docker registry login', re: /"auth"\s*:\s*"[A-Za-z0-9+/=]{8,}"/ },
  { rel: '.kube/config', kind: 'a Kubernetes token or key', re: /(token|client-key-data):\s*\S+/ },
  { rel: '.config/gh/hosts.yml', kind: 'a GitHub token', re: /oauth_token:\s*\S+/ },
  { rel: '.azure/accessTokens.json', kind: 'an Azure token', re: /accessToken/ }
]

/** Which known credential files hold a secret. Only the file name and kind are kept, never the value. */
export function secretFiles(read: (rel: string) => { text: string; mode: number } | null): SecretFile[] {
  const out: SecretFile[] = []
  for (const k of KEY_FILES) {
    const f = read(k.rel)
    if (f && k.re.test(f.text)) out.push({ file: `~/${k.rel}`, kind: k.kind, mode: f.mode & 0o777 })
  }
  return out
}

export function secretFilesCheck(files: SecretFile[]): Check {
  if (!files.length) return { id: 'secretfiles', title: 'Passwords and keys in plain files', status: 'ok', detail: 'None of the usual credential files (AWS, netrc, Git, npm, Docker, Kubernetes, GitHub) hold a plain-text secret.' }
  const open = files.filter((f) => (f.mode & 0o077) !== 0)
  return { id: 'secretfiles', title: 'Passwords and keys in plain files', status: open.length ? 'bad' : 'warn', detail: `${files.map((f) => `${f.file} (${f.kind}${(f.mode & 0o077) !== 0 ? ', readable by other users' : ''})`).join('; ')}. MacSec did not read the values.`, fix: `${open.length ? 'Run chmod 600 on them. ' : ''}Prefer a login that does not leave a key on disk: AWS SSO, the macOS Keychain credential helper for Git, and short-lived tokens. Rotate anything you are unsure about.` }
}

const HISTORY_SECRETS: { kind: string; re: RegExp }[] = [
  { kind: 'an AWS access key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { kind: 'a GitHub token', re: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/ },
  { kind: 'an API key (sk-)', re: /\bsk-[A-Za-z0-9_-]{24,}\b/ },
  { kind: 'a Slack token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
  { kind: 'a password on a command line', re: /\b(curl|mysql|psql|sshpass|wget)\b[^\n]*(\s-u\s+\S+:\S+|\s-p\S{4,}|--password[= ]\S+|sshpass\s+-p\s*\S+)/i },
  { kind: 'a bearer token', re: /Authorization:\s*Bearer\s+[A-Za-z0-9._~+/=-]{20,}/i },
  { kind: 'a password set in a variable', re: /\b(export\s+)?[A-Z_]*(PASSWORD|SECRET|TOKEN|API_KEY)[A-Z_]*=\S{6,}/ }
]

/** Secrets typed into a terminal and kept in the history. Only the kinds and how many lines. */
export function historySecrets(text: string): { kind: string; lines: number }[] {
  const out = new Map<string, number>()
  for (const line of text.split('\n').slice(-8000)) for (const s of HISTORY_SECRETS) if (s.re.test(line)) out.set(s.kind, (out.get(s.kind) ?? 0) + 1)
  return [...out].map(([kind, lines]) => ({ kind, lines }))
}

export function historyCheck(hits: { kind: string; lines: number }[]): Check {
  if (!hits.length) return { id: 'history', title: 'Secrets in your shell history', status: 'ok', detail: 'No keys, tokens or passwords were found in the last 8,000 commands.' }
  return { id: 'history', title: 'Secrets in your shell history', status: 'warn', detail: `Your command history holds ${hits.map((h) => `${h.kind} (${h.lines} ${h.lines === 1 ? 'line' : 'lines'})`).join(', ')}. MacSec did not keep the values.`, fix: 'Rotate those secrets, then clear the lines (edit ~/.zsh_history). Put secrets in environment files or the Keychain, and start a command with a space (with HIST_IGNORE_SPACE) to keep it out of the history.' }
}

export function envFilesCheck(found: { file: string; mode: number }[]): Check {
  if (!found.length) return { id: 'envfiles', title: '.env files in your projects', status: 'ok', detail: 'No .env files were found in the usual project folders.' }
  const open = found.filter((f) => (f.mode & 0o004) !== 0)
  return { id: 'envfiles', title: '.env files in your projects', status: open.length ? 'warn' : 'info', detail: `${found.length} .env ${found.length === 1 ? 'file' : 'files'} in your projects${open.length ? `, ${open.length} readable by every user: ${open.slice(0, 3).map((f) => f.file).join(', ')}` : ''}. Values were not read.`, ...(open.length ? { fix: 'Run chmod 600 on them, and make sure none is committed to Git or placed in a web folder.' } : {}) }
}

// ---------------------------------------------------------------- Software on this Mac

/** XProtect is Apple's malware list. An old one means automatic security updates are not arriving. */
export function xprotectAge(mtimeMs: number | null, now = Date.now()): Check {
  if (mtimeMs === null) return { id: 'xprotect', title: 'Apple’s malware definitions (XProtect)', status: 'info', detail: 'MacSec could not find the XProtect files.' }
  const days = Math.floor((now - mtimeMs) / 86_400_000)
  return { id: 'xprotect', title: 'Apple’s malware definitions (XProtect)', status: days > 60 ? 'bad' : days > 21 ? 'warn' : 'ok', detail: `Updated ${days <= 0 ? 'today' : `${days} ${days === 1 ? 'day' : 'days'} ago`}.${days > 21 ? ' These normally refresh every week or two.' : ''}`, ...(days > 21 ? { fix: 'System Settings, General, Software Update: turn on "Install Security Responses and system files".' } : {}) }
}

/** Kernel and system extensions that are not Apple's. Each one runs with deep access. */
export function thirdPartyExtensions(kexts: string, sysext: string): Check {
  const k = kexts.split('\n').filter((l) => /^\s*\d+\s/.test(l) && !/com\.apple\./.test(l)).map((l) => /\(([^)]+)\)|(\S+\.\S+)\s+\(/.exec(l)?.[1] ?? l.trim().split(/\s+/)[5] ?? '').filter(Boolean)
  const s = sysext.split('\n').filter((l) => /\[activated enabled\]/.test(l) && !/com\.apple\./.test(l)).map((l) => l.trim().split(/\s+/).find((x) => /\w+\.\w+\./.test(x)) ?? '').filter(Boolean)
  const all = [...new Set([...k, ...s])]
  if (!all.length) return { id: 'extensions3p', title: 'Kernel and system extensions', status: 'ok', detail: 'No extensions from other companies are loaded.' }
  return { id: 'extensions3p', title: 'Kernel and system extensions', status: 'info', detail: `${all.length} from other companies: ${all.slice(0, 6).join(', ')}${all.length > 6 ? ', and more' : ''}. Normal for VPNs, antivirus and virtual machines: check that you know each one.` }
}

/** Apps in /Applications that macOS would refuse to open (not signed or not notarized). */
export function rejectedApps(names: string[]): Check {
  if (!names.length) return { id: 'unsignedapps', title: 'Apps macOS does not trust', status: 'ok', detail: 'Every app checked passes Gatekeeper.' }
  return { id: 'unsignedapps', title: 'Apps macOS does not trust', status: 'warn', detail: `${names.length} ${names.length === 1 ? 'app is' : 'apps are'} not signed and approved by Apple: ${names.slice(0, 6).join(', ')}${names.length > 6 ? ', and more' : ''}.`, fix: 'Keep only the ones you know come from their makers. Delete the rest.' }
}

export function brewOutdated(out: string | null): Check {
  if (out === null) return { id: 'brew', title: 'Homebrew packages', status: 'info', detail: 'Homebrew is not installed here.' }
  const n = out.split('\n').filter((l) => l.trim()).length
  return { id: 'brew', title: 'Homebrew packages', status: n > 25 ? 'warn' : 'ok', detail: n ? `${n} ${n === 1 ? 'package has' : 'packages have'} a newer version.${n > 25 ? ' Old tools often carry known flaws.' : ''}` : 'Every Homebrew package is up to date.', ...(n > 25 ? { fix: 'Run: brew update && brew upgrade' } : {}) }
}

/** The sshd settings, which matter only when Remote Login is on. */
export function sshdConfig(text: string, remoteLoginOn: boolean): Check {
  const val = (k: string): string | null => {
    let v: string | null = null
    for (const l of text.split('\n')) {
      const m = new RegExp(`^\\s*${k}\\s+(\\S+)`, 'i').exec(l)
      if (m) v ??= m[1].toLowerCase()
    }
    return v
  }
  const root = val('PermitRootLogin')
  const pw = val('PasswordAuthentication')
  const bad: string[] = []
  if (root === 'yes') bad.push('root can sign in over SSH')
  if (pw !== 'no') bad.push('passwords are accepted, not only keys')
  if (!remoteLoginOn) return { id: 'sshd', title: 'SSH server settings', status: 'ok', detail: 'Remote Login is off, so nobody can reach SSH on this Mac.' }
  return { id: 'sshd', title: 'SSH server settings', status: root === 'yes' ? 'bad' : bad.length ? 'warn' : 'ok', detail: bad.length ? `Remote Login is on and ${bad.join(' and ')}.` : 'Remote Login is on, with root sign-in refused and keys only.', ...(bad.length ? { fix: 'Set PermitRootLogin no and PasswordAuthentication no in /etc/ssh/sshd_config.d/100-hardening.conf, or turn Remote Login off if you do not use it.' } : {}) }
}

export function cronJobs(out: string): Check {
  const jobs = out.split('\n').filter((l) => l.trim() && !l.trim().startsWith('#') && !/no crontab/i.test(l))
  return { id: 'cron', title: 'Scheduled jobs (cron)', status: jobs.length ? 'info' : 'ok', detail: jobs.length ? `${jobs.length} ${jobs.length === 1 ? 'job runs' : 'jobs run'} on a schedule: ${jobs.slice(0, 3).map((j) => j.trim().slice(0, 60)).join('; ')}. Malware often hides here: check that you know each one.` : 'You have no cron jobs.' }
}

// ---------------------------------------------------------------- Network and Wi-Fi

/** The security of the Wi-Fi network this Mac is on, from system_profiler. */
export function wifiSecurity(out: string): Check {
  const cur = /Current Network Information:\s*\n\s*([^\n:]+):\s*\n([\s\S]*?)(?:\n\s*\n|$)/.exec(out)
  if (!cur) return { id: 'wifi', title: 'Wi-Fi security', status: 'info', detail: 'This Mac is not on a Wi-Fi network right now.' }
  const name = cur[1].trim()
  const sec = /Security:\s*(.+)/.exec(cur[2])?.[1].trim() ?? ''
  const weak = /None|Open|WEP|^WPA Personal$|WPA Enterprise$/i.test(sec) && !/WPA2|WPA3/i.test(sec)
  return { id: 'wifi', title: 'Wi-Fi security', status: /None|Open/i.test(sec) ? 'bad' : weak ? 'warn' : 'ok', detail: `“${name}” uses ${sec || 'an unknown'} security.${weak ? ' That is open or outdated: others nearby can read or change your traffic.' : ''}`, ...(weak ? { fix: 'Join a WPA2 or WPA3 network, or turn on a VPN. If it is your router, change it to WPA3 or WPA2/WPA3.' } : {}) }
}

/** Wi-Fi networks the Mac remembers that have no password. They join by themselves and can be copied by anyone. */
export function savedOpenWifi(out: string): Check {
  const names = out.split('\n').slice(1).map((l) => l.trim()).filter(Boolean)
  const risky = names.filter((n) => /^(free|public|guest|open|airport|hotel|wifi|xfinitywifi|attwifi|starbucks|mcdonald)/i.test(n))
  return { id: 'savedwifi', title: 'Remembered Wi-Fi networks', status: risky.length ? 'warn' : 'ok', detail: `${names.length} remembered networks${risky.length ? `. These names look public and may be open: ${risky.slice(0, 5).join(', ')}` : ''}.`, ...(risky.length ? { fix: 'System Settings, Wi-Fi, Advanced: remove them, and turn off "Ask to join networks" if you do not want automatic joins.' } : {}) }
}

export function internetSharing(out: string): Check {
  const on = /Enabled\s*=\s*1/.test(out)
  return { id: 'internetsharing', title: 'Internet Sharing', status: on ? 'warn' : 'ok', detail: on ? 'Internet Sharing is on, so this Mac works as a router for other devices.' : 'Internet Sharing is off.', ...(on ? { fix: 'System Settings, General, Sharing, turn off Internet Sharing unless you use it.' } : {}) }
}

/** The DNS servers in use. Unusual public ones can redirect your lookups. */
export function dnsServers(out: string): Check {
  const ips = [...new Set([...out.matchAll(/nameserver\[\d+\]\s*:\s*(\S+)/g)].map((m) => m[1]))]
  if (!ips.length) return { id: 'dns', title: 'DNS servers', status: 'info', detail: 'MacSec could not read the DNS servers.' }
  const known = /^(1\.1\.1\.1|1\.0\.0\.1|8\.8\.8\.8|8\.8\.4\.4|9\.9\.9\.9|149\.112\.112\.112|208\.67\.22[02]\.22[02]|2606:4700:4700::|2001:4860:4860::)/
  const priv = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fe80:|fd|127\.|::1)/i
  const odd = ips.filter((i) => !known.test(i) && !priv.test(i))
  return { id: 'dns', title: 'DNS servers', status: odd.length ? 'warn' : 'ok', detail: `Lookups go to ${ips.join(', ')}.${odd.length ? ` ${odd.join(', ')} ${odd.length === 1 ? 'is' : 'are'} not your router or a well-known provider. If you did not choose it, something changed your DNS.` : ''}`, ...(odd.length ? { fix: 'System Settings, Network, Details, DNS: set your router or a provider you trust (1.1.1.1, 9.9.9.9).' } : {}) }
}

// ---------------------------------------------------------------- Runner

function run(cmd: string, args: string[], timeout = 8000): Promise<string> {
  return new Promise((resolve) => execFile(cmd, args, { timeout, maxBuffer: 8 * 1024 * 1024 }, (_e, out, err) => resolve(`${String(out)}${String(err)}`)))
}

const home = (...p: string[]): string => join(homedir(), ...p)
function readSmall(rel: string): { text: string; mode: number } | null {
  try {
    const p = home(rel)
    const st = lstatSync(p)
    if (!st.isFile() || st.size > 512 * 1024) return null
    return { text: readFileSync(p, 'utf8'), mode: st.mode }
  } catch {
    return null
  }
}

/** .env files in the folders developers keep projects in. Depth 3, and never inside node_modules or .git. */
export function findEnvFiles(roots = ['Sites', 'Projects', 'Developer', 'Code', 'code', 'dev', 'work', 'www', 'Laramac', 'Documents/GitHub', 'GitHub'].map((r) => home(r)), cap = 4000): { file: string; mode: number }[] {
  const out: { file: string; mode: number }[] = []
  let seen = 0
  const walk = (dir: string, depth: number): void => {
    if (depth > 3 || seen > cap) return
    let names: string[]
    try {
      names = readdirSync(dir)
    } catch {
      return
    }
    for (const n of names) {
      if (++seen > cap) return
      if (n === 'node_modules' || n === '.git' || n === 'vendor') continue
      const p = join(dir, n)
      let st
      try {
        st = lstatSync(p)
      } catch {
        continue
      }
      if (st.isDirectory()) walk(p, depth + 1)
      else if (st.isFile() && /^\.env(\.[A-Za-z0-9_-]+)?$/.test(n) && !/\.(example|sample|dist|template)$/.test(n)) out.push({ file: p.replace(homedir(), '~'), mode: st.mode & 0o777 })
    }
  }
  for (const r of roots) if (existsSync(r)) walk(r, 0)
  return out
}

/** Every deeper check. Each runs alone: one that cannot run never stops the others. */
export async function runDeepMacChecks(): Promise<Check[]> {
  const safe = async (fn: () => Promise<Check | Check[]> | Check | Check[]): Promise<Check[]> => {
    try {
      const r = await fn()
      return Array.isArray(r) ? r : [r]
    } catch {
      return []
    }
  }
  const out: Check[] = []
  const add = (group: Group, cs: Check[]): void => void out.push(...cs.map((c) => g(group, c)))
  add('Accounts and passwords', await safe(async () => rootAccount(await run('/usr/bin/dscl', ['.', '-read', '/Users/root', 'AuthenticationAuthority']))))
  add('Accounts and passwords', await safe(async () => adminAccounts(await run('/usr/bin/dscl', ['.', '-read', '/Groups/admin', 'GroupMembership']))))
  add('Accounts and passwords', await safe(async () => idleLock(await run('/usr/bin/defaults', ['-currentHost', 'read', 'com.apple.screensaver', 'idleTime']), await run('/usr/bin/defaults', ['read', 'com.apple.screensaver', 'askForPasswordDelay']))))
  add('Accounts and passwords', await safe(async () => loginWindow(await run('/usr/bin/defaults', ['read', '/Library/Preferences/com.apple.loginwindow', 'SHOWFULLNAME']))))
  add('Secrets left on this Mac', await safe(() => secretFilesCheck(secretFiles(readSmall))))
  add('Secrets left on this Mac', await safe(() => {
    let text = ''
    for (const f of ['.zsh_history', '.bash_history']) text += `\n${readSmall(f)?.text ?? ''}`
    return historyCheck(historySecrets(text))
  }))
  add('Secrets left on this Mac', await safe(() => envFilesCheck(findEnvFiles())))
  add('Software on this Mac', await safe(() => {
    const p = '/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara'
    const alt = '/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist'
    const f = existsSync(p) ? p : alt
    return xprotectAge(existsSync(f) ? statSync(f).mtimeMs : null)
  }))
  add('Software on this Mac', await safe(async () => thirdPartyExtensions(await run('/usr/sbin/kextstat', ['-l']), await run('/usr/bin/systemextensionsctl', ['list']))))
  add('Software on this Mac', await safe(async () => {
    const apps = readdirSync('/Applications').filter((n) => n.endsWith('.app')).slice(0, 80)
    const bad: string[] = []
    // A handful at a time, so the check stays quick.
    for (let i = 0; i < apps.length; i += 8) {
      const batch = await Promise.all(apps.slice(i, i + 8).map(async (a) => ({ a, o: await run('/usr/sbin/spctl', ['--assess', '--type', 'execute', `/Applications/${a}`], 6000) })))
      for (const { a, o } of batch) if (/rejected/i.test(o) && !/source=Apple/i.test(o)) bad.push(a.replace(/\.app$/, ''))
    }
    return rejectedApps(bad)
  }))
  add('Software on this Mac', await safe(async () => {
    const brew = ['/opt/homebrew/bin/brew', '/usr/local/bin/brew'].find((p) => existsSync(p))
    return brewOutdated(brew ? await run(brew, ['outdated', '--quiet'], 30000) : null)
  }))
  add('Software on this Mac', await safe(async () => {
    let cfg = ''
    for (const f of ['/etc/ssh/sshd_config', ...(existsSync('/etc/ssh/sshd_config.d') ? readdirSync('/etc/ssh/sshd_config.d').map((n) => `/etc/ssh/sshd_config.d/${n}`) : [])]) {
      try {
        cfg += `\n${readFileSync(f, 'utf8')}`
      } catch {
        /* not readable */
      }
    }
    const on = /Remote Login:\s*On/i.test(await run('/usr/sbin/systemsetup', ['-getremotelogin'])) || /:22\b/.test(await run('/usr/sbin/lsof', ['-nP', '-iTCP:22', '-sTCP:LISTEN']))
    return sshdConfig(cfg, on)
  }))
  add('Programs and commands', await safe(async () => cronJobs(await run('/usr/bin/crontab', ['-l']))))
  add('Network and Wi-Fi', await safe(async () => wifiSecurity(await run('/usr/sbin/system_profiler', ['SPAirPortDataType'], 20000))))
  add('Network and Wi-Fi', await safe(async () => savedOpenWifi(await run('/usr/sbin/networksetup', ['-listpreferredwirelessnetworks', 'en0']))))
  add('Network and Wi-Fi', await safe(async () => internetSharing(await run('/usr/bin/defaults', ['read', '/Library/Preferences/SystemConfiguration/com.apple.nat']))))
  add('Network and Wi-Fi', await safe(async () => dnsServers(await run('/usr/sbin/scutil', ['--dns']))))
  return out
}
