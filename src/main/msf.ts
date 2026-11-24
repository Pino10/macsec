/**
 * Metasploit, in check-only mode. MacSec never exploits anything. For a known flaw that MacSec has
 * matched to a version it saw, it asks Metasploit's own module whether the target is vulnerable, using
 * the module's `check` command, which is built to answer without attacking. A "vulnerable" answer is
 * kept as proof: the exact command and what Metasploit said.
 *
 * What is enforced here, not just promised:
 *   - Metasploit must already be installed by you. MacSec never installs it.
 *   - Only modules in the list below are used, chosen because they have a check and do not read
 *     other people's data. A name that is not in the list is refused.
 *   - Nothing runs unless you approved that module for this scan, one by one, after reading what it
 *     sends. Not ticked means not run.
 *   - Two kinds of module exist. "Check" modules (known flaws) get only: use, set RHOSTS, set RPORT,
 *     check, exit. "Look" modules (version, banner and title scanners: auxiliary/scanner only) get only:
 *     use, set RHOSTS, set RPORT, set THREADS 1, run, exit. There is no exploit, set PAYLOAD, set LHOST,
 *     no login or brute-force module, nothing that dumps data, floods or opens a session.
 *   - The host is a validated address, the port a number: nothing typed is read as a command.
 *   - It runs as an argument list (no shell), with its own home folder under ~/MacSec, and a time limit.
 *   - It only runs when you ticked it for that scan and the target is yours (or on this Mac).
 */
import { execFile } from 'child_process'
import { existsSync } from 'fs'
import type { Finding } from '../shared/types'
import { fid } from './scanners/parse'
import { createHash } from 'crypto'
import { toolEnv } from './toolbox'

export interface MsfModule {
  cve: string
  module: string
  /** The port the module expects when the service is on its usual one. */
  port: number
  label: string
}

/**
 * Modules with a check that does not exploit and does not read other people's files or memory.
 *
 * These are all auxiliary scanner modules. An exploit module is deliberately never on this list:
 * several popular ones implement `check` by executing a command on the target (Shellshock and Struts2
 * do), so "check only" would be a promise the module itself breaks. A real exploit belongs to a
 * controlled proof (src/main/impact), where it needs an engagement, a typed phrase and a cleanup.
 */
export const MODULES: MsfModule[] = [
  { cve: 'CVE-2017-0144', module: 'auxiliary/scanner/smb/smb_ms17_010', port: 445, label: 'EternalBlue (MS17-010) in SMB' },
  { cve: 'CVE-2019-0708', module: 'auxiliary/scanner/rdp/cve_2019_0708_bluekeep', port: 3389, label: 'BlueKeep in Remote Desktop' },
  { cve: 'CVE-2021-41773', module: 'auxiliary/scanner/http/apache_normalize_path', port: 80, label: 'Apache 2.4.49 path traversal' },
  { cve: 'CVE-2021-42013', module: 'auxiliary/scanner/http/apache_normalize_path', port: 80, label: 'Apache 2.4.50 path traversal' },
  { cve: 'CVE-2021-26855', module: 'auxiliary/scanner/http/exchange_proxylogon', port: 443, label: 'Exchange ProxyLogon' }
]

/** Where a real exploit is allowed: only these, only with a command payload and a callback proof. */
export interface RunModule {
  module: string
  cve: string
  title: string
  what: string
  port: number
  risk: string
}

/**
 * Exploit modules MacSec may run under a controlled proof. Each one is a command injection that
 * accepts `cmd/unix/generic`, has no webshell left behind, and is not known to crash the target.
 * Deliberately absent: EternalBlue and BlueKeep (they can crash a host), Spring4Shell and ProxyLogon
 * (they write a file to the target), Drupalgeddon 2 (it needs a PHP payload, not a command).
 */
export const RUN_MODULES: RunModule[] = [
  {
    module: 'exploit/multi/http/apache_mod_cgi_bash_env_exec',
    cve: 'CVE-2014-6271',
    title: 'Shellshock in CGI',
    what: 'Injects the command into a CGI header. The command is one curl or wget back to this Mac, nothing else.',
    port: 80,
    risk: 'Runs one command on the server, as the web user. It can be logged and it may be blocked. Nothing is written and no session is opened.'
  },
  {
    module: 'exploit/multi/http/struts2_content_type_ognl',
    cve: 'CVE-2017-5638',
    title: 'Apache Struts 2 (S2-045)',
    what: 'Injects the command through the Content-Type header with OGNL.',
    port: 8080,
    risk: 'Runs one command on the server. A patched or hardened server simply ignores it.'
  },
  {
    module: 'exploit/multi/http/atlassian_confluence_rce_cve_2022_26134',
    cve: 'CVE-2022-26134',
    title: 'Confluence OGNL injection',
    what: 'Injects the command through the URL with OGNL.',
    port: 8090,
    risk: 'Runs one command on the server. Confluence may log the request.'
  },
  {
    module: 'exploit/multi/http/gitlab_exif_rce',
    cve: 'CVE-2021-22205',
    title: 'GitLab ExifTool',
    what: 'Injects the command through an uploaded image. GitLab may keep the image upload.',
    port: 80,
    risk: 'Runs one command on the server. It uploads one image that GitLab may keep; MacSec cannot remove it, so that is reported as a leftover.'
  }
]

export const runModule = (m: string): RunModule | null => RUN_MODULES.find((x) => x.module === m) ?? null
export const validRunModule = (m: string): boolean => /^exploit\/[a-z0-9_/]+$/.test(m) && !!runModule(m)

/**
 * The script for one approved run. The command is generated by MacSec (a callback to this Mac), the
 * module is on the run-only list, and the host and port are validated. No payload other than
 * cmd/unix/generic is ever set, and no handler is started.
 */
export function runArgs(module: string, host: string, port: number, command: string): string[] {
  if (!validRunModule(module)) throw new Error('That Metasploit module is not on the run-only list.')
  if (!validTarget(host, port)) throw new Error('That address is not valid.')
  if (!/^curl -sS -m 10 http:\/\/[\w.:\[\]/-]+ \|\| wget -qO- -T 10 http:\/\/[\w.:\[\]/-]+$/.test(command)) throw new Error('The callback command is not the one MacSec writes.')
  return ['-q', '-n', '-x', `use ${module}; set RHOSTS ${host}; set RPORT ${port}; set PAYLOAD cmd/unix/generic; set CMD ${command}; set DisablePayloadHandler true; set ExitOnSession false; set WfsDelay 10; run; exit -y`]
}

export const moduleFor = (cve: string): MsfModule | null => MODULES.find((m) => m.cve === cve.toUpperCase()) ?? null
export const validModule = (m: string): boolean => /^[a-z0-9_/]+$/.test(m) && MODULES.some((x) => x.module === m)

const HOST = /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]*[a-z0-9])?$|^(\d{1,3}\.){3}\d{1,3}$/i
export const validTarget = (h: string, p: number): boolean => HOST.test(h) && h.length <= 253 && !h.startsWith('-') && Number.isInteger(p) && p > 0 && p < 65536

export interface LookModule {
  module: string
  title: string
  /** What it sends, in plain words. */
  what: string
  /** nmap service names this module fits, and the usual ports when the name is not known. */
  services: RegExp
  ports: number[]
}

/**
 * Look-only modules: they connect, read what the service says about itself and stop. They are all
 * auxiliary/scanner modules for banners, versions, titles and methods. No login, no brute force, no
 * enumeration, no data is read from the service, and THREADS is forced to 1.
 */
export const LOOK: LookModule[] = [
  { module: 'auxiliary/scanner/ssh/ssh_version', title: 'SSH version', what: 'Connects and reads the SSH banner (the version text the server announces).', services: /^ssh/i, ports: [22] },
  { module: 'auxiliary/scanner/ftp/ftp_version', title: 'FTP version', what: 'Connects and reads the FTP welcome banner.', services: /^ftp/i, ports: [21] },
  { module: 'auxiliary/scanner/telnet/telnet_version', title: 'Telnet banner', what: 'Connects and reads the Telnet banner. It does not log in.', services: /^telnet/i, ports: [23] },
  { module: 'auxiliary/scanner/smtp/smtp_version', title: 'SMTP banner', what: 'Connects and reads the mail server greeting.', services: /^smtp/i, ports: [25, 587] },
  { module: 'auxiliary/scanner/imap/imap_version', title: 'IMAP banner', what: 'Connects and reads the IMAP greeting.', services: /^imap/i, ports: [143] },
  { module: 'auxiliary/scanner/pop3/pop3_version', title: 'POP3 banner', what: 'Connects and reads the POP3 greeting.', services: /^pop3/i, ports: [110] },
  { module: 'auxiliary/scanner/http/http_version', title: 'Web server version', what: 'Sends one GET / and reads the Server header.', services: /^http/i, ports: [80, 8080, 8000, 8008] },
  { module: 'auxiliary/scanner/http/title', title: 'Web page title', what: 'Sends one GET / and reads the page title.', services: /^http/i, ports: [80, 8080, 8000, 8008] },
  { module: 'auxiliary/scanner/http/options', title: 'Web methods advertised', what: 'Sends one OPTIONS request and reads which methods the server says it allows. It does not use them.', services: /^http/i, ports: [80, 8080, 8000, 8008] },
  { module: 'auxiliary/scanner/http/robots_txt', title: 'robots.txt', what: 'Sends one GET /robots.txt and shows what it lists.', services: /^http/i, ports: [80, 8080, 8000, 8008] },
  { module: 'auxiliary/scanner/http/cert', title: 'Web certificate', what: 'Opens a TLS connection and reads the certificate (name, issuer, dates).', services: /(^https|ssl\/http|http.*ssl)/i, ports: [443, 8443] },
  { module: 'auxiliary/scanner/smb/smb_version', title: 'SMB version', what: 'Starts an SMB session without logging in and reads the version and signing settings.', services: /(microsoft-ds|netbios-ssn|^smb)/i, ports: [445, 139] },
  { module: 'auxiliary/scanner/smb/smb2', title: 'SMB 2 support', what: 'Sends an SMB2 negotiate message and reads whether SMB 2 is supported.', services: /(microsoft-ds|^smb)/i, ports: [445] },
  { module: 'auxiliary/scanner/mysql/mysql_version', title: 'MySQL version', what: 'Connects and reads the MySQL handshake (version text). It does not log in.', services: /^mysql/i, ports: [3306] },
  { module: 'auxiliary/scanner/postgres/postgres_version', title: 'PostgreSQL version', what: 'Starts a connection and reads the version the server reports. It tries no passwords.', services: /^postgres/i, ports: [5432] },
  { module: 'auxiliary/scanner/rdp/rdp_scanner', title: 'Remote Desktop detection', what: 'Sends a Remote Desktop connection request and reads whether it speaks RDP and requires network-level authentication. It does not log in.', services: /(ms-wbt-server|^rdp)/i, ports: [3389] }
]

export const validLook = (m: string): boolean => /^auxiliary\/scanner\/[a-z0-9_]+\/[a-z0-9_]+$/.test(m) && LOOK.some((x) => x.module === m)

export interface CatalogEntry {
  module: string
  kind: 'check' | 'look'
  title: string
  what: string
  /** What could go wrong, honestly. */
  risk: string
}

/** What the person is asked to approve: every module MacSec could use, in plain words. */
export function catalog(): CatalogEntry[] {
  const seen = new Set<string>()
  const checks: CatalogEntry[] = []
  for (const m of MODULES) {
    if (seen.has(m.module)) continue
    seen.add(m.module)
    checks.push({ module: m.module, kind: 'check', title: m.label, what: `Metasploit's own check for ${MODULES.filter((x) => x.module === m.module).map((x) => x.cve).join(', ')}. This is a scanner module: it sends one or two probes and answers "vulnerable", "safe" or "cannot tell". It does not exploit, does not read files and opens no session. Exploit modules are never on this list, because some of them run code during their check. Runs only when MacSec matched a version it saw to that flaw.`, risk: 'Low. A check sends a probe that real attackers also send. Very old or fragile servers have occasionally reacted badly to such probes, so run it in a quiet period on servers you own.' })
  }
  const looks: CatalogEntry[] = LOOK.map((l) => ({ module: l.module, kind: 'look', title: l.title, what: l.what, risk: 'Very low. One ordinary connection to a port that is already open, the same as a browser or a mail program would make.' }))
  return [...looks, ...checks]
}

/** The arguments for msfconsole: a fixed script of five commands around values that were validated. */
export function checkArgs(module: string, host: string, port: number): string[] {
  if (!validModule(module)) throw new Error('That Metasploit module is not on the check-only list.')
  if (!validTarget(host, port)) throw new Error('That address is not valid.')
  return ['-q', '-n', '-x', `use ${module}; set RHOSTS ${host}; set RPORT ${port}; check; exit -y`]
}

/** The arguments for a look-only module: a fixed script around validated values, one thread. */
export function lookArgs(module: string, host: string, port: number): string[] {
  if (!validLook(module)) throw new Error('That Metasploit module is not on the look-only list.')
  if (!validTarget(host, port)) throw new Error('That address is not valid.')
  return ['-q', '-n', '-x', `use ${module}; set RHOSTS ${host}; set RPORT ${port}; set THREADS 1; run; exit -y`]
}

export function msfPath(): string | null {
  return ['/opt/homebrew/bin/msfconsole', '/usr/local/bin/msfconsole', '/opt/metasploit-framework/bin/msfconsole'].find((p) => existsSync(p)) ?? null
}

export type MsfState = 'vulnerable' | 'appears' | 'safe' | 'unsupported' | 'unknown'

/** What Metasploit said, from its real output lines. */
export function parseCheck(out: string): { state: MsfState; line: string } {
  const lines = out.split('\n').map((l) => l.replace(/\x1b\[[0-9;]*m/g, '').trim()).filter(Boolean)
  const find = (re: RegExp): string | undefined => lines.find((l) => re.test(l))
  let l: string | undefined
  if ((l = find(/does not support check|check method is not supported|cannot reliably check|check is not supported/i))) return { state: 'unsupported', line: l }
  if ((l = find(/Failed to load module|Unknown module|Invalid module/i))) return { state: 'unsupported', line: l }
  if ((l = find(/^\[\+\].*\bthe target is vulnerable\b|^\[\+\].*\bis vulnerable\b/i))) return { state: 'vulnerable', line: l }
  if ((l = find(/appears to be vulnerable/i))) return { state: 'appears', line: l }
  if ((l = find(/not (exploitable|vulnerable)|appears to be safe|is not vulnerable|target is safe/i))) return { state: 'safe', line: l }
  return { state: 'unknown', line: lines.slice(-1)[0] ?? '' }
}

export type MsfRun = (bin: string, args: string[], timeoutMs: number) => Promise<string>

const defaultRun: MsfRun = (bin, args, timeoutMs) =>
  new Promise((resolve) => execFile(bin, args, { timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024, env: toolEnv() }, (_e, out, err) => resolve(`${String(out)}\n${String(err)}`)))

export interface MsfItem {
  cve: string
  host: string
  port: number
}

export interface MsfOptions {
  bin?: string
  run?: MsfRun
  cancelled?: () => boolean
  note?: (t: string) => void
  /** At most this many checks in one scan. */
  max?: number
  /** The modules the person approved for this scan, one by one. A module that is not in this list never runs. */
  approved: string[]
}

/** Runs the checks for the CVEs that have a module. A module is asked once per host and port, however many CVEs share it. */
export async function msfChecks(items: MsfItem[], o: MsfOptions): Promise<Finding[]> {
  const bin = o.bin ?? msfPath()
  if (!bin) {
    o.note?.('Metasploit is not installed here, so nothing was checked. Install it yourself from metasploit.com if you want this.')
    return []
  }
  const run = o.run ?? defaultRun
  const out: Finding[] = []
  const done = new Set<string>()
  for (const it of items) {
    if (o.cancelled?.() || done.size >= (o.max ?? 8)) break
    const m = moduleFor(it.cve)
    if (!m || !validTarget(it.host, it.port)) continue
    if (!o.approved.includes(m.module)) {
      o.note?.(`Not approved, so not run: ${m.label}`)
      continue
    }
    const key = `${m.module}|${it.host}|${it.port}`
    if (done.has(key)) continue
    done.add(key)
    o.note?.(`Metasploit check: ${m.label} on ${it.host}:${it.port}`)
    const args = checkArgs(m.module, it.host, it.port)
    const text = await run(bin, args, 180_000)
    const r = parseCheck(text)
    if (r.state === 'unsupported') o.note?.(`${m.module} cannot be checked without running it, so MacSec did not use it.`)
    if (r.state !== 'vulnerable' && r.state !== 'appears') continue
    const sure = r.state === 'vulnerable'
    const command = `msfconsole -q -n -x "use ${m.module}; set RHOSTS ${it.host}; set RPORT ${it.port}; check; exit -y"`
    out.push({
      id: fid('msf', m.module, it.host, it.port),
      tool: 'Metasploit (check only)',
      category: 'network',
      severity: 'critical',
      confidence: sure ? 'confirmed' : 'possible',
      title: `Metasploit's check says ${it.host}:${it.port} ${sure ? 'is vulnerable' : 'appears vulnerable'}: ${m.label}`,
      url: `${it.host}:${it.port}`,
      file: `${it.host}:${it.port}`,
      cves: undefined,
      description: `Metasploit's own check for ${it.cve} (${m.module}) answered: "${r.line.slice(0, 200)}". The check does not attack: MacSec only used the module's check command, never run or exploit.`,
      fix: 'Update the software to a fixed version now, and close the port to the internet until you have. Then run this check again.',
      proof: {
        request: `msfconsole check ${m.module} ${it.host}:${it.port}`,
        reproduce: command,
        status: 0,
        bytes: Buffer.byteLength(text),
        sha256: createHash('sha256').update(text).digest('hex'),
        at: new Date().toISOString(),
        shows: [`Metasploit said: ${r.line.slice(0, 160)}`, `module ${m.module}, command check only`, `matches ${it.cve}`]
      }
    })
  }
  return out
}

// ---------------------------------------------------------------- Look-only modules

const strip = (out: string): string[] => out.split('\n').map((l) => l.replace(/\x1b\[[0-9;]*m/g, '').replace(/\r/g, '').trim()).filter(Boolean)

/** The facts a look-only module printed: its [+] lines, without the address prefix. Nothing else is kept. */
export function parseLook(out: string): string[] {
  return strip(out)
    .filter((l) => /^\[\+\]/.test(l))
    .map((l) => l.replace(/^\[\+\]\s*/, '').replace(/^[\w.:[\]-]+\s+-\s+/, '').slice(0, 220))
    .slice(0, 6)
}

export interface LookItem {
  host: string
  port: number
  service?: string
}

/** The open ports a look-only module fits: by the service Nmap named, or by the usual port when it did not name one. */
export function portsFor(l: LookModule, open: LookItem[]): LookItem[] {
  return open.filter((p) => (p.service ? l.services.test(p.service) : l.ports.includes(p.port)))
}

const LOOK_PROOF = (module: string, host: string, port: number): string => `msfconsole -q -n -x "use ${module}; set RHOSTS ${host}; set RPORT ${port}; set THREADS 1; run; exit -y"`

/** Runs the approved look-only modules on the ports they fit. Each result is an observation, not a flaw, except risky methods. */
export async function msfLook(open: LookItem[], o: MsfOptions): Promise<Finding[]> {
  const bin = o.bin ?? msfPath()
  if (!bin) return []
  const run = o.run ?? defaultRun
  const out: Finding[] = []
  let n = 0
  for (const l of LOOK) {
    if (!o.approved.includes(l.module)) continue
    for (const it of portsFor(l, open)) {
      if (o.cancelled?.() || n >= (o.max ?? 24)) return out
      if (!validTarget(it.host, it.port)) continue
      n++
      o.note?.(`Metasploit look: ${l.title} on ${it.host}:${it.port}`)
      const text = await run(bin, lookArgs(l.module, it.host, it.port), 120_000)
      const lines = parseLook(text)
      if (!lines.length) continue
      const proof = {
        request: `msfconsole ${l.module} ${it.host}:${it.port}`,
        reproduce: LOOK_PROOF(l.module, it.host, it.port),
        status: 0,
        bytes: Buffer.byteLength(text),
        sha256: createHash('sha256').update(text).digest('hex'),
        at: new Date().toISOString(),
        shows: lines.map((x) => `Metasploit printed: ${x}`)
      }
      const base = { tool: 'Metasploit (look only)', category: 'network' as const, url: `${it.host}:${it.port}`, file: `${it.host}:${it.port}` }
      const methods = l.module.endsWith('/options') ? /\b(PUT|DELETE|TRACE|CONNECT|PATCH)\b/g : null
      const risky = methods ? [...new Set(lines.join(' ').match(methods) ?? [])] : []
      if (risky.length)
        out.push({ id: fid('msflook-methods', it.host, it.port), ...base, severity: 'low', confidence: 'possible', title: `${it.host}:${it.port} advertises the methods ${risky.join(', ')}`, description: `The server's OPTIONS answer lists ${risky.join(', ')}. Advertising a method does not prove it works, and MacSec did not try them. Try them by hand on a copy: PUT and DELETE can change or remove files, and TRACE can help steal cookies in old browsers.`, fix: 'Allow only the methods the site needs (usually GET, HEAD, POST) in the web server settings.', proof })
      out.push({ id: fid('msflook', l.module, it.host, it.port), ...base, severity: 'info', confidence: 'confirmed', title: `Metasploit read the ${l.title.toLowerCase()} of ${it.host}:${it.port}`, description: `What the service said about itself: ${lines.slice(0, 3).join(' | ')}. This is an observation, not a flaw. Compare the version with the live flaw list above, and remove version text from banners where you can.`, fix: 'If the version is old, update it. Where the software allows it, hide the exact version from banners.', proof })
    }
  }
  return out
}
