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
 *   - The only commands ever sent are use, set RHOSTS, set RPORT, check and exit. There is no run,
 *     exploit, set PAYLOAD, set LHOST or anything that opens a session.
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

/** Modules with a check that does not exploit and does not read other people's files or memory. */
export const MODULES: MsfModule[] = [
  { cve: 'CVE-2017-0144', module: 'auxiliary/scanner/smb/smb_ms17_010', port: 445, label: 'EternalBlue (MS17-010) in SMB' },
  { cve: 'CVE-2019-0708', module: 'auxiliary/scanner/rdp/cve_2019_0708_bluekeep', port: 3389, label: 'BlueKeep in Remote Desktop' },
  { cve: 'CVE-2021-41773', module: 'auxiliary/scanner/http/apache_normalize_path', port: 80, label: 'Apache 2.4.49 path traversal' },
  { cve: 'CVE-2021-42013', module: 'auxiliary/scanner/http/apache_normalize_path', port: 80, label: 'Apache 2.4.50 path traversal' },
  { cve: 'CVE-2022-22965', module: 'exploit/multi/http/spring_framework_rce_spring4shell', port: 8080, label: 'Spring4Shell' },
  { cve: 'CVE-2017-5638', module: 'exploit/multi/http/struts2_content_type_ognl', port: 8080, label: 'Apache Struts 2 (S2-045)' },
  { cve: 'CVE-2018-7600', module: 'exploit/unix/webapp/drupal_drupalgeddon2', port: 80, label: 'Drupalgeddon 2' },
  { cve: 'CVE-2014-6271', module: 'exploit/multi/http/apache_mod_cgi_bash_env_exec', port: 80, label: 'Shellshock in CGI' },
  { cve: 'CVE-2022-26134', module: 'exploit/multi/http/atlassian_confluence_rce_cve_2022_26134', port: 8090, label: 'Confluence OGNL injection' },
  { cve: 'CVE-2021-26855', module: 'auxiliary/scanner/http/exchange_proxylogon', port: 443, label: 'Exchange ProxyLogon' },
  { cve: 'CVE-2021-22205', module: 'exploit/multi/http/gitlab_exif_rce', port: 80, label: 'GitLab ExifTool' }
]

export const moduleFor = (cve: string): MsfModule | null => MODULES.find((m) => m.cve === cve.toUpperCase()) ?? null
export const validModule = (m: string): boolean => /^[a-z0-9_/]+$/.test(m) && MODULES.some((x) => x.module === m)

const HOST = /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]*[a-z0-9])?$|^(\d{1,3}\.){3}\d{1,3}$/i
export const validTarget = (h: string, p: number): boolean => HOST.test(h) && h.length <= 253 && !h.startsWith('-') && Number.isInteger(p) && p > 0 && p < 65536

/** The arguments for msfconsole: a fixed script of five commands around values that were validated. */
export function checkArgs(module: string, host: string, port: number): string[] {
  if (!validModule(module)) throw new Error('That Metasploit module is not on the check-only list.')
  if (!validTarget(host, port)) throw new Error('That address is not valid.')
  return ['-q', '-n', '-x', `use ${module}; set RHOSTS ${host}; set RPORT ${port}; check; exit -y`]
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
}

/** Runs the checks for the CVEs that have a module. A module is asked once per host and port, however many CVEs share it. */
export async function msfChecks(items: MsfItem[], o: MsfOptions = {}): Promise<Finding[]> {
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
