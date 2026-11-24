/**
 * Bring-your-own tools. A plugin is a declared binary, an argument array, a parser and a timeout.
 * No shell, no implicit network, no automatic run: the person presses Run and confirms the authority.
 */
import { execFile } from 'child_process'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs'
import { join } from 'path'
import { randomBytes } from 'crypto'
import type { Finding, PluginDef, PluginRun, SessionInfo, Severity } from '../shared/types'
import { dirs } from './paths'
import { readSession, saveFindings, sessionDetail, sessionDir } from './sessions'
import { currentEngagement, engagementProblem } from './engagement'
import { fid } from './scanners/parse'
import { log } from './logs'

const file = (): string => join(dirs.config(), 'plugins.json')
const MAX = 50
const SEVS: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

const load = (): PluginDef[] => {
  try {
    const list = JSON.parse(readFileSync(file(), 'utf8')) as PluginDef[]
    return Array.isArray(list) ? list.filter((p) => p && typeof p.id === 'string' && typeof p.bin === 'string') : []
  } catch {
    return []
  }
}
const write = (list: PluginDef[]): void => {
  mkdirSync(dirs.config(), { recursive: true, mode: 0o700 })
  writeFileSync(file(), JSON.stringify(list.slice(0, MAX), null, 2), { mode: 0o600 })
}

export function listPlugins(): PluginDef[] {
  return load().sort((a, b) => a.name.localeCompare(b.name))
}

export function savePlugin(input: unknown): PluginDef[] {
  const p = (input ?? {}) as Record<string, unknown>
  const name = typeof p.name === 'string' ? p.name.trim().slice(0, 60) : ''
  const bin = typeof p.bin === 'string' ? p.bin.trim() : ''
  if (!name) throw new Error('Give the plugin a name.')
  if (!bin.startsWith('/') || !existsSync(bin)) throw new Error('The binary must be an absolute path that exists on this Mac.')
  const args = Array.isArray(p.args) ? p.args.filter((a): a is string => typeof a === 'string').slice(0, 50) : []
  const parser = p.parser === 'lines' || p.parser === 'regex' || p.parser === 'jsonl' ? p.parser : 'json'
  const pattern = typeof p.pattern === 'string' ? p.pattern.slice(0, 300) : undefined
  if (parser === 'regex' && !pattern) throw new Error('A regex parser needs a pattern.')
  const severity = SEVS.includes(p.severity as Severity) ? (p.severity as Severity) : 'medium'
  const list = load().filter((x) => x.name.toLowerCase() !== name.toLowerCase())
  const plugin: PluginDef = { id: `pl-${randomBytes(4).toString('hex')}`, name, bin, args, parser, ...(pattern ? { pattern } : {}), severity, ...(typeof p.description === 'string' ? { description: p.description.slice(0, 500) } : {}) }
  write([plugin, ...list])
  return listPlugins()
}

export function deletePlugin(id: string): PluginDef[] {
  write(load().filter((p) => p.id !== id))
  return listPlugins()
}

export function pluginPresets(): { name: string; bin: string; args: string[]; parser: PluginDef['parser']; pattern?: string; severity: Severity; description: string; install: string }[] {
  return [
    { name: 'Nmap service scan', bin: '/opt/homebrew/bin/nmap', args: ['-sV', '--open', '-oG', '-', '{host}'], parser: 'regex', pattern: 'Ports: (.+)', severity: 'info', description: 'Open ports and service versions from an in-scope host.', install: 'brew install nmap' },
    { name: 'NetExec SMB', bin: '/opt/homebrew/bin/nxc', args: ['smb', '{host}'], parser: 'lines', severity: 'info', description: 'SMB signing, dialect and host information. No credential attack.', install: 'pipx install netexec' },
    { name: 'LDAP base search', bin: '/opt/homebrew/bin/ldapsearch', args: ['-x', '-H', 'ldap://{host}', '-s', 'base'], parser: 'lines', severity: 'info', description: 'Anonymous base search against an in-scope directory.', install: 'brew install openldap' },
    { name: 'Nuclei JSONL', bin: '/opt/homebrew/bin/nuclei', args: ['-u', '{target}', '-jsonl', '-silent'], parser: 'jsonl', severity: 'high', description: 'Read a Nuclei JSONL result as findings. The operator supplies the templates and the target.', install: 'brew install nuclei' },
    { name: 'smbmap', bin: '/opt/homebrew/bin/smbmap', args: ['-H', '{host}'], parser: 'lines', severity: 'info', description: 'SMB share visibility from an in-scope host.', install: 'pipx install smbmap' }
  ]
}

export interface PluginOutput {
  title: string
  severity: Severity
  location: string
  evidence: string
}

/** Parsers are deliberately small and strict: no shell, no eval, no HTML. */
export function parsePluginOutput(text: string, plugin: PluginDef, fallbackLocation: string): PluginOutput[] {
  const out: PluginOutput[] = []
  if (plugin.parser === 'json' || plugin.parser === 'jsonl') {
    if (plugin.parser === 'jsonl') {
      const rows: unknown[] = []
      for (const line of text.split(/\r?\n/)) {
        if (!line.trim()) continue
        try {
          rows.push(JSON.parse(line))
        } catch {
          // A broken line is skipped; the other lines still count.
        }
      }
      for (const raw of rows) {
        const r = raw as Record<string, unknown>
        const info = (r.info ?? {}) as Record<string, unknown>
        const title = typeof r.title === 'string' ? r.title : typeof info.name === 'string' ? info.name : ''
        if (!title) continue
        const sev = String(r.severity ?? info.severity ?? '')
        out.push({
          title: title.slice(0, 200),
          severity: SEVS.includes(sev as Severity) ? (sev as Severity) : plugin.severity ?? 'medium',
          location: typeof r['matched-at'] === 'string' ? r['matched-at'] : typeof r.host === 'string' ? r.host : fallbackLocation,
          evidence: typeof r['matcher-name'] === 'string' ? r['matcher-name'] : typeof r['matched-at'] === 'string' ? r['matched-at'] : ''
        })
        if (out.length >= 100) break
      }
      return out
    }
    let data: unknown
    try {
      const start = text.indexOf('[')
      const end = text.lastIndexOf(']')
      data = JSON.parse(start >= 0 && end > start ? text.slice(start, end + 1) : text)
    } catch {
      return []
    }
    if (!Array.isArray(data)) return []
    for (const raw of data) {
      const r = raw as Record<string, unknown>
      const title = typeof r.title === 'string' ? r.title.trim().slice(0, 200) : ''
      if (!title) continue
      out.push({
        title,
        severity: SEVS.includes(r.severity as Severity) ? (r.severity as Severity) : plugin.severity ?? 'medium',
        location: typeof r.location === 'string' ? r.location.slice(0, 300) : fallbackLocation,
        evidence: typeof r.evidence === 'string' ? r.evidence.slice(0, 1500) : ''
      })
      if (out.length >= 100) break
    }
    return out
  }
  const lines = text.split(/\r?\n/).filter((l) => l.trim())
  if (plugin.parser === 'regex') {
    let re: RegExp
    try {
      re = new RegExp(plugin.pattern as string)
    } catch {
      return []
    }
    for (const line of lines) {
      const m = re.exec(line)
      if (!m) continue
      out.push({ title: (m[1] ?? line).trim().slice(0, 200), severity: plugin.severity ?? 'medium', location: fallbackLocation, evidence: line.slice(0, 1500) })
      if (out.length >= 100) break
    }
    return out
  }
  for (const line of lines.slice(0, 100)) out.push({ title: line.trim().slice(0, 200), severity: plugin.severity ?? 'medium', location: fallbackLocation, evidence: line.slice(0, 1500) })
  return out
}

export async function runPlugin(sessionId: string, pluginId: string, confirmed: boolean): Promise<PluginRun> {
  if (!confirmed) throw new Error('Confirm that you are allowed to run this tool on this target.')
  const p = load().find((x) => x.id === pluginId)
  if (!p) throw new Error('That plugin is not saved on this Mac.')
  const s = readSession(sessionId)
  const target = s.target
  let host = ''
  try {
    host = new URL(target).hostname
  } catch {
    // A local project has no host.
  }
  if (host) {
    const e = currentEngagement()
    const problem = engagementProblem(e, host, ['confidentiality'])
    if (problem) throw new Error(problem)
  }
  const args = p.args.map((a) => a.replace(/\{target\}/g, target).replace(/\{host\}/g, host).replace(/\{url\}/g, target).replace(/\{session\}/g, sessionId))
  const out = await new Promise<string>((resolve, reject) => {
    execFile(p.bin, args, { cwd: sessionDir(sessionId), timeout: 10 * 60_000, maxBuffer: 8 * 1024 * 1024, env: process.env }, (e, stdout, stderr) => {
      if (e && !stdout) return reject(new Error(`${p.name} failed: ${String(stderr).trim().split('\n').slice(-2).join(' ')}`))
      resolve(String(stdout))
    })
  })
  const parsed = parsePluginOutput(out, p, host || target)
  const findings: Finding[] = parsed.map((x) => ({
    id: fid(`Plugin: ${p.name}`, x.title, x.location),
    tool: `Plugin: ${p.name}`,
    category: host ? 'web' : 'code',
    severity: x.severity,
    title: x.title,
    confidence: 'possible',
    file: host ? undefined : x.location,
    url: host ? x.location : undefined,
    description: x.evidence,
    proof: undefined
  }))
  const d = sessionDetail(sessionId)
  saveFindings(sessionId, [...d.findings, ...findings])
  log('info', `Plugin ${p.name}: ${findings.length} finding${findings.length === 1 ? '' : 's'}`, sessionId)
  return { session: readSession(sessionId) as SessionInfo, added: findings.length, output: out.slice(-4000), detail: sessionDetail(sessionId) }
}
