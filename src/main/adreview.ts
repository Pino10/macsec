/**
 * AD review from a BloodHound export. This reads an export; it does not touch a domain, guess a
 * password or run a credential attack. The findings say what the export shows, not what is certain.
 */
import { execFileSync } from 'child_process'
import { existsSync, readFileSync, statSync } from 'fs'
import { basename } from 'path'
import type { Finding, SessionInfo } from '../shared/types'
import { beginOp, SessionRun, endOp } from './engine'
import { createSession, saveFindings, sessionDir } from './sessions'
import { fid } from './scanners/parse'
import { log } from './logs'

export type AdKind = 'user' | 'computer' | 'group' | 'domain'
export interface AdNode {
  kind: AdKind
  name: string
  props: Record<string, unknown>
}

const MAX = 60 * 1024 * 1024
const low = (o: Record<string, unknown>): Record<string, unknown> => {
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(o)) out[k.toLowerCase()] = v
  return out
}
const truth = (v: unknown): boolean => v === true || v === 'true' || v === 1 || v === '1'
const arr = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : typeof v === 'string' && v.trim() ? v.split(/[;,]/).map((x) => x.trim()) : [])
const str = (v: unknown): string => (typeof v === 'string' ? v : v == null ? '' : String(v))

const kindOf = (hint: string | undefined, props: Record<string, unknown>, name: string): AdKind => {
  const h = (hint ?? '').toLowerCase()
  if (h.includes('user')) return 'user'
  if (h.includes('computer')) return 'computer'
  if (h.includes('group')) return 'group'
  if (h.includes('domain')) return 'domain'
  if (name.endsWith('$')) return 'computer'
  if (props.operatingsystem) return 'computer'
  if (props.members !== undefined || props.grouptype !== undefined) return 'group'
  if (props.functionallevel !== undefined || props.domainname !== undefined) return 'domain'
  return 'user'
}

export function parseAdExport(text: string, hint?: string): AdNode[] {
  let data: unknown
  try {
    data = JSON.parse(text)
  } catch {
    // JSONL exports: one object per line.
    data = text.split(/\r?\n/).filter((l) => l.trim()).map((l) => JSON.parse(l))
  }
  const rows: { hint?: string; raw: Record<string, unknown> }[] = []
  const add = (h: string | undefined, v: unknown): void => {
    if (v && typeof v === 'object' && !Array.isArray(v)) rows.push({ hint: h, raw: v as Record<string, unknown> })
  }
  if (Array.isArray(data)) for (const r of data) add(hint, r)
  else if (data && typeof data === 'object') {
    const o = data as Record<string, unknown>
    let found = false
    for (const k of ['users', 'computers', 'groups', 'domains', 'gpos', 'ous']) {
      if (Array.isArray(o[k])) {
        found = true
        for (const r of o[k] as unknown[]) add(k, r)
      }
    }
    if (!found) add(hint, o)
  }
  const out: AdNode[] = []
  for (const { hint: h, raw } of rows) {
    const nested = (raw.Properties ?? raw.properties ?? raw.props ?? {}) as Record<string, unknown>
    const props = low({ ...raw, ...nested })
    const name = str(props.name ?? props.samaccountname ?? props.cn).trim()
    if (!name) continue
    out.push({ kind: kindOf(h, props, name), name, props })
    if (out.length >= 30_000) break
  }
  return out
}

export function analyzeAd(nodes: AdNode[], source: string): Finding[] {
  const out: Finding[] = []
  const seen = new Set<string>()
  const add = (n: AdNode, severity: Finding['severity'], title: string, description: string, fix: string): void => {
    const key = `${title}|${n.name}`
    if (seen.has(key)) return
    seen.add(key)
    out.push({
      id: fid('BloodHound', title, n.name),
      tool: 'BloodHound import',
      category: 'network',
      severity,
      title: `${title}: ${n.name}`,
      file: source,
      confidence: 'possible',
      description,
      fix,
      snippet: description.slice(0, 400)
    })
  }
  for (const n of nodes) {
    const p = n.props
    const enabled = p.enabled === undefined ? true : truth(p.enabled)
    if (!enabled) continue
    if (n.kind === 'user' || n.kind === 'computer') {
      const spns = arr(p.serviceprincipalnames)
      if (n.kind === 'user' && spns.length && n.name.toUpperCase() !== 'KRBTGT') {
        add(n, 'high', 'Kerberoastable service account', `The export shows ${spns.length} SPN(s): ${spns.slice(0, 4).join(', ')}. A service account with an SPN can be requested and cracked offline.`, 'Use a managed service account or a long random password, remove unnecessary SPNs, and rotate the account password.')
      }
      if (n.kind === 'user' && truth(p.dontreqpreauth)) {
        add(n, 'high', 'AS-REP roastable account', 'The export sets Do not require Kerberos preauthentication. An attacker can request an AS-REP and crack it offline.', 'Clear "Do not require Kerberos preauthentication" unless there is a documented reason.')
      }
      if (truth(p.unconstraineddelegation)) {
        add(n, 'high', 'Unconstrained delegation', 'This object is trusted for unconstrained delegation. If compromised, it can impersonate users to other services.', 'Remove unconstrained delegation; use constrained or resource-based constrained delegation where possible.')
      }
      const delegates = arr(p.allowedtodelegate)
      if (delegates.length) {
        add(n, 'medium', 'Constrained delegation', `Allowed to delegate to: ${delegates.slice(0, 6).join(', ')}.`, 'Review the delegation targets and whether the account still needs them.')
      }
      if (truth(p.admincount)) add(n, 'medium', 'AdminCount=1 account', 'The object is marked AdminCount=1, which often means it was privileged and may still hold inherited rights.', 'Confirm whether the account still needs privileged access; remove it from protected groups or reset AdminCount only with care.')
      if (truth(p.pwdneverexpires)) add(n, 'low', 'Password never expires', 'The export sets PasswordNeverExpires on an enabled account.', 'Prefer a long unique password or a managed service account; document any exception.')
      if (truth(p.passwordnotrequired)) add(n, 'medium', 'Password not required', 'The account can have an empty password.', 'Set a strong password or disable the account.')
      if (n.kind === 'computer' && p.haslaps !== undefined && !truth(p.haslaps)) add(n, 'low', 'LAPS not detected', 'The export does not show LAPS on this computer.', 'Roll out Windows LAPS for local administrator password rotation.')
    }
  }
  return out
}

const readZip = (path: string): { name: string; text: string }[] => {
  const names = execFileSync('/usr/bin/unzip', ['-Z1', path], { maxBuffer: 8 * 1024 * 1024 }).toString().split(/\r?\n/).filter((n) => /\.json$/i.test(n))
  const out: { name: string; text: string }[] = []
  for (const n of names.slice(0, 20)) {
    const text = execFileSync('/usr/bin/unzip', ['-p', path, n], { maxBuffer: MAX }).toString()
    out.push({ name: basename(n), text })
  }
  return out
}

export async function runAdAudit(id: string, path: string): Promise<void> {
  const op = beginOp(id)
  const s = new SessionRun(id, op)
  try {
    const read = s.step('read', 'Read the BloodHound export')
    let files: { name: string; text: string }[] = []
    await s.run(read, async () => {
      if (!existsSync(path)) throw new Error('That export is not there any more.')
      if (statSync(path).size > MAX) throw new Error('That export is larger than 60 MB; trim it first.')
      files = path.toLowerCase().endsWith('.zip') ? readZip(path) : [{ name: basename(path), text: readFileSync(path, 'utf8') }]
      if (!files.length) throw new Error('No JSON files were found in that export.')
      return []
    })
    const analyze = s.step('analyze', 'Check Kerberos, delegation and privileged accounts')
    let findings: Finding[] = []
    await s.run(analyze, async () => {
      const nodes = files.flatMap((f) => parseAdExport(f.text, f.name))
      findings = analyzeAd(nodes, basename(path))
      saveFindings(id, findings)
      return findings
    })
    s.add(findings)
    s.finish()
    log('info', `AD review of ${basename(path)}: ${findings.length} findings`, id)
  } catch (e) {
    s.finish((e as Error).message)
    log('error', `AD review: ${(e as Error).message}`, id)
  } finally {
    endOp(id)
  }
}

export function startAdAudit(path: string): SessionInfo {
  if (!existsSync(path)) throw new Error('Choose a BloodHound JSON or ZIP export first.')
  if (!/\.(json|zip)$/i.test(path)) throw new Error('Choose a .json or .zip BloodHound export.')
  const s = createSession('ad-audit', `AD review: ${basename(path)}`, path)
  s.mode = undefined
  void runAdAudit(s.id, path)
  return s
}
