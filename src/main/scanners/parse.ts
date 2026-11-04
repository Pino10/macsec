/**
 * Each scanner writes its own JSON. These turn them all into one kind of Finding, so the report
 * can sort, merge and count them the same way. Secrets are never copied into a finding: only
 * the kind of key, the file and the line.
 */
import { createHash } from 'crypto'
import { isAbsolute, relative } from 'path'
import type { Finding, FindingCategory, Severity } from '../../shared/types'

export function fid(...parts: (string | number | undefined)[]): string {
  return createHash('sha1').update(parts.map((p) => String(p ?? '')).join('|')).digest('hex').slice(0, 12)
}

const rel = (root: string, f: string | undefined): string | undefined => {
  if (!f) return undefined
  const p = f.replace(/^file:\/\//, '')
  return isAbsolute(p) ? relative(root, p) : p.replace(/^\.\//, '')
}

/** Maps every scanner's words for severity onto ours. */
export function sev(v: unknown): Severity {
  const s = String(v ?? '').toLowerCase()
  if (/crit/.test(s)) return 'critical'
  if (/^(high|error)$/.test(s)) return 'high'
  if (/^(medium|moderate|warning|warn)$/.test(s)) return 'medium'
  if (/^(low|note)$/.test(s)) return 'low'
  const n = Number(s)
  if (!Number.isNaN(n) && s !== '') return n >= 9 ? 'critical' : n >= 7 ? 'high' : n >= 4 ? 'medium' : n > 0 ? 'low' : 'info'
  return 'info'
}

const cweOf = (v: unknown): string | undefined => {
  const first = Array.isArray(v) ? v[0] : v
  const m = /CWE-?(\d+)/i.exec(String(first ?? '')) ?? /^(\d+)$/.exec(String(first ?? ''))
  return m ? `CWE-${m[1]}` : undefined
}

const mk = (tool: string, category: FindingCategory, f: Omit<Finding, 'id' | 'tool' | 'category'>): Finding => ({
  id: fid(tool, f.file, f.line, f.title, f.advisory),
  tool,
  category,
  ...f
})

const json = <T>(text: string): T | null => {
  try {
    return JSON.parse(text) as T
  } catch {
    return null
  }
}
const jsonLines = <T>(text: string): T[] =>
  text
    .split('\n')
    .map((l) => json<T>(l.trim()))
    .filter((x): x is T => !!x)

// ---------------------------------------------------------------- Semgrep

export function parseSemgrep(text: string, root: string): Finding[] {
  type R = { check_id: string; path: string; start: { line: number }; extra: { message: string; severity: string; lines?: string; fix?: string; metadata?: { cwe?: string | string[]; references?: string[]; confidence?: string; impact?: string; owasp?: string | string[] } } }
  const d = json<{ results?: R[] }>(text)
  return (d?.results ?? []).map((r) => {
    const m = r.extra.metadata ?? {}
    // Semgrep's ERROR is "likely a real problem"; its impact field is finer when present.
    const s = m.impact ? sev(m.impact) : sev(r.extra.severity)
    return mk('Semgrep', 'code', {
      severity: s,
      title: r.check_id.split('.').pop()!.replace(/[-_]/g, ' '),
      file: rel(root, r.path),
      line: r.start.line,
      cwe: cweOf(m.cwe),
      description: r.extra.message,
      fix: r.extra.fix,
      snippet: r.extra.lines && r.extra.lines !== 'requires login' ? r.extra.lines.slice(0, 600) : undefined,
      url: m.references?.[0]
    })
  })
}

// ---------------------------------------------------------------- Bearer

export function parseBearer(text: string, root: string): Finding[] {
  type R = { cwe_ids?: string[]; id: string; title: string; description?: string; documentation_url?: string; line_number?: number; full_filename?: string; filename?: string; code_extract?: string }
  const d = json<Record<string, R[]>>(text) ?? {}
  const out: Finding[] = []
  for (const level of ['critical', 'high', 'medium', 'low', 'warning']) {
    for (const r of d[level] ?? []) {
      out.push(
        mk('Bearer', 'code', {
          severity: level === 'warning' ? 'low' : sev(level),
          title: r.title,
          file: rel(root, r.full_filename ?? r.filename),
          line: r.line_number,
          cwe: cweOf(r.cwe_ids),
          description: r.description?.split('\n## ')[0]?.replace(/^## Description\s*/i, '').trim().slice(0, 1200),
          snippet: r.code_extract?.slice(0, 600),
          url: r.documentation_url
        })
      )
    }
  }
  return out
}

// ---------------------------------------------------------------- Bandit

export function parseBandit(text: string, root: string): Finding[] {
  type R = { filename: string; line_number: number; issue_severity: string; issue_confidence: string; issue_text: string; test_id: string; test_name: string; issue_cwe?: { id: number; link: string }; code?: string; more_info?: string }
  const d = json<{ results?: R[] }>(text)
  return (d?.results ?? []).map((r) => {
    // Low-confidence findings drop a level: Bandit is cautious.
    let s = sev(r.issue_severity)
    if (r.issue_confidence === 'LOW' && s !== 'info') s = s === 'high' ? 'medium' : s === 'medium' ? 'low' : s
    return mk('Bandit', 'code', {
      severity: s,
      title: `${r.test_name.replace(/_/g, ' ')} (${r.test_id})`,
      file: rel(root, r.filename),
      line: r.line_number,
      cwe: r.issue_cwe ? `CWE-${r.issue_cwe.id}` : undefined,
      description: r.issue_text,
      snippet: r.code?.slice(0, 600),
      url: r.more_info
    })
  })
}

// ---------------------------------------------------------------- gosec

export function parseGosec(text: string, root: string): Finding[] {
  type R = { severity: string; confidence: string; cwe?: { id: string }; rule_id: string; details: string; file: string; line: string; code?: string }
  const d = json<{ Issues?: R[] }>(text)
  return (d?.Issues ?? []).map((r) =>
    mk('gosec', 'code', {
      severity: sev(r.severity),
      title: `${r.details} (${r.rule_id})`,
      file: rel(root, r.file),
      line: parseInt(r.line, 10) || undefined,
      cwe: r.cwe?.id ? `CWE-${r.cwe.id}` : undefined,
      snippet: r.code?.slice(0, 600)
    })
  )
}

// ---------------------------------------------------------------- Secrets

/** Which kinds of secret matter most. */
function secretSeverity(kind: string): Severity {
  const k = kind.toLowerCase()
  if (/(private[-_ ]?key|aws|gcp|azure|stripe|live|github|gitlab|slack|openai|anthropic|database|postgres|mysql|mongodb|twilio|sendgrid|jwt)/.test(k)) return 'critical'
  return 'high'
}

export function parseGitleaks(text: string, root: string): Finding[] {
  type R = { RuleID: string; Description: string; File: string; StartLine: number; Commit?: string; Author?: string; Date?: string; Entropy?: number }
  return (json<R[]>(text) ?? []).map((r) =>
    mk('Gitleaks', 'secret', {
      severity: secretSeverity(r.RuleID),
      title: `${r.Description || r.RuleID} in code`,
      file: rel(root, r.File),
      line: r.StartLine,
      cwe: 'CWE-798',
      description: r.Commit ? `Found in Git history, commit ${r.Commit.slice(0, 10)}${r.Date ? ` (${r.Date.slice(0, 10)})` : ''}. It stays in the history even if the file changed since.` : 'The value is in the file now.',
      fix: 'Revoke and replace the key at its provider first, then move it to an environment variable or secret store. If it was ever pushed, assume it was copied.'
    })
  )
}

export function parseTrufflehog(text: string, root: string): Finding[] {
  type R = { DetectorName: string; Verified: boolean; SourceMetadata?: { Data?: { Filesystem?: { file: string; line?: number }; Git?: { file: string; line?: number; commit?: string } } } }
  return jsonLines<R>(text)
    .filter((r) => r.DetectorName)
    .map((r) => {
      const fs = r.SourceMetadata?.Data?.Filesystem
      const git = r.SourceMetadata?.Data?.Git
      return mk('TruffleHog', 'secret', {
        severity: r.Verified ? 'critical' : secretSeverity(r.DetectorName),
        title: `${r.DetectorName} key${r.Verified ? ' (confirmed live)' : ''}`,
        file: rel(root, fs?.file ?? git?.file),
        line: fs?.line ?? git?.line,
        cwe: 'CWE-798',
        description: git?.commit ? `In Git history, commit ${git.commit.slice(0, 10)}.` : undefined,
        fix: 'Revoke and replace the key at its provider, then keep it out of the code.'
      })
    })
}

// ---------------------------------------------------------------- Dependencies

export function parseOsv(text: string, root: string): Finding[] {
  type V = { id: string; summary?: string; details?: string; aliases?: string[]; database_specific?: { severity?: string; cwe_ids?: string[] }; affected?: { ranges?: { events?: { fixed?: string }[] }[] }[] }
  type P = { package: { name: string; version: string; ecosystem: string }; vulnerabilities?: V[]; groups?: { ids: string[]; max_severity?: string }[] }
  const d = json<{ results?: { source?: { path: string }; packages?: P[] }[] }>(text)
  const out: Finding[] = []
  for (const r of d?.results ?? []) {
    for (const p of r.packages ?? []) {
      for (const v of p.vulnerabilities ?? []) {
        const group = p.groups?.find((g) => g.ids.includes(v.id))
        const s = group?.max_severity ? sev(group.max_severity) : sev(v.database_specific?.severity ?? 'medium')
        const fixed = v.affected?.flatMap((a) => a.ranges ?? []).flatMap((x) => x.events ?? []).find((e) => e.fixed)?.fixed
        const cve = v.aliases?.find((a) => a.startsWith('CVE-'))
        out.push(
          mk('OSV-Scanner', 'dependency', {
            severity: s,
            title: `${p.package.name} ${p.package.version}: ${v.summary ?? v.id}`,
            file: rel(root, r.source?.path),
            advisory: cve ?? v.id,
            cwe: cweOf(v.database_specific?.cwe_ids),
            description: v.details?.slice(0, 1200),
            fix: fixed ? `Update ${p.package.name} to ${fixed} or later.` : 'No fixed version yet: check the advisory for a workaround.',
            url: `https://osv.dev/vulnerability/${v.id}`
          })
        )
      }
    }
  }
  return out
}

export function parseTrivy(text: string, root: string): Finding[] {
  type V = { VulnerabilityID: string; PkgName: string; InstalledVersion: string; FixedVersion?: string; Severity: string; Title?: string; Description?: string; PrimaryURL?: string; CweIDs?: string[] }
  type M = { ID: string; Title: string; Description?: string; Message?: string; Resolution?: string; Severity: string; PrimaryURL?: string; CauseMetadata?: { StartLine?: number } }
  const d = json<{ Results?: { Target: string; Vulnerabilities?: V[]; Misconfigurations?: M[] }[] }>(text)
  const out: Finding[] = []
  for (const r of d?.Results ?? []) {
    for (const v of r.Vulnerabilities ?? []) {
      out.push(
        mk('Trivy', 'dependency', {
          severity: sev(v.Severity),
          title: `${v.PkgName} ${v.InstalledVersion}: ${v.Title ?? v.VulnerabilityID}`,
          file: rel(root, r.Target),
          advisory: v.VulnerabilityID,
          cwe: cweOf(v.CweIDs),
          description: v.Description?.slice(0, 1200),
          fix: v.FixedVersion ? `Update ${v.PkgName} to ${v.FixedVersion}.` : 'No fixed version yet.',
          url: v.PrimaryURL
        })
      )
    }
    for (const m of r.Misconfigurations ?? []) {
      out.push(
        mk('Trivy', 'config', {
          severity: sev(m.Severity),
          title: m.Title,
          file: rel(root, r.Target),
          line: m.CauseMetadata?.StartLine,
          description: m.Message ?? m.Description,
          fix: m.Resolution,
          url: m.PrimaryURL
        })
      )
    }
  }
  return out
}

// ---------------------------------------------------------------- Merging

const RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

/**
 * Different scanners often report the same problem. Dependency advisories are merged by package
 * and advisory, secrets and code findings by file and line; the most severe wording wins and the
 * other tools are listed with it.
 */
export function mergeFindings(list: Finding[]): Finding[] {
  const byKey = new Map<string, Finding>()
  for (const f of list) {
    const pkg = f.category === 'dependency' ? f.title.split(':')[0].split(' ')[0] : ''
    const key =
      f.category === 'dependency'
        ? `dep|${pkg}|${f.advisory}`
        : f.category === 'secret'
          ? `sec|${f.file}|${f.line}`
          : `${f.category}|${f.file}|${f.line}|${f.cwe ?? f.title.toLowerCase()}`
    const prev = byKey.get(key)
    if (!prev) byKey.set(key, { ...f })
    else {
      const tools = new Set([...prev.tool.split(', '), f.tool])
      const keep = RANK[f.severity] < RANK[prev.severity] ? { ...f } : prev
      keep.tool = [...tools].join(', ')
      keep.fix = keep.fix ?? f.fix
      keep.cwe = keep.cwe ?? f.cwe
      keep.url = keep.url ?? f.url
      byKey.set(key, keep)
    }
  }
  return [...byKey.values()].sort((a, b) => RANK[a.severity] - RANK[b.severity] || (a.file ?? '').localeCompare(b.file ?? '') || (a.line ?? 0) - (b.line ?? 0))
}

export function countBySeverity(list: Finding[]): Record<Severity, number> {
  const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  // Findings you marked fixed, accepted or not a problem no longer count.
  for (const f of list) if (!f.triage) c[f.severity]++
  return c
}
