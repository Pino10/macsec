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

// ---------------------------------------------------------------- zizmor (GitHub Actions)

export function parseZizmor(text: string, root: string): Finding[] {
  type Loc = { symbolic?: { key?: { Local?: { verbatim_path?: string } }; annotation?: string; kind?: string }; concrete?: { location?: { start_point?: { row?: number } }; feature?: string } }
  type R = { ident: string; desc: string; url?: string; determinations?: { confidence?: string; severity?: string }; locations?: Loc[]; ignored?: boolean }
  return (json<R[]>(text) ?? [])
    .filter((r) => !r.ignored)
    .map((r) => {
      const primary = r.locations?.find((l) => l.symbolic?.kind === 'Primary') ?? r.locations?.[0]
      let s = sev(r.determinations?.severity)
      // Low-confidence results drop a level, like Bandit's.
      if (r.determinations?.confidence === 'Low' && s !== 'info') s = s === 'critical' ? 'high' : s === 'high' ? 'medium' : s === 'medium' ? 'low' : s
      const row = primary?.concrete?.location?.start_point?.row
      return mk('zizmor', 'config', {
        severity: s,
        title: `${r.desc} (${r.ident})`,
        file: rel(root, primary?.symbolic?.key?.Local?.verbatim_path),
        line: row !== undefined ? row + 1 : undefined,
        description: primary?.symbolic?.annotation,
        snippet: primary?.concrete?.feature?.slice(0, 600),
        url: r.url
      })
    })
}

// ---------------------------------------------------------------- Hadolint (Dockerfiles)

/** Hadolint rules that matter for security, rated higher than its style advice. */
const HADOLINT_SECURITY: Record<string, Severity> = { DL3002: 'high', DL3004: 'medium', DL3007: 'low', DL3006: 'low', DL3020: 'low', DL4006: 'low', DL3008: 'low', DL3013: 'low', DL3016: 'low', DL3018: 'low', DL3028: 'low' }

export function parseHadolint(text: string, root: string): Finding[] {
  type R = { code: string; column?: number; file: string; level: string; line: number; message: string }
  return (json<R[]>(text) ?? [])
    .filter((r) => r.level !== 'style' && (r.level === 'error' || r.level === 'warning' || HADOLINT_SECURITY[r.code]))
    .map((r) =>
      mk('Hadolint', 'config', {
        severity: HADOLINT_SECURITY[r.code] ?? (r.level === 'error' ? 'medium' : 'low'),
        title: `${r.message.split('. ')[0].slice(0, 140)} (${r.code})`,
        file: rel(root, r.file),
        line: r.line,
        description: r.message,
        url: /^DL\d+$/.test(r.code) ? `https://github.com/hadolint/hadolint/wiki/${r.code}` : undefined
      })
    )
}

// ---------------------------------------------------------------- Grype

export function parseGrype(text: string, root: string): Finding[] {
  type M = {
    vulnerability: { id: string; severity: string; description?: string; urls?: string[]; fix?: { versions?: string[]; state?: string }; epss?: { epss: number }[] }
    relatedVulnerabilities?: { id: string; description?: string; cwes?: unknown }[]
    artifact: { name: string; version: string; type: string; locations?: { path?: string; accessPath?: string }[] }
  }
  const d = json<{ matches?: M[] }>(text)
  return (d?.matches ?? []).map((m) => {
    const v = m.vulnerability
    const fixes = v.fix?.state === 'fixed' ? v.fix.versions ?? [] : []
    const epss = v.epss?.[0]?.epss
    return mk('Grype', 'dependency', {
      severity: sev(v.severity === 'Negligible' ? 'info' : v.severity),
      title: `${m.artifact.name} ${m.artifact.version}: ${v.id}`,
      file: rel(root, m.artifact.locations?.[0]?.accessPath ?? m.artifact.locations?.[0]?.path),
      advisory: v.id,
      description: (v.description ?? m.relatedVulnerabilities?.find((r) => r.description)?.description ?? '').slice(0, 1200) + (epss !== undefined ? ` Chance of being exploited in the next 30 days (EPSS): ${(epss * 100).toFixed(1)}%.` : ''),
      fix: fixes.length ? `Update ${m.artifact.name} to ${fixes.find((f) => newerOrEqual(f, m.artifact.version)) ?? fixes[0]}.` : 'No fixed version yet.',
      url: v.urls?.[0]
    })
  })
}

const newerOrEqual = (a: string, b: string): boolean => {
  const pa = a.split(/[.-]/).map((x) => parseInt(x, 10) || 0)
  const pb = b.split(/[.-]/).map((x) => parseInt(x, 10) || 0)
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) > (pb[i] ?? 0)
  return true
}

// ---------------------------------------------------------------- Syft (SBOM and licences)

export interface SbomSummary {
  components: number
  byType: Record<string, number>
  licences: Record<string, number>
}

/** CycloneDX JSON from Syft: what the project is made of. */
export function sbomSummary(text: string): SbomSummary {
  type C = { type?: string; name: string; licenses?: { license?: { id?: string; name?: string }; expression?: string }[]; properties?: { name: string; value: string }[] }
  const d = json<{ components?: C[] }>(text)
  const out: SbomSummary = { components: 0, byType: {}, licences: {} }
  for (const c of d?.components ?? []) {
    if (c.type === 'file' || c.type === 'operating-system') continue
    out.components++
    const t = c.properties?.find((p) => p.name === 'syft:package:type')?.value ?? c.type ?? 'other'
    out.byType[t] = (out.byType[t] ?? 0) + 1
    for (const l of c.licenses ?? []) {
      const id = l.license?.id ?? l.license?.name ?? l.expression ?? 'unknown'
      out.licences[id] = (out.licences[id] ?? 0) + 1
    }
  }
  return out
}

/** Strong copyleft licences in dependencies: worth knowing before shipping closed-source software. */
export function parseSyftLicences(text: string, root: string): Finding[] {
  type C = { name: string; version?: string; licenses?: { license?: { id?: string; name?: string }; expression?: string }[]; properties?: { name: string; value: string }[] }
  const d = json<{ components?: C[] }>(text)
  const out: Finding[] = []
  for (const c of d?.components ?? []) {
    const ids = (c.licenses ?? []).map((l) => l.license?.id ?? l.license?.name ?? l.expression ?? '').filter(Boolean)
    const strong = ids.find((id) => /\b(AGPL|GPL|SSPL|EUPL|OSL)\b/i.test(id) && !/LGPL/i.test(id))
    if (!strong) continue
    out.push(
      mk('Syft', 'dependency', {
        severity: /AGPL|SSPL/i.test(strong) ? 'medium' : 'low',
        title: `${c.name}${c.version ? ` ${c.version}` : ''} is licensed ${strong}`,
        file: rel(root, c.properties?.find((p) => p.name === 'syft:location:0:path')?.value),
        description: /AGPL|SSPL/i.test(strong) ? 'Network copyleft: offering this software as a service can oblige you to publish your source code.' : 'Copyleft: distributing software that includes it can oblige you to publish your source code under the same licence.',
        fix: 'Check the licence fits how you ship the software, or choose a package with a permissive licence.'
      })
    )
  }
  return out
}

// ---------------------------------------------------------------- Checkov (infrastructure as code)

/** Checkov's open-source checks carry no severity, so it is judged from what the check is about. */
export function checkovSeverity(id: string, name: string): Severity {
  const t = `${id} ${name}`.toLowerCase()
  if (/0\.0\.0\.0|public|anonymous|wildcard|\*|admin|root|privileged|secret|password|credential|hardcoded/.test(t)) return 'high'
  if (/encrypt|tls|ssl|https|logging|mfa|kms|versioning|backup/.test(t)) return 'medium'
  return 'low'
}

export function parseCheckov(text: string, root: string): Finding[] {
  type F = { check_id: string; check_name: string; file_path: string; file_line_range?: number[]; resource?: string; severity?: string | null; guideline?: string | null }
  type R = { check_type?: string; results?: { failed_checks?: F[] } }
  const d = json<R | R[]>(text)
  const list = Array.isArray(d) ? d : d ? [d] : []
  const out: Finding[] = []
  for (const r of list)
    for (const f of r.results?.failed_checks ?? [])
      out.push(
        mk('Checkov', 'config', {
          severity: f.severity ? sev(f.severity) : checkovSeverity(f.check_id, f.check_name),
          title: `${f.check_name} (${f.check_id})`,
          file: rel(root, f.file_path.replace(/^\//, '')),
          line: f.file_line_range?.[0],
          description: f.resource ? `In ${f.resource}${r.check_type ? ` (${r.check_type})` : ''}.` : undefined,
          url: f.guideline ?? undefined
        })
      )
  return out
}

// ---------------------------------------------------------------- ZAP baseline (passive)

export function parseZap(text: string): Finding[] {
  type I = { uri: string; method?: string; param?: string; evidence?: string }
  type A = { pluginid: string; name: string; riskcode: string; confidence?: string; desc?: string; solution?: string; reference?: string; cweid?: string; instances?: I[]; count?: string }
  const d = json<{ site?: { '@name': string; alerts?: A[] }[] }>(text)
  const strip = (h?: string): string => (h ?? '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim()
  const out: Finding[] = []
  for (const site of d?.site ?? [])
    for (const a of site.alerts ?? []) {
      const risk = Number(a.riskcode)
      let s: Severity = risk >= 3 ? 'high' : risk === 2 ? 'medium' : risk === 1 ? 'low' : 'info'
      if (a.confidence === '1' && s !== 'info') s = s === 'high' ? 'medium' : 'low'
      const inst = a.instances?.[0]
      out.push(
        mk('ZAP', 'web', {
          severity: s,
          title: `${a.name}${a.instances && a.instances.length > 1 ? ` (${a.instances.length} places)` : ''}`,
          url: inst?.uri ?? site['@name'],
          cwe: a.cweid && a.cweid !== '-1' && a.cweid !== '0' ? `CWE-${a.cweid}` : undefined,
          description: strip(a.desc).slice(0, 1000) + (inst?.param ? ` Parameter: ${inst.param}.` : ''),
          fix: strip(a.solution).slice(0, 600) || undefined,
          advisory: `ZAP-${a.pluginid}`
        })
      )
    }
  return out
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
