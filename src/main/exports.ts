/**
 * Findings in the formats other tools read: SARIF (GitHub code scanning and most editors),
 * DefectDojo's generic import, and the CycloneDX SBOM Syft wrote. Plus findings over time
 * (what is new, fixed or still there since the last session on the same target), and the
 * pre-commit hook and CI workflows MacSec suggests. Secrets never appear: findings only ever
 * hold the kind of key, its file and line.
 */
import type { Finding, SessionInfo, Severity } from '../shared/types'

const SARIF_LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' }
const SCORE: Record<Severity, string> = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '0.0' }

/** SARIF 2.1.0, one run per tool, with rules by title. */
export function toSarif(findings: Finding[], version: string): object {
  const byTool = new Map<string, Finding[]>()
  for (const f of findings) byTool.set(f.tool, [...(byTool.get(f.tool) ?? []), f])
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [...byTool].map(([tool, list]) => {
      const rules = new Map<string, Finding>()
      for (const f of list) rules.set(ruleId(f), f)
      return {
        tool: {
          driver: {
            name: tool === 'MacSec' ? 'MacSec' : `${tool} (via MacSec)`,
            version,
            informationUri: 'https://github.com/Pino10/macsec',
            rules: [...rules].map(([id, f]) => ({
              id,
              name: f.title.slice(0, 120),
              shortDescription: { text: f.title.slice(0, 300) },
              ...(f.description ? { fullDescription: { text: f.description.slice(0, 2000) } } : {}),
              ...(f.fix ? { help: { text: f.fix.slice(0, 2000) } } : {}),
              ...(f.url ? { helpUri: f.url } : {}),
              properties: { 'security-severity': SCORE[f.severity], tags: ['security', f.category, ...(f.cwe ? [`external/cwe/${f.cwe.toLowerCase()}`] : [])] }
            }))
          }
        },
        results: list.map((f) => ({
          ruleId: ruleId(f),
          level: SARIF_LEVEL[f.severity],
          message: { text: [f.title, f.description, f.fix ? `Fix: ${f.fix}` : ''].filter(Boolean).join('\n').slice(0, 4000) },
          ...(f.file ? { locations: [{ physicalLocation: { artifactLocation: { uri: f.file.replace(/\\/g, '/') }, ...(f.line ? { region: { startLine: f.line } } : {}) } }] } : {}),
          partialFingerprints: { macsecId: f.id }
        }))
      }
    })
  }
}

const ruleId = (f: Finding): string => (f.advisory ?? f.cwe ?? f.title).replace(/[^A-Za-z0-9._-]+/g, '-').slice(0, 120)

const DOJO: Record<Severity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' }

/** DefectDojo's "Generic Findings Import" JSON. */
export function toDefectDojo(findings: Finding[], s: SessionInfo): object {
  return {
    findings: findings.map((f) => ({
      title: f.title.slice(0, 500),
      severity: DOJO[f.severity],
      description: [f.description, f.why, f.impact, `Found by ${f.tool} in MacSec session ${s.id} (${s.target}).`].filter(Boolean).join('\n\n'),
      mitigation: f.fix ?? '',
      references: f.url ?? '',
      ...(f.file ? { file_path: f.file } : {}),
      ...(f.line ? { line: f.line } : {}),
      ...(f.cwe ? { cwe: Number(f.cwe.replace(/\D/g, '')) || undefined } : {}),
      ...(f.advisory ? { vulnerability_ids: [{ vulnerability_id: f.advisory }] } : {}),
      unique_id_from_tool: f.id,
      vuln_id_from_tool: f.advisory ?? f.cwe ?? undefined,
      active: f.triage !== 'fixed' && f.triage !== 'not-a-problem',
      false_p: f.verdict === 'false-positive' || f.triage === 'not-a-problem',
      risk_accepted: f.triage === 'accepted',
      date: (s.finishedAt ?? s.createdAt).slice(0, 10)
    }))
  }
}

export interface Compare {
  previous: { id: string; at: string } | null
  added: Finding[]
  fixed: Finding[]
  still: number
}

/** The latest finished session before this one, of the same kind and target. */
export function previousSession(all: SessionInfo[], s: SessionInfo): SessionInfo | null {
  return all.filter((x) => x.id !== s.id && x.kind === s.kind && x.target === s.target && x.status === 'done' && x.createdAt < s.createdAt).sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0] ?? null
}

/** Findings are matched by their id, which comes from the tool, file, line and title. */
export function compareFindings(now: Finding[], before: Finding[]): Omit<Compare, 'previous'> {
  const was = new Set(before.map((f) => f.id))
  const is = new Set(now.map((f) => f.id))
  // A finding that moved a few lines keeps its tool and title: match those as well.
  const loose = (f: Finding): string => `${f.tool}|${f.title}|${f.file ?? ''}`
  const wasLoose = new Set(before.map(loose))
  const isLoose = new Set(now.map(loose))
  return {
    added: now.filter((f) => !was.has(f.id) && !wasLoose.has(loose(f))),
    fixed: before.filter((f) => !is.has(f.id) && !isLoose.has(loose(f))),
    still: now.filter((f) => was.has(f.id) || wasLoose.has(loose(f))).length
  }
}

/** A Git pre-commit hook that stops a commit when Gitleaks finds a key in what is staged. */
export function preCommitHook(gitleaks: string): string {
  return `#!/bin/sh
# Written by MacSec: stops a commit that contains passwords or API keys.
# Skip it once with: git commit --no-verify
GITLEAKS="${gitleaks}"
[ -x "$GITLEAKS" ] || GITLEAKS="$(command -v gitleaks)"
if [ -z "$GITLEAKS" ]; then
  echo "MacSec pre-commit: Gitleaks is not installed, so keys were not checked." >&2
  exit 0
fi
"$GITLEAKS" git --pre-commit --staged --redact --no-banner --exit-code 1 || {
  echo "" >&2
  echo "MacSec stopped this commit: a password or key is in the staged files (shown above, masked)." >&2
  echo "Move it to an environment variable, then commit again." >&2
  exit 1
}
`
}

/** A CI workflow that runs MacSec's free scanners on every push and pull request. */
export function ciWorkflow(kind: 'github' | 'azure'): string {
  if (kind === 'github')
    return `# Written by MacSec: the same free scanners MacSec runs, on every push and pull request.
# Pin each action to a commit SHA before relying on it (zizmor, which MacSec runs, will remind you).
name: Security
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
          fetch-depth: 0
      - name: Semgrep
        run: |
          pipx run semgrep scan --config p/default --config p/owasp-top-ten --sarif --output semgrep.sarif --metrics off || true
      - name: Gitleaks (keys and passwords, whole history)
        run: |
          docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:latest git /repo --redact --no-banner --exit-code 1
      - name: OSV-Scanner (known flaws in packages)
        run: |
          docker run --rm -v "$PWD:/src" ghcr.io/google/osv-scanner:latest scan source -r /src || true
      - name: Trivy (packages and configuration)
        run: |
          docker run --rm -v "$PWD:/src" aquasec/trivy:latest fs --scanners vuln,misconfig --exit-code 0 /src
      - name: zizmor (GitHub Actions)
        run: |
          pipx run zizmor --format plain . || true
      - name: Upload to code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: semgrep.sarif
`
  return `# Written by MacSec: the same free scanners MacSec runs, on every push and pull request.
trigger:
  branches:
    include: [main]
pr:
  branches:
    include: ['*']
pool:
  vmImage: ubuntu-latest
steps:
  - checkout: self
    fetchDepth: 0
    persistCredentials: false
  - script: pipx run semgrep scan --config p/default --config p/owasp-top-ten --metrics off --error
    displayName: Semgrep
  - script: docker run --rm -v "$(Build.SourcesDirectory):/repo" zricethezav/gitleaks:latest git /repo --redact --no-banner --exit-code 1
    displayName: Gitleaks (keys and passwords, whole history)
  - script: docker run --rm -v "$(Build.SourcesDirectory):/src" ghcr.io/google/osv-scanner:latest scan source -r /src
    displayName: OSV-Scanner (known flaws in packages)
    continueOnError: true
  - script: docker run --rm -v "$(Build.SourcesDirectory):/src" aquasec/trivy:latest fs --scanners vuln,misconfig --exit-code 0 /src
    displayName: Trivy (packages and configuration)
`
}

/** Laramac's sites, read from its settings, so MacSec can offer their addresses. Read only. */
export function laramacSites(settingsText: string): { name: string; url: string }[] {
  try {
    const s = JSON.parse(settingsText) as { tld?: string; siteConfig?: Record<string, { secure?: boolean }>; httpPort?: number; httpsPort?: number }
    const tld = (s.tld ?? 'test').replace(/[^a-z0-9-]/gi, '')
    return Object.entries(s.siteConfig ?? {})
      .filter(([n]) => /^[A-Za-z0-9._-]+$/.test(n))
      .map(([name, c]) => ({ name, url: `${c.secure ? 'https' : 'http'}://${name.toLowerCase()}.${tld}` }))
  } catch {
    return []
  }
}
