import type { Finding, SessionDetail, SessionInfo } from '../shared/types'
import { owaspChecklist, type OwaspChecklist, type OwaspTest } from './seckit/owasp'

/**
 * Puts a session's findings under the OWASP Top 10 (2025), and works out which of the ten its
 * steps could see, so a category with no findings shows "Checked" only when something looked.
 */

const STEP_TESTS: [RegExp, OwaspTest][] = [
  [/^(semgrep|bearer|bandit|gosec|mobsfscan|checkov|zizmor|hadolint|settings|binary)$/, 'sast'],
  [/^(gitleaks|trufflehog|js)$/, 'secrets'],
  [/^(osv-scanner|trivy|grype|syft|wpscan)$/, 'dependencies'],
  [/^(nuclei|zap|exposed|katana|access)$/, 'web-scan'],
  [/^(headers|tls|httpx)$/, 'headers'],
  [/^(spec|probe)$/, 'api']
]

/** The kinds of test a session ran, from its finished steps. */
export function testsOf(s: Pick<SessionInfo, 'kind' | 'reviewer' | 'steps'>): OwaspTest[] {
  const out = new Set<OwaspTest>()
  for (const st of s.steps) {
    if (st.status !== 'done') continue
    for (const [re, t] of STEP_TESTS) if (re.test(st.id)) out.add(t)
    // An AI that reads the code checks all ten; on a web scan the AI step only summarises.
    if ((st.id === 'ai' || st.id === 'claude' || st.id === 'code') && (s.kind === 'code-review' || s.kind === 'audit') && s.reviewer && s.reviewer !== 'none') out.add('code-review')
  }
  return [...out]
}

const text = (f: Finding): string => [f.tool, f.category, f.advisory ?? '', f.description ?? ''].join(' ')

/** The checklist for a session. Findings ruled out or marked as not a problem do not count. */
export function sessionOwasp(s: SessionDetail, children: SessionDetail[] = []): OwaspChecklist {
  const all = [s, ...children]
  const findings = all.flatMap((x) => x.findings).filter((f) => f.verdict !== 'false-positive' && f.triage !== 'not-a-problem')
  return owaspChecklist(
    findings.map((f) => ({
      title: f.title,
      // Secrets and package flaws are known kinds, whatever their wording.
      text: f.category === 'secret' ? `hard-coded secret ${text(f)}` : f.category === 'dependency' ? `vulnerable package ${text(f)}` : text(f),
      severity: f.severity,
      cwe: f.category === 'secret' ? [798] : f.category === 'dependency' ? [1395] : f.cwe ? [f.cwe] : []
    })),
    [...new Set(all.flatMap((x) => testsOf(x)))]
  )
}
