import { mkdtempSync, mkdirSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
import { hashFor, pickAsset, pickChecksum, toolEnv } from '../src/main/toolbox'
import { countBySeverity, mergeFindings, parseBandit, parseBearer, parseGitleaks, parseGosec, parseOsv, parseSemgrep, parseTrivy, parseTrufflehog, sev } from '../src/main/scanners/parse'
import { planScanners, projectStats } from '../src/main/scanners/plan'
import { parseAiOutput, rankFiles, reviewPrompt } from '../src/main/aireview'
import { markdownToHtml, sessionHtml } from '../src/main/report'
import { redact } from '../src/main/logs'
import { azureOrg } from '../src/main/projects'
import { setRoot } from '../src/main/paths'

const A = (...names: string[]): { name: string; url: string }[] => names.map((name) => ({ name, url: `https://x/${name}` }))

describe('picking the right download', () => {
  const cases: [string, string[], string, string][] = [
    ['gitleaks', ['gitleaks_8.28.0_darwin_arm64.tar.gz', 'gitleaks_8.28.0_darwin_x64.tar.gz', 'gitleaks_8.28.0_linux_arm64.tar.gz', 'gitleaks_8.28.0_checksums.txt'], 'gitleaks_8.28.0_darwin_arm64.tar.gz', 'gitleaks_8.28.0_darwin_x64.tar.gz'],
    ['trivy', ['trivy_0.65.0_macOS-ARM64.tar.gz', 'trivy_0.65.0_macOS-64bit.tar.gz', 'trivy_0.65.0_macOS-ARM64.tar.gz.pem', 'trivy_0.65.0_checksums.txt'], 'trivy_0.65.0_macOS-ARM64.tar.gz', 'trivy_0.65.0_macOS-64bit.tar.gz'],
    ['nuclei', ['nuclei_3.4.7_macOS_arm64.zip', 'nuclei_3.4.7_macOS_amd64.zip', 'nuclei_3.4.7_linux_amd64.zip', 'nuclei_3.4.7_checksums.txt'], 'nuclei_3.4.7_macOS_arm64.zip', 'nuclei_3.4.7_macOS_amd64.zip'],
    ['osv', ['osv-scanner_darwin_arm64', 'osv-scanner_darwin_amd64', 'osv-scanner_linux_amd64', 'osv-scanner_SHA256SUMS'], 'osv-scanner_darwin_arm64', 'osv-scanner_darwin_amd64'],
    ['uv', ['uv-aarch64-apple-darwin.tar.gz', 'uv-aarch64-apple-darwin.tar.gz.sha256', 'uv-x86_64-apple-darwin.tar.gz', 'uv-x86_64-apple-darwin.tar.gz.sha256', 'uv-x86_64-unknown-linux-gnu.tar.gz'], 'uv-aarch64-apple-darwin.tar.gz', 'uv-x86_64-apple-darwin.tar.gz'],
    ['trufflehog', ['trufflehog_3.90.5_darwin_arm64.tar.gz', 'trufflehog_3.90.5_darwin_amd64.tar.gz', 'trufflehog_3.90.5_checksums.txt', 'trufflehog_3.90.5_checksums.txt.sig'], 'trufflehog_3.90.5_darwin_arm64.tar.gz', 'trufflehog_3.90.5_darwin_amd64.tar.gz']
  ]
  for (const [name, assets, arm, x64] of cases) {
    it(name, () => {
      expect(pickAsset(A(...assets), 'arm64')?.name).toBe(arm)
      expect(pickAsset(A(...assets), 'x64')?.name).toBe(x64)
    })
  }
  it('finds the checksum list or the per-file checksum', () => {
    expect(pickChecksum(A('a_darwin_arm64.tar.gz', 'a_checksums.txt', 'a_checksums.txt.sig'), { name: 'a_darwin_arm64.tar.gz', url: '' })?.name).toBe('a_checksums.txt')
    expect(pickChecksum(A('uv-aarch64-apple-darwin.tar.gz', 'uv-aarch64-apple-darwin.tar.gz.sha256', 'sha256.sum'), { name: 'uv-aarch64-apple-darwin.tar.gz', url: '' })?.name).toBe('uv-aarch64-apple-darwin.tar.gz.sha256')
    expect(pickChecksum(A('osv-scanner_darwin_arm64', 'osv-scanner_SHA256SUMS'), { name: 'osv-scanner_darwin_arm64', url: '' })?.name).toBe('osv-scanner_SHA256SUMS')
    const h = 'a'.repeat(64)
    expect(hashFor(`${h}  gitleaks_darwin_arm64.tar.gz\n${'b'.repeat(64)}  other`, 'gitleaks_darwin_arm64.tar.gz')).toBe(h)
    expect(hashFor(`${h} *uv-aarch64-apple-darwin.tar.gz\n`, 'uv-aarch64-apple-darwin.tar.gz')).toBe(h)
    expect(hashFor(`${h}\n`, 'anything')).toBe(h)
  })
  it('runs tools with a private home inside MacSec', () => {
    setRoot('/tmp/macsec-test-root')
    const env = toolEnv()
    expect(env.HOME).toBe('/tmp/macsec-test-root/tools/home')
    expect(env.TRIVY_CACHE_DIR).toContain('/tmp/macsec-test-root/tools/home')
    expect(env.SEMGREP_SEND_METRICS).toBe('off')
  })
})

describe('reading scanner output', () => {
  const root = '/proj'
  it('Semgrep', () => {
    const f = parseSemgrep(JSON.stringify({ results: [{ check_id: 'php.lang.security.injection.tainted-sql-string', path: '/proj/app/User.php', start: { line: 12 }, extra: { message: 'SQL built from input', severity: 'ERROR', lines: '$db->query("..." . $_GET["id"])', metadata: { cwe: ['CWE-89: SQL Injection'], impact: 'HIGH', references: ['https://owasp.org'] } } }] }), root)
    expect(f[0]).toMatchObject({ severity: 'high', file: 'app/User.php', line: 12, cwe: 'CWE-89', title: 'tainted sql string' })
  })
  it('Bearer', () => {
    const f = parseBearer(JSON.stringify({ critical: [{ cwe_ids: ['89'], id: 'php_lang_sql', title: 'SQL injection', full_filename: '/proj/a.php', line_number: 3, description: '## Description\nUnsanitized input in SQL.\n## Remediations\n...' }], warning: [{ id: 'x', title: 'Weak', filename: 'b.php', line_number: 1 }] }), root)
    expect(f.map((x) => x.severity)).toEqual(['critical', 'low'])
    expect(f[0].cwe).toBe('CWE-89')
    expect(f[0].description).toBe('Unsanitized input in SQL.')
  })
  it('Bandit lowers low-confidence findings', () => {
    const f = parseBandit(JSON.stringify({ results: [{ filename: './a.py', line_number: 4, issue_severity: 'HIGH', issue_confidence: 'LOW', issue_text: 'shell=True', test_id: 'B602', test_name: 'subprocess_popen_with_shell_equals_true', issue_cwe: { id: 78, link: '' } }] }), root)
    expect(f[0]).toMatchObject({ severity: 'medium', cwe: 'CWE-78', file: 'a.py' })
  })
  it('gosec', () => {
    expect(parseGosec(JSON.stringify({ Issues: [{ severity: 'HIGH', confidence: 'HIGH', cwe: { id: '89' }, rule_id: 'G201', details: 'SQL string formatting', file: '/proj/db.go', line: '20-22' }] }), root)[0]).toMatchObject({ line: 20, cwe: 'CWE-89', file: 'db.go' })
  })
  it('Gitleaks and TruffleHog never keep the secret', () => {
    const g = parseGitleaks(JSON.stringify([{ RuleID: 'aws-access-token', Description: 'AWS Access Key', File: 'config/app.php', StartLine: 9, Secret: 'AKIAREDACTED', Match: 'AKIA...' }]), root)
    expect(g[0]).toMatchObject({ severity: 'critical', category: 'secret', file: 'config/app.php', line: 9 })
    expect(JSON.stringify(g)).not.toContain('AKIA')
    const t = parseTrufflehog(`${JSON.stringify({ DetectorName: 'Stripe', Verified: false, Raw: 'sk_live_secret', SourceMetadata: { Data: { Filesystem: { file: '/proj/.env', line: 2 } } } })}\nnot json\n`, root)
    expect(t[0]).toMatchObject({ file: '.env', line: 2, severity: 'critical' })
    expect(JSON.stringify(t)).not.toContain('sk_live')
  })
  it('OSV and Trivy, merged into one finding per advisory', () => {
    const o = parseOsv(JSON.stringify({ results: [{ source: { path: '/proj/composer.lock' }, packages: [{ package: { name: 'guzzlehttp/guzzle', version: '7.4.0', ecosystem: 'Packagist' }, vulnerabilities: [{ id: 'GHSA-25mq-v84q-4j7r', summary: 'Cookie leak', aliases: ['CVE-2022-31042'], affected: [{ ranges: [{ events: [{ introduced: '0' }, { fixed: '7.4.4' }] }] }] }], groups: [{ ids: ['GHSA-25mq-v84q-4j7r'], max_severity: '7.5' }] }] }] }), root)
    expect(o[0]).toMatchObject({ severity: 'high', advisory: 'CVE-2022-31042', file: 'composer.lock' })
    expect(o[0].fix).toContain('7.4.4')
    const t = parseTrivy(JSON.stringify({ Results: [{ Target: 'composer.lock', Vulnerabilities: [{ VulnerabilityID: 'CVE-2022-31042', PkgName: 'guzzlehttp/guzzle', InstalledVersion: '7.4.0', FixedVersion: '7.4.4', Severity: 'HIGH', Title: 'Cookie leak' }] }, { Target: 'Dockerfile', Misconfigurations: [{ ID: 'DS002', Title: 'Image user should not be root', Severity: 'HIGH', Resolution: 'Add USER', CauseMetadata: { StartLine: 1 } }] }] }), root)
    const merged = mergeFindings([...o, ...t])
    expect(merged).toHaveLength(2)
    expect(merged.find((m) => m.category === 'dependency')!.tool).toBe('OSV-Scanner, Trivy')
    expect(countBySeverity(merged).high).toBe(2)
  })
  it('maps every way of saying severity', () => {
    expect(['CRITICAL', 'ERROR', 'MODERATE', 'warning', 'note', '9.8', '5.3', ''].map(sev)).toEqual(['critical', 'high', 'medium', 'medium', 'low', 'critical', 'medium', 'info'])
  })
})

describe('planning a review', () => {
  it('picks scanners for the languages, and more at Deep', () => {
    const root = mkdtempSync(join(tmpdir(), 'ms-plan-'))
    mkdirSync(join(root, 'app'))
    writeFileSync(join(root, 'app', 'a.php'), '<?php')
    writeFileSync(join(root, 'tool.py'), 'print(1)')
    mkdirSync(join(root, 'node_modules', 'x'), { recursive: true })
    writeFileSync(join(root, 'node_modules', 'x', 'i.js'), '')
    writeFileSync(join(root, 'composer.lock'), '{}')
    const stats = projectStats(root)
    expect(stats.languages).toEqual(expect.arrayContaining(['PHP', 'Python']))
    expect(stats.languages).not.toContain('JavaScript')
    expect(stats.manifests).toContain('composer.lock')
    const quick = planScanners(root, stats, 'quick', '/out').map((r) => r.id)
    const deep = planScanners(root, { ...stats, git: true }, 'deep', '/out')
    expect(quick).toEqual(['semgrep', 'bandit', 'gitleaks', 'osv-scanner'])
    expect(deep.map((r) => r.id)).toEqual(['semgrep', 'bearer', 'bandit', 'gitleaks', 'trufflehog', 'osv-scanner', 'trivy'])
    expect(deep.find((r) => r.id === 'gitleaks')!.args[0]).toBe('git')
    expect(deep.find((r) => r.id === 'trufflehog')!.args).toContain('--no-verification')
    expect(deep.find((r) => r.id === 'semgrep')!.args).toContain('p/phpcs-security-audit')
  })
})

describe('the AI reviewer', () => {
  it('reads the report, its findings and its verdicts', () => {
    const text = '<think>hmm</think>## Summary\nOne problem.\n\n### [HIGH] IDOR on orders\n**Where:** `app/Orders.php:40`\n\n```json\n{"findings":[{"severity":"high","title":"IDOR on orders","file":"app/Orders.php","line":40,"cwe":"CWE-639","fix":"Check ownership"}],"verdicts":[{"id":"abc","verdict":"false-positive"},{"id":"def","verdict":"confirmed"}]}\n```'
    const r = parseAiOutput(text, 'Claude Code')
    expect(r.report).toContain('## Summary')
    expect(r.report).not.toContain('```json')
    expect(r.report).not.toContain('think')
    expect(r.findings[0]).toMatchObject({ severity: 'high', file: 'app/Orders.php', line: 40, category: 'ai', tool: 'Claude Code' })
    expect(r.verdicts.get('abc')).toBe('false-positive')
  })
  it('keeps the report when the JSON is broken', () => {
    const r = parseAiOutput('## Summary\nok\n```json\n{broken\n```', 'Model')
    expect(r.findings).toEqual([])
    expect(r.report).toContain('Summary')
  })
  it('asks for the access-control and logic checks scanners miss', () => {
    const p = reviewPrompt('shop', 'security', 'deep', [])
    expect(p).toMatch(/IDOR/)
    expect(p).toMatch(/Do not modify any file/)
  })
  it('reads flagged and risky files first', () => {
    const order = rankFiles(['README.md', 'src/util/math.ts', 'app/Http/Controllers/AuthController.php', 'lib/x.ts'], [{ id: '1', tool: 'Semgrep', category: 'code', severity: 'critical', title: 't', file: 'lib/x.ts' }])
    expect(order.slice(0, 2)).toEqual(['lib/x.ts', 'app/Http/Controllers/AuthController.php'])
  })
})

describe('reports and logs', () => {
  it('escapes everything from code and scanners', () => {
    const html = markdownToHtml('### [HIGH] XSS <script>alert(1)</script>\n- `a<b>`\n```\n<img onerror=x>\n```')
    expect(html).not.toContain('<script>')
    expect(html).not.toContain('<img')
    expect(html).toContain('<span class="sev high">HIGH</span>')
    const page = sessionHtml({ id: 'x', kind: 'code-review', title: '<b>t</b>', target: 't', createdAt: new Date().toISOString(), status: 'done', counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, steps: [], findings: [{ id: '1', tool: 'Semgrep', category: 'code', severity: 'high', title: '<svg onload=1>', file: 'a"b' }] })
    expect(page).not.toContain('<svg onload')
    expect(page).not.toContain('<b>t</b>')
  })
  it('keeps tokens out of the log', () => {
    expect(redact('cloning https://x-access-token:ghp_abcdefghijklmnopqrstuvwxyz123456@github.com/a/b')).not.toContain('ghp_')
    expect(redact('AUTHORIZATION: basic eDpwYXQ=')).toContain('[hidden]')
  })
  it('understands Azure DevOps paths', () => {
    expect(azureOrg('https://dev.azure.com/contoso/Shop')).toBe('contoso')
    expect(azureOrg('contoso.visualstudio.com')).toBe('contoso')
    expect(() => azureOrg('bad org!')).toThrow()
  })
})
