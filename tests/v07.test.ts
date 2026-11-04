import { execFileSync } from 'child_process'
import { mkdtempSync, readFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
import { checkovSeverity, parseCheckov, parseGrype, parseSyftLicences, parseZap, sbomSummary } from '../src/main/scanners/parse'
import { ciWorkflow, compareFindings, preCommitHook, previousSession, toDefectDojo, toSarif } from '../src/main/exports'
import { autoUpdates, extensionRisk, fileVault, firewall, gatekeeper, launchProgram, parseLsof, scoreOf, signerOf, sip, sshKeyProtected } from '../src/main/checkup'
import { macsecCli, macsecTools } from '../src/main/mcptools'
import { SKILLS } from '../src/main/seckit/skills'
import type { Finding, SessionInfo } from '../src/shared/types'

const fx = (n: string): string => readFileSync(join(__dirname, 'fixtures', n), 'utf8')

describe('Grype, Syft, Checkov and ZAP (real output)', () => {
  it('reads Grype matches with their fixes', () => {
    const f = parseGrype(fx('grype.json'), '/')
    expect(f.length).toBeGreaterThan(0)
    expect(f[0]).toMatchObject({ tool: 'Grype', category: 'dependency', advisory: 'CVE-1999-0001', severity: 'low' })
    expect(f[0].fix).toMatch(/Update package-1 to/)
    expect(f[0].description).toMatch(/EPSS/)
  })
  it('summarises the SBOM Syft writes', () => {
    const s = sbomSummary(fx('syft-cyclonedx.json'))
    expect(s.components).toBeGreaterThan(0)
    expect(s.licences.MIT).toBeGreaterThan(0)
    expect(parseSyftLicences(JSON.stringify({ components: [{ name: 'x', version: '1', licenses: [{ license: { id: 'AGPL-3.0-only' } }] }, { name: 'y', licenses: [{ license: { id: 'LGPL-2.1' } }] }] }), '/')).toHaveLength(1)
  })
  it('reads Checkov results for Terraform and Dockerfiles', () => {
    const f = parseCheckov(fx('checkov.json'), '/tmp/iac')
    expect(f.length).toBeGreaterThan(3)
    const ssh = f.find((x) => x.title.includes('CKV_AWS_24'))!
    expect(ssh).toMatchObject({ severity: 'high', file: 'main.tf', line: 5, category: 'config' })
    expect(checkovSeverity('CKV_X', 'Ensure logging is enabled')).toBe('medium')
  })
  it('reads ZAP’s JSON report', () => {
    const f = parseZap(fx('zap.json'))
    expect(f[0]).toMatchObject({ tool: 'ZAP', category: 'web', severity: 'high', cwe: 'CWE-123', url: 'http://example.com/example_3' })
    expect(f[0].title).toBe('XSS (2 places)')
    expect(f[0].description).not.toMatch(/<p>/)
  })
})

const fd = (id: string, extra: Partial<Finding> = {}): Finding => ({ id, tool: 'Semgrep', category: 'code', severity: 'high', title: `T${id}`, file: 'a.php', line: 3, ...extra })
const sess = (id: string, at: string, extra: Partial<SessionInfo> = {}): SessionInfo => ({ id, kind: 'code-review', title: 'shop', target: '/www/shop', createdAt: at, status: 'done', counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, steps: [], ...extra })

describe('Findings over time and exports', () => {
  it('finds the previous session of the same target', () => {
    const all = [sess('a', '2026-01-01'), sess('b', '2026-02-01'), sess('c', '2026-03-01'), sess('d', '2026-02-15', { target: '/www/other' }), sess('e', '2026-02-20', { status: 'failed' })]
    expect(previousSession(all, all[2])?.id).toBe('b')
    expect(previousSession(all, all[0])).toBeNull()
  })
  it('says what is new, fixed and still there', () => {
    const c = compareFindings([fd('1'), fd('3'), fd('9', { title: 'T2', line: 7 })], [fd('1'), fd('2')])
    expect(c.added.map((f) => f.id)).toEqual(['3'])
    expect(c.fixed).toEqual([])
    expect(c.still).toBe(2)
  })
  it('writes SARIF that GitHub code scanning reads', () => {
    const s = toSarif([fd('1', { cwe: 'CWE-89', severity: 'critical' }), fd('2', { tool: 'Gitleaks', category: 'secret' })], '0.7.0') as { version: string; runs: { tool: { driver: { name: string; rules: { properties: Record<string, unknown> }[] } }; results: { level: string; locations: unknown[] }[] }[] }
    expect(s.version).toBe('2.1.0')
    expect(s.runs).toHaveLength(2)
    expect(s.runs[0].results[0].level).toBe('error')
    expect(s.runs[0].tool.driver.rules[0].properties['security-severity']).toBe('9.5')
  })
  it('writes DefectDojo’s generic import', () => {
    const d = toDefectDojo([fd('1', { cwe: 'CWE-79', triage: 'accepted' })], sess('x', '2026-03-01')) as { findings: Record<string, unknown>[] }
    expect(d.findings[0]).toMatchObject({ severity: 'High', cwe: 79, risk_accepted: true, file_path: 'a.php', line: 3, unique_id_from_tool: '1' })
  })
  it('writes a pre-commit hook and CI workflows', () => {
    expect(preCommitHook('/Users/x/MacSec/tools/bin/gitleaks')).toContain('git --pre-commit --staged --redact')
    expect(ciWorkflow('github')).toContain('upload-sarif')
    expect(ciWorkflow('github')).toContain('persist-credentials: false')
    expect(ciWorkflow('azure')).toContain('vmImage: ubuntu-latest')
  })
})

describe('Mac check-up', () => {
  it('reads Apple’s tools', () => {
    expect(fileVault('FileVault is On.').status).toBe('ok')
    expect(fileVault('FileVault is Off.').status).toBe('bad')
    expect(firewall('Firewall is enabled. (State = 1)', 'Firewall stealth mode is on').status).toBe('ok')
    expect(firewall('Firewall is disabled. (State = 0)', '').status).toBe('warn')
    expect(gatekeeper('assessments enabled').status).toBe('ok')
    expect(sip('System Integrity Protection status: disabled.').status).toBe('bad')
    expect(autoUpdates('0', '1').status).toBe('warn')
  })
  it('reads lsof (real output)', () => {
    const ports = parseLsof(fx('lsof.txt'))
    expect(ports.length).toBeGreaterThan(0)
    expect(ports.every((p) => p.port > 0 && p.command.length > 0)).toBe(true)
    expect(parseLsof('COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nhttpd 10 me 4u IPv6 0x1 0t0 TCP *:8080 (LISTEN)\n')[0]).toMatchObject({ command: 'httpd', port: 8080, everyone: true })
  })
  it('tells keys with and without a passphrase apart (real ssh-keygen)', () => {
    const d = mkdtempSync(join(tmpdir(), 'k-'))
    execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', join(d, 'plain')])
    execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', 'a long passphrase', '-f', join(d, 'protected')])
    expect(sshKeyProtected(readFileSync(join(d, 'plain'), 'utf8'))).toBe(false)
    expect(sshKeyProtected(readFileSync(join(d, 'protected'), 'utf8'))).toBe(true)
    expect(sshKeyProtected('-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n')).toBe(true)
  })
  it('flags extensions that read every site, and unsigned login items', () => {
    expect(extensionRisk({ permissions: ['storage', 'cookies'], host_permissions: ['<all_urls>'] })).toEqual(['cookies', 'reads every site'])
    expect(extensionRisk({ permissions: ['storage'] })).toEqual([])
    expect(launchProgram({ ProgramArguments: ['/Applications/X.app/Contents/MacOS/x', '--bg'] })).toBe('/Applications/X.app/Contents/MacOS/x')
    expect(signerOf('Authority=Developer ID Application: Example Inc (ABCDE12345)\nTeamIdentifier=ABCDE12345')).toBe('Developer ID Application: Example Inc (ABCDE12345) (ABCDE12345)')
    expect(signerOf('/x: code object is not signed at all')).toBeNull()
    expect(scoreOf({ at: '', macos: '', checks: [{ id: 'a', title: '', status: 'bad', detail: '' }], loginItems: [], ports: [], sshKeys: [], extensions: [] })).toBe(80)
  })
})

describe('MCP and the macsec command', () => {
  it('offers read tools and one that starts a review of a www project', async () => {
    const started: string[] = []
    const t = macsecTools({ sessions: () => [sess('a', '2026')], session: () => ({ ...sess('a', '2026'), findings: [fd('1', { context: { start: 1, lines: ['x'], at: 1 } })] }), compare: () => ({}), projects: () => [{ name: 'shop', path: '/www/shop', languages: [] }], review: (p) => { started.push(p); return sess('n', '2026') }, checkup: async () => ({}) })
    expect(t.map((x) => x.name)).toEqual(['list_sessions', 'get_session', 'compare_session', 'list_projects', 'start_code_review', 'mac_checkup'])
    const g = (await t[1].run({ id: 'a' })) as { findings: Finding[] }
    expect(g.findings[0].context).toBeUndefined()
    await expect(t[4].run({ project: '../etc' })).rejects.toThrow(/No project/)
    await t[4].run({ project: 'shop' })
    expect(started).toEqual(['/www/shop'])
  })
  it('the command reads the token from MacSec’s folder', () => {
    const sh = macsecCli('/Users/x/MacSec/config/mcp-token', 53537)
    expect(sh).toContain('TOKEN_FILE="/Users/x/MacSec/config/mcp-token"')
    expect(sh).toContain('http://127.0.0.1:53537/mcp')
  })
  it('ships 29 skills', () => {
    expect(Object.keys(SKILLS)).toHaveLength(29)
  })
})
