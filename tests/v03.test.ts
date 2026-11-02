import { createServer, type Server } from 'http'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { addEvidence, maskSecrets } from '../src/main/evidence'
import { parseAiOutput, scannerBrief } from '../src/main/aireview'
import { parseSecurityReview } from '../src/main/audit'
import { markdownToHtml, sessionHtml } from '../src/main/report'
import { signedOutCheck } from '../src/main/webextra'
import { ensureDirs, setRoot } from '../src/main/paths'
import { ensureSkills, listSkills, pluginArgs } from '../src/main/skills'

describe('evidence', () => {
  it('masks secrets but keeps enough to recognise them', () => {
    expect(maskSecrets("'client_secret' => 'Q8x~kd8Hf.Zr2vK1pLmN0qW4sT6uY8bA3cE5gI7',")).toBe("'client_secret' => 'Q8x~••••••••',")
    expect(maskSecrets('AZURE_CLIENT_SECRET=Q8x~kd8Hf.Zr2vK1pLmN0qW4sT6uY8bA3cE5gI7')).toBe('AZURE_CLIENT_SECRET=Q8x~••••••••')
    expect(maskSecrets('key = "AKIAIOSFODNN7EXAMPLE"')).not.toContain('IOSFODNN7')
    expect(maskSecrets('$x = $request->input("name");')).toBe('$x = $request->input("name");')
  })
  it('adds the lines around each finding, from the code', () => {
    const root = mkdtempSync(join(tmpdir(), 'ms-ev-'))
    mkdirSync(join(root, 'config'))
    writeFileSync(join(root, 'config', 'azure.php'), ['<?php', 'return [', "  'tenant' => 'contoso',", "  'client_id' => 'abc',", "  'client_secret' => 'Q8x~kd8Hf.Zr2vK1pLmN0qW4sT6uY8bA3cE5gI7',", '];'].join('\n'))
    writeFileSync(join(root, 'composer.lock'), '{\n  "packages": [\n    { "name": "guzzlehttp/guzzle", "version": "7.4.0" }\n  ]\n}')
    const [secret, dep, outside] = addEvidence(root, [
      { id: '1', tool: 'Gitleaks', category: 'secret', severity: 'critical', title: 'Azure AD client secret in code', file: 'config/azure.php', line: 5 },
      { id: '2', tool: 'OSV-Scanner', category: 'dependency', severity: 'high', title: 'guzzlehttp/guzzle 7.4.0: Cookie leak', file: 'composer.lock' },
      { id: '3', tool: 'x', category: 'code', severity: 'low', title: 't', file: '../../etc/passwd', line: 1 }
    ])
    expect(secret.context!.at).toBe(5)
    expect(secret.context!.lines.join('\n')).toContain("'client_secret' => 'Q8x~••••••••'")
    expect(secret.context!.lines.join('\n')).not.toContain('kd8Hf')
    expect(dep.context!.at).toBe(3)
    expect(outside.context).toBeUndefined()
  })
})

describe('the AI report', () => {
  it('reads explanations and verdict reasons', () => {
    const r = parseAiOutput('## Executive summary\nx\n```json\n{"findings":[{"severity":"high","title":"IDOR","file":"a.php","line":3,"why":"any user","impact":"read orders","fixCode":"$user->orders()","verify":"curl as user B"}],"verdicts":[{"id":"s1","verdict":"confirmed","severity":"critical","reason":"live secret"}]}\n```', 'Claude Code')
    expect(r.findings[0]).toMatchObject({ why: 'any user', impact: 'read orders', fixCode: '$user->orders()', verify: 'curl as user B' })
    expect(r.details.get('s1')).toEqual({ verdict: 'confirmed', severity: 'critical', reason: 'live secret' })
  })
  it('gives the reviewer the code of the most severe scanner findings', () => {
    const b = scannerBrief([{ id: 'a', tool: 'Gitleaks', category: 'secret', severity: 'critical', title: 'Key', file: 'x.php', line: 2, context: { start: 1, at: 2, lines: ['<?php', "$k = 'abcd••••';"] } }])
    expect(b).toContain("2> $k = 'abcd••••';")
  })
  it('reads Claude Code /security-review', () => {
    const f = parseSecurityReview('# Vuln 1: SQL injection in report export\n\n* Severity: High\n* File: `app/Export.php:77`\n\nDescription here.\n\n# Vuln 2: Open redirect\nSeverity: Medium\n`routes/web.php:12`', '/nowhere')
    expect(f.map((x) => [x.severity, x.title, x.file, x.line])).toEqual([
      ['high', 'SQL injection in report export', 'app/Export.php', 77],
      ['medium', 'Open redirect', 'routes/web.php', 12]
    ])
  })
  it('renders tables and evidence in the PDF, escaped', () => {
    expect(markdownToHtml('| Severity | Finding |\n|---|---|\n| High | <b>x</b> |')).toBe('<table><tr><th>Severity</th><th>Finding</th></tr><tr><td>High</td><td>&lt;b&gt;x&lt;/b&gt;</td></tr></table>')
    const html = sessionHtml({ id: 'x', kind: 'code-review', title: 't', target: 't', createdAt: new Date().toISOString(), status: 'done', counts: { critical: 1, high: 0, medium: 0, low: 0, info: 0 }, steps: [], findings: [{ id: '1', tool: 'Gitleaks', category: 'secret', severity: 'critical', title: 'Key', file: 'a.php', line: 2, context: { start: 1, at: 2, lines: ['<?php', '<script>'] }, fixCode: 'env("KEY")' }] })
    expect(html).toContain('class="ln hit"')
    expect(html).not.toContain('<script>')
  })
})

describe('skills', () => {
  it('writes the security plugin into MacSec and loads it', () => {
    setRoot(mkdtempSync(join(tmpdir(), 'ms-sk-')))
    ensureDirs()
    ensureSkills()
    expect(listSkills().map((s) => s.name)).toEqual(expect.arrayContaining(['security-code-review', 'secrets-triage', 'dependency-triage', 'security-report']))
    const args = pluginArgs()
    expect(args[0]).toBe('--plugin-dir')
    expect(JSON.parse(readFileSync(join(args[1], '.claude-plugin', 'plugin.json'), 'utf8')).name).toBe('macsec-security')
    expect(readFileSync(join(args[1], 'skills', 'secrets-triage', 'SKILL.md'), 'utf8')).toMatch(/^---\nname: secrets-triage\ndescription: /)
    // Your own skills load too, once there is one.
    expect(args).toHaveLength(2)
    const mine = join(args[1], '..', '..', 'extensions', 'claude', 'skills', 'my-rules')
    mkdirSync(mine, { recursive: true })
    writeFileSync(join(mine, 'SKILL.md'), '---\nname: my-rules\ndescription: x\n---\n')
    expect(pluginArgs()).toHaveLength(4)
    expect(existsSync(join(mine, 'SKILL.md'))).toBe(true)
  })
})

describe('signed in versus signed out', () => {
  let srv: Server
  let base = ''
  beforeAll(async () => {
    srv = createServer((req, res) => {
      const signedIn = /session=ok/.test(req.headers.cookie ?? '')
      const page = 'x'.repeat(2000)
      if (req.url === '/account/orders') return res.writeHead(200).end(`<h1>Orders</h1>${page}`)
      if (req.url === '/dashboard') return signedIn ? res.writeHead(200).end(`<h1>Dashboard</h1>${page}`) : res.writeHead(302, { location: '/login' }).end()
      res.writeHead(404).end()
    })
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()))
    base = `http://127.0.0.1:${(srv.address() as { port: number }).port}`
  })
  afterAll(() => srv.close())
  it('flags the private page that is the same for everyone, not the protected one', async () => {
    const f = await signedOutCheck([`${base}/account/orders`, `${base}/dashboard`, `${base}/app.js`], { Cookie: 'session=ok' }, () => false, () => undefined)
    expect(f.map((x) => x.title)).toEqual(['Shows the same content when signed out: /account/orders'])
  })
})
