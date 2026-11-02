import { existsSync, mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
import { dirs, ensureDirs, setRoot } from '../src/main/paths'

const VENV = '/tmp/scanvenv/bin'
const run = existsSync(join(VENV, 'semgrep')) ? describe : describe.skip

run('a real review, end to end (needs Semgrep and Bandit)', () => {
  it('runs the scanners, merges findings and writes the session', async () => {
    setRoot(mkdtempSync(join(tmpdir(), 'ms-e2e-')))
    ensureDirs()
    for (const b of ['semgrep', 'bandit']) symlinkSync(join(VENV, b), join(dirs.bin(), b))
    const proj = mkdtempSync(join(tmpdir(), 'ms-vuln-'))
    mkdirSync(join(proj, 'app'))
    writeFileSync(join(proj, 'app', 'orders.php'), `<?php\n$id = $_GET['id'];\n$r = mysqli_query($conn, "SELECT * FROM orders WHERE id = " . $id);\necho $_GET['name'];\nsystem("ping " . $_GET['host']);\n`)
    writeFileSync(join(proj, 'tool.py'), `import subprocess, pickle, hashlib\ndef run(cmd):\n    subprocess.call(cmd, shell=True)\ndef load(b):\n    return pickle.loads(b)\nh = hashlib.md5(b'x').hexdigest()\n`)
    writeFileSync(join(proj, 'server.js'), `const express = require('express')\nconst app = express()\napp.get('/r', (req, res) => { res.send('<p>' + req.query.q + '</p>'); eval(req.query.code) })\n`)
    const { startReview } = await import('../src/main/review')
    const { readSession, sessionDetail } = await import('../src/main/sessions')
    // Only Semgrep and Bandit are here; the others would download from GitHub.
    const s = await startReview({ source: { kind: 'local', path: proj }, reviewer: 'none', depth: 'standard', focus: 'security', keepCode: false, skip: ['bearer', 'gitleaks', 'trufflehog', 'osv-scanner', 'trivy'] })
    for (let i = 0; i < 600 && readSession(s.id).status === 'running'; i++) await new Promise((r) => setTimeout(r, 1000))
    const d = sessionDetail(s.id)
    console.log(d.steps.map((x) => `${x.id}: ${x.status} ${x.detail ?? ''}`).join('\n'))
    console.log(d.findings.map((f) => `${f.severity} ${f.tool} ${f.file}:${f.line} ${f.title} ${f.cwe ?? ''}`).join('\n'))
    expect(d.status).toBe('done')
    expect(d.steps.find((x) => x.id === 'semgrep')!.status).toBe('done')
    expect(d.steps.find((x) => x.id === 'bandit')!.status).toBe('done')
    expect(d.findings.some((f) => f.tool.includes('Bandit') && f.file === 'tool.py')).toBe(true)
    expect(d.findings.some((f) => f.tool.includes('Semgrep') && f.file === 'app/orders.php')).toBe(true)
    expect(d.counts.high + d.counts.critical + d.counts.medium).toBeGreaterThan(0)
    // Scanner caches stayed inside MacSec.
    expect(existsSync(join(dirs.toolHome(), '.semgrep')) || existsSync(join(dirs.toolHome(), '.cache'))).toBe(true)
  }, 700_000)
})
