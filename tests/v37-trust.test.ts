/** The trust fixes: pinned DNS, masked evidence everywhere, and a proof that reaches its finding. */
import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { createServer, type Server } from 'http'
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { pinnedRequest } from '../src/main/netclient'
import { NetGuard } from '../src/main/netguard'
import { addEvidence } from '../src/main/evidence'
import { attachProof } from '../src/main/impact/link'
import type { ImpactPlan, ImpactRun } from '../src/shared/impact'
import type { Finding } from '../src/shared/types'

let dir = ''
let server: Server | null = null
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'macsec-trust-'))
})
afterEach(() => {
  server?.close()
  server = null
  rmSync(dir, { recursive: true, force: true })
})

const serve = (): Promise<{ port: number; seen: string[] }> =>
  new Promise((resolve) => {
    const seen: string[] = []
    server = createServer((req, res) => {
      seen.push(`${req.method} ${req.url} host=${req.headers.host}`)
      if (req.url === '/moved') {
        res.writeHead(302, { location: '/elsewhere' })
        res.end()
        return
      }
      res.writeHead(200, { 'content-type': 'text/plain', 'set-cookie': 'a=b' })
      res.end('pinned ok')
    })
    server.listen(0, '127.0.0.1', () => resolve({ port: (server!.address() as { port: number }).port, seen }))
  })

describe('a request that cannot re-resolve', () => {
  it('connects to the approved address and keeps the name in the Host header', async () => {
    const { port, seen } = await serve()
    const r = await pinnedRequest(`http://pinned.example:${port}/x`, { address: '127.0.0.1', headers: { 'User-Agent': 'MacSec test' } })
    expect(r.status).toBe(200)
    expect(r.body).toBe('pinned ok')
    expect(r.headers.get('set-cookie')).toContain('a=b')
    expect(seen[0]).toContain('host=pinned.example')
  })

  it('never follows a redirect on its own', async () => {
    const { port } = await serve()
    const r = await pinnedRequest(`http://pinned.example:${port}/moved`, { address: '127.0.0.1' })
    expect(r.status).toBe(302)
    expect(r.headers.get('location')).toBe('/elsewhere')
  })

  it('the guard keeps the address it approved, and refuses a metadata answer', async () => {
    const g = new NetGuard(async () => ['93.184.216.34'])
    await g.check('example.com')
    expect(g.addressFor('example.com')).toBe('93.184.216.34')
    expect(g.addressFor('other.test')).toBeNull()
    await expect(new NetGuard(async () => ['169.254.169.254']).check('meta.test')).rejects.toThrow(/metadata/)
    await expect(new NetGuard(async () => ['93.184.216.34', '10.0.0.5']).check('mixed.test')).rejects.toThrow(/rebinding/)
  })
})

describe('evidence is masked whatever the finding is about', () => {
  it('hides a key that sits next to a non-secret finding', () => {
    mkdirSync(join(dir, 'config'), { recursive: true })
    writeFileSync(join(dir, 'config', 'database.php'), "<?php\n$key = 'not-a-real-key-abcdefghijklmnopqrstuvwxyz';\n$db = mysqli_connect($host, $user, $pass);\n")
    const f: Finding = { id: 'sql', tool: 'Semgrep', category: 'code', severity: 'high', title: 'SQL injection in database.php', file: 'config/database.php', line: 3 }
    const [out] = addEvidence(dir, [f])
    expect(out.context?.lines.join('\n')).toContain('not-')
    expect(out.context?.lines.join('\n')).not.toContain('abcdefghijklmnopqrstuvwxyz')
  })
})

describe('a proof reaches the finding', () => {
  const plan: ImpactPlan = {
    id: 'pl-1',
    engagementId: 'eng-1',
    target: 'http://shop.test',
    goal: ['confidentiality'],
    caps: { requests: 10, writes: 0, minutes: 5 },
    notes: [],
    at: '',
    source: 'rules',
    steps: [{ id: 's1', action: 'traversal-read', aims: 'confidentiality', url: 'http://shop.test/download', param: 'file', why: 'w', preview: [], from: 'f1' }]
  }
  const run: ImpactRun = {
    id: 'run-1',
    planId: 'pl-1',
    engagementId: 'eng-1',
    target: 'http://shop.test',
    startedAt: '',
    finishedAt: '2026-11-24T00:00:00.000Z',
    goal: ['confidentiality'],
    proven: ['confidentiality'],
    steps: [{ step: 's1', action: 'traversal-read', aims: 'confidentiality', status: 'proven', title: 't', detail: 'd', ms: 1, evidence: { method: 'GET', url: 'http://shop.test/download?file=../../etc/passwd', status: 200, bytes: 4, sha256: 'a'.repeat(64), at: '2026-11-24T00:00:00.000Z', shows: ['/etc/passwd was read'] } }],
    leftover: [],
    stopped: 'Every goal was proven.',
    requests: 1,
    writes: 0
  }
  it('marks the finding confirmed, with the proof and the engagement', () => {
    const findings: Finding[] = [{ id: 'f1', tool: 'MacSec', category: 'web', severity: 'medium', title: 'File read possible', confidence: 'possible' }]
    const { findings: out, linked } = attachProof(findings, run, plan, 'eng-1:abc')
    expect(linked).toEqual(['f1'])
    expect(out[0].confidence).toBe('confirmed')
    expect(out[0].controlled?.runId).toBe('run-1')
    expect(out[0].controlled?.engagementRef).toBe('eng-1:abc')
    expect(out[0].proof?.shows[0]).toMatch(/passwd/)
  })

  it('does nothing when the step was not proven', () => {
    const notProven = { ...run, steps: [{ ...run.steps[0], status: 'not-proven' as const }] }
    const findings: Finding[] = [{ id: 'f1', tool: 'MacSec', category: 'web', severity: 'medium', title: 'File read possible' }]
    expect(attachProof(findings, notProven, plan, 'x').linked).toEqual([])
  })
})
