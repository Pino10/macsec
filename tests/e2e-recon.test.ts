import { existsSync, mkdtempSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
import { ensureDirs, setRoot } from '../src/main/paths'

// A real Next.js dev site at http://myapp.test (Laramac's nginx config in front of it).
const run = existsSync('/tmp/lm/myapp/package.json') ? describe : describe.skip

run('a real recon session', () => {
  it('runs every step, keeps the map and finds the source maps', async () => {
    setRoot(mkdtempSync(join(tmpdir(), 'ms-recon-')))
    ensureDirs()
    const { startRecon, reconData } = await import('../src/main/reconscan')
    const { readSession, sessionDetail } = await import('../src/main/sessions')
    const s = startRecon({ target: 'myapp.test', depth: 'standard', reviewer: 'none', authorized: false })
    for (let i = 0; i < 300 && readSession(s.id).status === 'running'; i++) await new Promise((r) => setTimeout(r, 1000))
    const d = sessionDetail(s.id)
    console.log(d.steps.map((x) => `${x.id}: ${x.status} ${x.detail ?? ''}`).join('\n'))
    expect(d.status).toBe('done')
    expect(d.steps.find((x) => x.id === 'js')?.status).toBe('done')
    expect(d.findings.some((f) => f.tool === 'Source map check')).toBe(true)
    const map = reconData(s.id) as { hosts: { host: string }[]; js: unknown[] }
    expect(map.hosts.some((h) => h.host === 'myapp.test')).toBe(true)
    expect(map.js.length).toBeGreaterThan(2)
    // Not on this Mac: confirmation needed.
    expect(() => startRecon({ target: 'example.com', depth: 'passive', reviewer: 'none', authorized: false })).toThrow(/permission/)
  }, 400_000)
})
