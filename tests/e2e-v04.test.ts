import { existsSync, mkdtempSync, symlinkSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
import { dirs, ensureDirs, setRoot } from '../src/main/paths'
import type { LogLine } from '../src/shared/types'

const VENV = '/tmp/scanvenv/bin'
const APP = '/tmp/mob'
const NAABU = '/tmp/nb/naabu'
const run = existsSync(join(VENV, 'mobsfscan')) && existsSync(APP) ? describe : describe.skip

run('0.4 end to end (needs mobsfscan, a sample app and naabu)', () => {
  it('checks a mobile app from source, with live output', async () => {
    setRoot(mkdtempSync(join(tmpdir(), 'ms-e2e4-')))
    ensureDirs()
    for (const b of ['semgrep', 'mobsfscan']) symlinkSync(join(VENV, b), join(dirs.bin(), b))
    const { logEvents } = await import('../src/main/logs')
    const live: LogLine[] = []
    logEvents.on('line', (l: LogLine) => l.live && live.push(l))
    const { startMobileScan } = await import('../src/main/mobilescan')
    const { readSession, sessionDetail } = await import('../src/main/sessions')
    const s = startMobileScan({ path: APP, reviewer: 'none' })
    for (let i = 0; i < 400 && readSession(s.id).status === 'running'; i++) await new Promise((r) => setTimeout(r, 1000))
    const d = sessionDetail(s.id)
    console.log(d.steps.map((x) => `${x.id}: ${x.status} ${x.detail ?? ''}`).join('\n'))
    console.log(d.findings.map((f) => `${f.severity} ${f.tool} ${f.file ?? ''}:${f.line ?? ''} ${f.title}`).join('\n'))
    expect(d.status).toBe('done')
    expect(d.steps.find((x) => x.id === 'mobsfscan')!.status).toBe('done')
    expect(d.findings.some((f) => f.tool === 'mobsfscan' && f.file?.endsWith('MainActivity.java') && f.context)).toBe(true)
    expect(d.findings.some((f) => f.title.includes('DeepLinkActivity'))).toBe(true)
    // mobsfscan already reported debuggable: MacSec's own check does not repeat it.
    expect(d.findings.filter((f) => /debug/i.test(f.title)).length).toBe(1)
    expect(d.steps.every((x) => x.status !== 'running' && x.lastLine === undefined)).toBe(true)
    console.log(`${live.length} live lines, e.g. ${live[0]?.text}`)
  }, 500_000)

  it.runIf(existsSync(NAABU))('checks the ports of this machine', async () => {
    symlinkSync(NAABU, join(dirs.bin(), 'naabu'))
    const { startAudit } = await import('../src/main/audit')
    const { readSession, sessionDetail } = await import('../src/main/sessions')
    const s = startAudit({ kind: 'server', host: '127.0.0.1', ports: 'top100', reviewer: 'none', authorized: false })
    for (let i = 0; i < 300 && readSession(s.id).status === 'running'; i++) await new Promise((r) => setTimeout(r, 1000))
    const d = sessionDetail(s.id)
    console.log(d.steps.map((x) => `${x.id}: ${x.status} ${x.detail ?? ''}`).join('\n'))
    expect(d.status).toBe('done')
    expect(d.steps.find((x) => x.id === 'naabu')!.status).toBe('done')
  }, 400_000)
})
