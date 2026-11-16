import { describe, expect, it } from 'vitest'
import { coverage, coverageText, isOpen, issueText, sparkPath, topFindings, trends } from '../src/shared/insights'
import { postureOf, postureScore, postureWord } from '../src/shared/posture'
import { trayModel } from '../src/main/traymodel'
import { SKILLS } from '../src/main/seckit/skills'
import type { Finding, SessionInfo } from '../src/shared/types'

const counts = (c = 0, h = 0, m = 0, l = 0, i = 0): SessionInfo['counts'] => ({ critical: c, high: h, medium: m, low: l, info: i })
const sess = (id: string, kind: SessionInfo['kind'], target: string, at: string, c: SessionInfo['counts'], status: SessionInfo['status'] = 'done'): SessionInfo => ({ id, kind, title: target, target, createdAt: at, status, counts: c, steps: [] })
const f = (o: Partial<Finding>): Finding => ({ id: 'x', tool: 'semgrep', category: 'code', severity: 'low', title: 't', ...o })

describe('coverage: the score says what it is based on', () => {
  const list = [sess('b', 'code-review', 'shop', '2026-11-02', counts(1)), sess('a', 'code-review', 'shop', '2026-11-01', counts(2))]
  it('counts the newest test of each target and names what was never tested', () => {
    const c = coverage(list, false)
    expect(c.find((x) => x.area === 'code')?.tests).toBe(1)
    const t = coverageText(c)
    expect(t.basedOn).toBe('Based on 1 code review.')
    expect(t.missing.map((m) => m.area)).toEqual(['web', 'api', 'mac'])
  })
  it('includes this Mac once it was checked, and says so when nothing was tested', () => {
    expect(coverageText(coverage(list, true)).basedOn).toContain('a check of this Mac')
    expect(coverageText(coverage([], false)).basedOn).toBe('Nothing has been tested yet.')
  })
  it('a running or failed test does not count as tested', () => {
    expect(coverage([sess('r', 'web-scan', 'https://x.test', '2026-11-03', counts(), 'running')], false).find((x) => x.area === 'web')?.tests).toBe(0)
  })
})

describe('fix these first', () => {
  const s = { id: 's1', title: 'shop' }
  it('leads with the most severe open findings, confirmed ones first', () => {
    const top = topFindings([{ session: s, findings: [f({ id: 'a', severity: 'high' }), f({ id: 'b', severity: 'critical', file: 'a.php', line: 3 }), f({ id: 'c', severity: 'high', verdict: 'confirmed' }), f({ id: 'd', severity: 'low' })] }], 3)
    expect(top.map((x) => x.id)).toEqual(['b', 'c', 'a'])
    expect(top[0].where).toBe('a.php:3')
  })
  it('leaves out what you dealt with and what the AI ruled out', () => {
    expect(isOpen(f({ triage: 'fixed' }))).toBe(false)
    expect(isOpen(f({ verdict: 'false-positive' }))).toBe(false)
    expect(topFindings([{ session: s, findings: [f({ severity: 'critical', triage: 'accepted' }), f({ severity: 'critical', verdict: 'false-positive' })] }])).toEqual([])
  })
})

describe('getting safer', () => {
  it('needs two finished tests of the same target, oldest first, and says which way it moved', () => {
    const t = trends([sess('c', 'code-review', 'shop', '2026-11-03', counts(0, 1)), sess('b', 'code-review', 'shop', '2026-11-02', counts(1, 1)), sess('a', 'code-review', 'shop', '2026-11-01', counts(2, 2)), sess('z', 'web-scan', 'site', '2026-11-01', counts())], postureScore)
    expect(t).toHaveLength(1)
    expect(t[0].points.map((p) => p.at)).toEqual(['2026-11-01', '2026-11-02', '2026-11-03'])
    expect(t[0].change).toBeGreaterThan(0)
  })
  it('draws a line inside its box', () => {
    expect(sparkPath([0, 100], 120, 34)).toBe('M0.0 34.0 L120.0 0.0')
    expect(sparkPath([], 120, 34)).toBe('')
  })
})

describe('copy as an issue', () => {
  it('writes the finding out in plain sections', () => {
    const t = issueText(f({ title: 'SQL injection', severity: 'critical', file: 'a.php', line: 4, cwe: 'CWE-89', description: 'Joined into SQL.', impact: 'Orders can be read.', fix: 'Bind it.' }), 'shop')
    expect(t).toContain('## SQL injection')
    expect(t).toContain('`a.php:4`')
    expect(t).toContain('### How to fix')
  })
  it('never carries a secret: only the kind, the file and the line', () => {
    const t = issueText(f({ title: 'Stripe key', category: 'secret', file: '.env', line: 2, description: 'sk_live_abc123 found' }), 'shop')
    expect(t).not.toContain('sk_live_abc123')
    expect(t).toContain('rotate it')
  })
})

describe('menu bar', () => {
  it('shows the score when idle and the running test when busy', () => {
    const done = sess('a', 'code-review', 'shop', '2026-11-01', counts(1))
    expect(trayModel([done]).title.trim()).toBe(String(postureOf([done.counts])))
    expect(trayModel([done]).lines[0].label).toContain(postureWord(postureOf([done.counts]), true).toLowerCase())
    const run = { ...sess('b', 'web-scan', 'site', '2026-11-02', counts(), 'running'), steps: [{ id: 'nuclei', label: 'Nuclei', status: 'running' as const }] }
    const m = trayModel([run, done])
    expect(m.title).toContain('1 running')
    expect(m.lines.some((l) => l.session === 'b' && l.label.includes('Nuclei'))).toBe(true)
    expect(trayModel([]).lines[0].label).toBe('No tests yet')
  })
})

describe('skills', () => {
  it('there are 43, none with an em dash', () => {
    expect(Object.keys(SKILLS)).toHaveLength(43)
    for (const s of Object.values(SKILLS)) expect(s.body).not.toContain('—')
  })
})
