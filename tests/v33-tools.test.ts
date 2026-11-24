/** The new free tools: what they parse, what they may run, and what the caps do. */
import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { setRoot } from '../src/main/paths'
import { parseGau } from '../src/main/reconscan'
import { parseSqlmap, setSqlmapRunner } from '../src/main/impact/actions'
import { CATALOG, toolDef } from '../src/main/toolbox'
import { engagementUsage, saveEngagement } from '../src/main/engagement'
import { runCampaign } from '../src/main/impact/campaign'
import { planFromRules } from '../src/main/impact/planner'
import { exploitPhrase } from '../src/main/validate'
import type { Engagement, ImpactPlan, PlannedStep } from '../src/shared/impact'
import type { Finding } from '../src/shared/types'

const TARGET = 'http://shop.example.test'
const HOST = 'shop.example.test'
const PHRASE = exploitPhrase(HOST)
const iso = (d: number): string => new Date(Date.now() + d * 86400_000).toISOString()

let dir = ''
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'macsec-tools-'))
  setRoot(dir)
})
afterEach(() => {
  setSqlmapRunner(null)
  rmSync(dir, { recursive: true, force: true })
})

const engagement = (over: Partial<Engagement> = {}): Engagement => ({
  id: 'eng-tools001',
  client: 'Acme',
  authorityRef: 'R-2',
  authorizedBy: 'CISO',
  hosts: [HOST],
  allowPrivate: true,
  startsAt: iso(-1),
  endsAt: iso(5),
  caps: { requests: 300, writes: 5, minutes: 15 },
  allowed: ['confidentiality', 'integrity', 'availability'],
  createdAt: iso(0),
  used: { requests: 0, writes: 0 },
  ...over
})

const plan = (steps: PlannedStep[], over: Partial<ImpactPlan> = {}): ImpactPlan => ({
  id: 'pl-tools001',
  engagementId: 'eng-tools001',
  target: TARGET,
  goal: ['confidentiality'],
  steps,
  source: 'rules',
  caps: { requests: 300, writes: 5, minutes: 15 },
  notes: [],
  at: iso(0),
  ...over
})

const step = (over: Partial<PlannedStep> = {}): PlannedStep => ({
  id: 's1',
  action: 'sql-injection-proof',
  aims: 'confidentiality',
  url: `${TARGET}/product`,
  param: 'id',
  why: 'the scan found a quote changing the answer',
  preview: [],
  ...over
})

const SQLMAP_OUT = `[12:00:00] [INFO] testing connection to the target URL
sqlmap identified the following injection point(s):
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1
back-end DBMS: MySQL >= 5.0
`

describe('the new tools', () => {
  it('lists ffuf, gau, wafw00f and sqlmap as tools MacSec manages, and gives Nmap a formula', () => {
    expect(toolDef('ffuf')?.method).toBe('release')
    expect(toolDef('gau')?.method).toBe('release')
    expect(toolDef('wafw00f')?.method).toBe('python')
    expect(toolDef('sqlmap')?.method).toBe('python')
    const nmap = toolDef('nmap')
    expect(nmap?.method).toBe('app')
    expect(nmap && nmap.method === 'app' ? nmap.formula?.name : null).toBe('nmap')
    expect(CATALOG.every((t) => t.id !== 'metasploit')).toBe(true)
  })

  it('reads gau output: JSON lines or plain URLs, same domain only, no duplicates', () => {
    const text = [
      JSON.stringify({ url: 'https://shop.example.test/admin?id=1' }),
      'https://shop.example.test/admin?id=1',
      'https://other.test/x',
      'https://api.shop.example.test/v1/users#frag',
      'not an address'
    ].join('\n')
    expect(parseGau(text, 'example.test')).toEqual(['https://shop.example.test/admin?id=1', 'https://api.shop.example.test/v1/users'])
    expect(parseGau('', 'example.test')).toEqual([])
  })

  it('reads sqlmap naming a parameter, and nothing from a run that found no injection', () => {
    expect(parseSqlmap(SQLMAP_OUT)).toMatchObject({ parameter: 'id', place: 'GET', dbms: 'MySQL >= 5.0' })
    expect(parseSqlmap('[INFO] no parameters found\n[INFO] all tested parameters do not appear to be injectable')).toBeNull()
  })

  it('plans a sqlmap proof from a database-error finding', () => {
    const finding: Finding = {
      id: 'f1',
      tool: 'MacSec',
      category: 'web',
      severity: 'high',
      title: 'A quote in "id" makes the page show a database error: /product',
      url: `${TARGET}/product?id=1`,
      confidence: 'confirmed'
    }
    const p = planFromRules({ target: TARGET, goal: ['confidentiality'], findings: [finding], caps: { requests: 300, writes: 5, minutes: 15 } })
    expect(p.steps[0].action).toBe('sql-injection-proof')
    expect(p.steps[0].url).toBe(`${TARGET}/product`)
    expect(p.steps[0].param).toBe('id')
    expect(p.steps[0].preview.join(' ')).toMatch(/risk 1/)
  })

  it('proves an injection with a bounded sqlmap run, counting its requests against the engagement', async () => {
    setSqlmapRunner(async (bin, args) => {
      expect(bin).toContain('sqlmap')
      expect(args).toContain('--risk=1')
      expect(args).toContain('--level=1')
      expect(args).toContain('--technique=BE')
      expect(args.join(' ')).not.toMatch(/--dump|--os-shell|--sql-shell|--file-read|--file-write|--tamper/)
      return SQLMAP_OUT
    })
    const e = saveEngagement({ client: 'Acme', authorityRef: 'R-2', authorizedBy: 'CISO', hosts: [HOST], startsAt: iso(-1), endsAt: iso(5), caps: { requests: 300, writes: 5, minutes: 15 }, allowed: ['confidentiality', 'integrity'] })
    const run = await runCampaign({ plan: plan([step()], { engagementId: e.id }), engagement: e, approved: ['s1'], phrase: PHRASE, acceptLeftovers: false, delayMs: 0, guard: false })
    expect(run.steps[0].status).toBe('proven')
    expect(run.steps[0].title).toMatch(/SQL injection/)
    expect(run.steps[0].evidence?.shows.join(' ')).toMatch(/risk 1/)
    expect(engagementUsage(e.id).requests).toBe(80)
  })

  it('refuses sqlmap when the cap cannot pay for it', async () => {
    const e = engagement({ caps: { requests: 20, writes: 0, minutes: 10 } })
    const run = await runCampaign({ plan: plan([step()]), engagement: e, approved: ['s1'], phrase: PHRASE, acceptLeftovers: false, delayMs: 0, guard: false })
    expect(run.steps[0].status).toBe('not-proven')
    expect(run.requests).toBe(0)
  })
})
