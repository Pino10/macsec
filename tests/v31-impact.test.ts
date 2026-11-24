/**
 * Controlled proofs: the gate is the feature. These tests are about the refusals as much as the
 * proofs, because a run that cannot happen is the point of an engagement.
 */
import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, readdirSync, readFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { setRoot } from '../src/main/paths'
import {
  engagementProblem,
  engagementUsage,
  normaliseDraft,
  revokeEngagement,
  saveEngagement,
  withUsage
} from '../src/main/engagement'
import { exploitPhrase, hostCovers, phraseMatches, validCaps, validImpacts, validScopeHost, validWindow, validUrl } from '../src/main/validate'
import { IMPACT_ACTIONS, actionInfo } from '../src/main/impact/catalog'
import { aiPlanCost, aiPlannerPrompt, checkStep, parseAiPlan, planFromRules } from '../src/main/impact/planner'
import { runCampaign, runProblem } from '../src/main/impact/campaign'
import { maskUrl, requestStop, clearStop, safeHeaders } from '../src/main/impact/client'
import { previewOf } from '../src/main/impact/actions'
import type { Engagement, ImpactPlan, PlannedStep } from '../src/shared/impact'
import type { Finding } from '../src/shared/types'

const iso = (offsetDays: number): string => new Date(Date.now() + offsetDays * 86400_000).toISOString()
const TARGET = 'http://shop.example.test'
const HOST = 'shop.example.test'
const PHRASE = exploitPhrase(HOST)

let dir = ''
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'macsec-impact-'))
  setRoot(dir)
  clearStop()
})
afterEach(() => {
  clearStop()
  rmSync(dir, { recursive: true, force: true })
})

const engagement = (over: Partial<Engagement> = {}): Engagement => ({
  id: 'eng-test0001',
  client: 'Acme',
  authorityRef: 'REF-1',
  authorizedBy: 'The client',
  hosts: [HOST],
  allowPrivate: true,
  startsAt: iso(-1),
  endsAt: iso(7),
  caps: { requests: 50, writes: 5, minutes: 10 },
  allowed: ['confidentiality', 'integrity', 'availability'],
  createdAt: iso(0),
  used: { requests: 0, writes: 0 },
  ...over
})

const step = (over: Partial<PlannedStep> = {}): PlannedStep => ({
  id: 's1',
  action: 'traversal-read',
  aims: 'confidentiality',
  url: `${TARGET}/download`,
  param: 'file',
  why: 'the scan found a file parameter',
  preview: [],
  write: false,
  ...over
})

const plan = (steps: PlannedStep[], over: Partial<ImpactPlan> = {}): ImpactPlan => ({
  id: 'pl-test0001',
  engagementId: 'eng-test0001',
  target: TARGET,
  goal: ['confidentiality'],
  steps,
  source: 'rules',
  caps: { requests: 50, writes: 5, minutes: 10 },
  notes: [],
  at: iso(0),
  ...over
})

const finding = (over: Partial<Finding> = {}): Finding => ({
  id: 'f1',
  tool: 'MacSec',
  category: 'web',
  severity: 'high',
  title: 'Path traversal in the file parameter',
  url: `${TARGET}/download?file=readme.txt`,
  confidence: 'confirmed',
  ...over
})

type Fake = (url: string, init: RequestInit) => Promise<Response>
const fetchOf = (fn: Fake): typeof fetch => ((u: unknown, init?: unknown) => fn(String(u), (init ?? {}) as RequestInit)) as unknown as typeof fetch

describe('the engagement is the gate', () => {
  it('covers exact hosts and subdomains of a wildcard, never the apex', () => {
    expect(hostCovers(['shop.example.com'], 'shop.example.com')).toBe(true)
    expect(hostCovers(['shop.example.com'], 'www.shop.example.com')).toBe(false)
    expect(hostCovers(['*.example.com'], 'shop.example.com')).toBe(true)
    expect(hostCovers(['*.example.com'], 'a.b.example.com')).toBe(true)
    expect(hostCovers(['*.example.com'], 'example.com')).toBe(false)
    expect(hostCovers(['*.example.com'], 'notexample.com')).toBe(false)
  })

  it('refuses a URL where a host belongs, and a wildcard over an IP', () => {
    expect(() => validScopeHost('https://shop.example.com/path')).toThrow()
    expect(() => validScopeHost('*:443')).toThrow()
    expect(() => validScopeHost('*.10.0.0.1')).toThrow()
    expect(validScopeHost('*.Example.COM')).toBe('*.example.com')
  })

  it('clamps caps and refuses an empty impact set', () => {
    expect(validCaps({ requests: 999999, writes: -5, minutes: 99999 })).toEqual({ requests: 20000, writes: 0, minutes: 480 })
    expect(validCaps({})).toEqual({ requests: 400, writes: 10, minutes: 20 })
    expect(() => validImpacts([])).toThrow()
    expect(validImpacts(['integrity', 'integrity', 'nonsense'])).toEqual(['integrity'])
  })

  it('refuses a window that is reversed, in the past or longer than a year', () => {
    expect(() => validWindow(iso(5), iso(1))).toThrow()
    expect(() => validWindow(iso(-10), iso(-5))).toThrow()
    expect(() => validWindow(iso(0), iso(400))).toThrow()
    expect(() => validWindow('not a date', iso(1))).toThrow()
  })

  it('will not save an authority that allows writes but not integrity', () => {
    expect(() =>
      saveEngagement({ client: 'Acme', authorityRef: 'R', authorizedBy: 'C', hosts: [HOST], startsAt: iso(-1), endsAt: iso(5), caps: { requests: 10, writes: 3, minutes: 5 }, allowed: ['confidentiality'] })
    ).toThrow(/integrity/)
  })

  it('normalises and stores an engagement, then reports every reason it may not be used', () => {
    const saved = saveEngagement({ client: ' Acme ', authorityRef: 'REF-9', authorizedBy: 'CISO', hosts: ['SHOP.example.test', '*.acme.test'], stats: 1, startsAt: iso(-1), endsAt: iso(9), caps: { requests: 30, writes: 2, minutes: 10 }, allowed: ['confidentiality', 'integrity'] })
    expect(saved.hosts).toEqual(['shop.example.test', '*.acme.test'])
    expect(saved.caps).toEqual({ requests: 30, writes: 2, minutes: 10 })
    expect(engagementProblem(null, HOST, ['confidentiality'])).toMatch(/no engagement/)
    expect(engagementProblem(saved, 'other.example.test', ['confidentiality'])).toMatch(/not one of the hosts/)
    expect(engagementProblem(saved, HOST, ['availability'])).toMatch(/does not allow availability/)
    expect(engagementProblem(saved, HOST, ['confidentiality'])).toBeNull()
    const revoked = revokeEngagement(saved.id)
    expect(engagementProblem(revoked, HOST, ['confidentiality'])).toMatch(/revoked/)
  })

  it('counts what was already spent from the stored runs', async () => {
    const e = saveEngagement({ client: 'Acme', authorityRef: 'R', authorizedBy: 'C', hosts: [HOST], startsAt: iso(-1), endsAt: iso(5), caps: { requests: 50, writes: 5, minutes: 10 }, allowed: ['confidentiality', 'integrity'] })
    const run = await runCampaign({
      plan: plan([step()], { engagementId: e.id }),
      engagement: e,
      approved: ['s1'],
      phrase: PHRASE,
      acceptLeftovers: false,
      delayMs: 0,
      guard: false,
      fetchImpl: fetchOf(async () => new Response('<html>not found</html>', { status: 404 }))
    })
    // Every attempt answers 404, so the action tries all nine shapes and reports nothing.
    expect(run.requests).toBe(9)
    expect(run.steps[0].status).toBe('not-proven')
    expect(engagementUsage(e.id).requests).toBe(run.requests)
    expect(withUsage(e).used.requests).toBe(run.requests)
  })

  it('the phrase is the target, spelled exactly', () => {
    expect(phraseMatches(PHRASE, HOST)).toBe(true)
    expect(phraseMatches('EXPLOIT other.test', HOST)).toBe(false)
    expect(phraseMatches('exploit shop.example.test', HOST)).toBe(false)
    expect(phraseMatches(PHRASE, 'other.test')).toBe(false)
  })
})

describe('planning', () => {
  it('proposes a file read for a traversal finding, on its own page and parameter', () => {
    const p = planFromRules({ target: TARGET, goal: ['confidentiality'], findings: [finding()], caps: { requests: 50, writes: 5, minutes: 10 } })
    expect(p.steps).toHaveLength(1)
    expect(p.steps[0].action).toBe('traversal-read')
    expect(p.steps[0].url).toBe(`${TARGET}/download`)
    expect(p.steps[0].param).toBe('file')
    expect(p.steps[0].preview.length).toBeGreaterThan(0)
  })

  it('proposes template arithmetic and an upload, and says what the upload still needs', () => {
    const findings = [
      finding({ id: 'f1', title: 'Server-side template injection in q', url: `${TARGET}/search?q=x` }),
      finding({ id: 'f2', title: 'File upload leaves files readable', url: `${TARGET}/avatar/upload?user=1` })
    ]
    const p = planFromRules({ target: TARGET, goal: ['integrity'], findings, caps: { requests: 50, writes: 5, minutes: 10 } })
    const kinds = p.steps.map((s) => s.action)
    expect(kinds).toContain('ssti-marker')
    expect(kinds).toContain('upload-write')
    expect(p.notes.join(' ')).toMatch(/read back/)
    expect(p.steps.find((s) => s.action === 'upload-write')?.write).toBe(true)
  })

  it('ignores a finding on another origin and one that was ruled out', () => {
    const p = planFromRules({
      target: TARGET,
      goal: ['confidentiality'],
      findings: [finding({ url: 'http://evil.test/download?file=x' }), finding({ id: 'f2', verdict: 'false-positive' })],
      caps: { requests: 50, writes: 5, minutes: 10 }
    })
    expect(p.steps).toHaveLength(0)
    expect(p.notes.join(' ')).toMatch(/replay/)
  })

  it('rejects a step the catalogue does not know, an off-site address, a missing parameter and a write with no undo', () => {
    expect(checkStep({ action: 'drop-tables', url: TARGET }, TARGET)).toEqual({ reason: 'unknown proof drop-tables' })
    expect('reason' in checkStep({ action: 'traversal-read', url: 'http://evil.test/x', param: 'f' }, TARGET)).toBe(true)
    expect('reason' in checkStep({ action: 'traversal-read', url: `${TARGET}/x` }, TARGET)).toBe(true)
    const write = checkStep({ action: 'replay-request', url: `${TARGET}/cart`, method: 'POST', body: 'a=1', expect: 'ok' }, TARGET)
    expect('reason' in write).toBe(true)
    const ok = checkStep({ action: 'replay-request', url: `${TARGET}/cart`, method: 'POST', body: 'a=1', expect: 'ok', undo: 'delete the row I made' }, TARGET)
    expect('step' in ok && ok.step.write).toBe(true)
  })

  it('takes only valid steps from an AI answer, and says why the rest were dropped', () => {
    const text = 'here:\n```json\n{"steps":[{"action":"traversal-read","aims":"confidentiality","url":"' + TARGET + '/download","param":"file","why":"w"},{"action":"replay-request","url":"http://evil.test/x","expect":"a"}]}\n```'
    const p = parseAiPlan(text, { target: TARGET, goal: ['confidentiality'], findings: [], caps: { requests: 50, writes: 5, minutes: 10 } })
    expect(p.steps).toHaveLength(1)
    expect(p.steps[0].id).toBe('s1')
    expect(p.notes.join(' ')).toMatch(/not used/)
    expect(parseAiPlan('no json here', { target: TARGET, goal: ['confidentiality'], findings: [], caps: { requests: 50, writes: 5, minutes: 10 } }).notes.join(' ')).toMatch(/no JSON block/)
  })

  it('keeps the AI prompt small and free of source code', () => {
    const prompt = aiPlannerPrompt({ target: TARGET, goal: ['confidentiality'], findings: [finding({ description: 'secret source line' })], caps: { requests: 50, writes: 5, minutes: 10 } })
    expect(prompt).not.toContain('secret source line')
    expect(prompt).toContain('traversal-read')
    const cost = aiPlanCost(prompt)
    expect(cost.calls).toBe(1)
    expect(cost.tokens).toBeLessThan(4000)
  })

  it('previews the exact requests for every action in the catalogue', () => {
    for (const a of IMPACT_ACTIONS) {
      const p = previewOf({ id: 's1', action: a.id, aims: a.impact[0], url: `${TARGET}/page`, param: 'p', why: '', preview: [], write: a.writes })
      expect(p.length).toBeGreaterThan(0)
    }
    expect(actionInfo('traversal-read').maxRequests).toBeLessThanOrEqual(10)
  })
})

describe('the refusals', () => {
  it('will not run without the phrase, without approvals, or without accepting a write', () => {
    const e = engagement()
    const base = { plan: plan([step(), step({ id: 's2', action: 'upload-write', write: true, param: 'file', verifyUrl: `${TARGET}/u/{name}`, undo: 'delete the file' })]), engagement: e, phrase: PHRASE, acceptLeftovers: false }
    expect(runProblem({ ...base, approved: ['s1'] })).toBeNull()
    expect(runProblem({ ...base, phrase: 'nope', approved: ['s1'] })).toMatch(/EXPLOIT/)
    expect(runProblem({ ...base, approved: [] })).toMatch(/at least one step/)
    expect(runProblem({ ...base, approved: ['s1', 's2'] })).toMatch(/accept/)
    expect(runProblem({ ...base, approved: ['s1', 's2'], acceptLeftovers: true })).toBeNull()
  })

  it('refuses a run whose engagement does not allow the goal or the host', () => {
    const e = engagement({ allowed: ['confidentiality'] })
    const wrongGoal = plan([step({ aims: 'integrity' })], { goal: ['integrity'] })
    expect(runProblem({ plan: wrongGoal, engagement: e, approved: ['s1'], phrase: PHRASE, acceptLeftovers: false })).toMatch(/does not allow integrity/)
    const otherHost = plan([step()], { target: 'http://other.test' })
    expect(runProblem({ plan: otherHost, engagement: e, approved: ['s1'], phrase: exploitPhrase('other.test'), acceptLeftovers: false })).toMatch(/not one of the hosts/)
  })

  it('refuses a step that points off the target, and one that changes data when the engagement does not allow it', async () => {
    const e = engagement()
    const off = await runCampaign({ plan: plan([step({ url: 'http://other.test/download' })]), engagement: e, approved: ['s1'], phrase: PHRASE, acceptLeftovers: false, delayMs: 0, guard: false, fetchImpl: fetchOf(async () => new Response('x')) })
    expect(off.steps[0].status).toBe('failed')
    expect(off.steps[0].detail).toMatch(/target site itself/)
    expect(off.requests).toBe(0)
    const readOnly = engagement({ allowed: ['confidentiality'], caps: { requests: 10, writes: 0, minutes: 5 } })
    const writePlan = plan([step({ action: 'replay-request', method: 'POST', write: true, url: `${TARGET}/cart`, expect: 'ok', undo: 'x' })])
    expect(runProblem({ plan: writePlan, engagement: readOnly, approved: ['s1'], phrase: PHRASE, acceptLeftovers: true })).toMatch(/does not allow integrity/)
    await expect(
      runCampaign({ plan: writePlan, engagement: readOnly, approved: ['s1'], phrase: PHRASE, acceptLeftovers: true, delayMs: 0, guard: false, fetchImpl: fetchOf(async () => new Response('ok')) })
    ).rejects.toThrow(/integrity/)
  })

  it('stops when the person stops it', async () => {
    const e = engagement()
    const run = await runCampaign({
      plan: plan([step(), step({ id: 's2' })], { goal: ['confidentiality', 'integrity'] }),
      engagement: e,
      approved: ['s1', 's2'],
      phrase: PHRASE,
      acceptLeftovers: false,
      delayMs: 0,
      guard: false,
      fetchImpl: fetchOf(async () => {
        requestStop()
        return new Response('nope', { status: 404 })
      })
    })
    expect(run.stopped).toMatch(/Stopped/)
    expect(run.steps).toHaveLength(1)
  })
})

describe('the proofs', () => {
  it('proves a file read, and keeps the file itself out of the record', async () => {
    const e = engagement()
    const passwd = 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n'
    const run = await runCampaign({
      plan: plan([step()]),
      engagement: e,
      approved: ['s1'],
      phrase: PHRASE,
      acceptLeftovers: false,
      delayMs: 0,
      guard: false,
      fetchImpl: fetchOf(async (url) => {
        const q = new URL(url).searchParams.get('file') ?? ''
        return q.includes('etc/passwd') ? new Response(passwd, { status: 200, headers: { 'content-type': 'text/plain' } }) : new Response('<html>no</html>', { status: 404 })
      })
    })
    expect(run.proven).toEqual(['confidentiality'])
    expect(run.steps[0].status).toBe('proven')
    expect(run.steps[0].evidence?.shows.join(' ')).toMatch(/passwd/)
    expect(JSON.stringify(run)).not.toContain('daemon:x:1:1')
  })

  it('writes one file, reads it back, and removes it again', async () => {
    const e = engagement()
    const seen: string[] = []
    let uploaded = ''
    const run = await runCampaign({
      plan: plan([step({ action: 'upload-write', param: 'file', write: true, aims: 'integrity', verifyUrl: `${TARGET}/u/{name}`, undo: 'delete the file' })], { goal: ['integrity'] }),
      engagement: e,
      approved: ['s1'],
      phrase: PHRASE,
      acceptLeftovers: true,
      delayMs: 0,
      guard: false,
      fetchImpl: fetchOf(async (url, init) => {
        seen.push(`${init.method ?? 'GET'} ${url}`)
        if (init.method === 'POST') {
          expect(init.body).toBeInstanceOf(FormData)
          uploaded = 'macsec-proof-test.txt'
          return new Response('{"ok":true}', { status: 201 })
        }
        if (init.method === 'DELETE') return new Response(null, { status: 204 })
        return new Response(`macsec-${uploaded.includes('proof') ? 'marker' : 'x'}`, { status: 200 })
      })
    })
    // The file never comes back with its marker, so nothing is proven, but the delete is still tried.
    expect(seen.some((s) => s.startsWith('POST'))).toBe(true)
    expect(seen.some((s) => s.startsWith('DELETE'))).toBe(true)
    expect(run.steps[0].status).toBe('not-proven')
    expect(run.steps[0].cleanup?.done).toBe(true)
    expect(run.leftover).toHaveLength(0)
  })

  it('proves a write when the file really comes back with its marker', async () => {
    const e = engagement()
    let marker = ''
    const run = await runCampaign({
      plan: plan([step({ action: 'upload-write', param: 'file', write: true, aims: 'integrity', verifyUrl: `${TARGET}/u/{name}`, undo: 'delete the file' })], { goal: ['integrity'] }),
      engagement: e,
      approved: ['s1'],
      phrase: PHRASE,
      acceptLeftovers: true,
      delayMs: 0,
      guard: false,
      fetchImpl: fetchOf(async (url, init) => {
        if (init.method === 'POST') {
          const form = init.body as FormData
          const file = form.get('file') as File
          marker = (await file.text()).split('\n')[0]
          return new Response('{"ok":true}', { status: 201 })
        }
        if (init.method === 'DELETE') return new Response(null, { status: 204 })
        return new Response(marker, { status: 200 })
      })
    })
    expect(run.steps[0].status).toBe('proven')
    expect(run.steps[0].cleanup?.done).toBe(true)
    expect(run.leftover).toHaveLength(0)
  })

  it('shows template arithmetic and records no expression as proof of code execution', async () => {
    const e = engagement()
    const run = await runCampaign({
      plan: plan([step({ action: 'ssti-marker', param: 'q', aims: 'integrity' })], { goal: ['integrity'] }),
      engagement: e,
      approved: ['s1'],
      phrase: PHRASE,
      acceptLeftovers: false,
      delayMs: 0,
      guard: false,
      fetchImpl: fetchOf(async (url) => {
        const q = new URL(url).searchParams.get('q') ?? ''
        return new Response(q.includes('{{7*7}}') ? '<p>42 plus 7 is 49</p>' : '<p>hello</p>', { status: 200 })
      })
    })
    expect(run.steps[0].status).toBe('proven')
    expect(run.steps[0].title).toMatch(/calculates/)
    expect(run.steps[0].detail).toMatch(/stopped at arithmetic/)
  })

  it('replays exactly one request and proves only the string the person named', async () => {
    const e = engagement()
    let calls = 0
    const run = await runCampaign({
      plan: plan([step({ action: 'replay-request', method: 'GET', expect: 'admin', aims: 'confidentiality', url: `${TARGET}/admin` })]),
      engagement: e,
      approved: ['s1'],
      phrase: PHRASE,
      acceptLeftovers: false,
      delayMs: 0,
      guard: false,
      fetchImpl: fetchOf(async () => {
        calls++
        return new Response('<h1>admin panel</h1>', { status: 200 })
      })
    })
    expect(calls).toBe(1)
    expect(run.steps[0].status).toBe('proven')
    expect(run.requests).toBe(1)
  })

  it('measures one request against three without flooding, and believes only a real difference', async () => {
    const e = engagement()
    const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))
    let n = 0
    const run = await runCampaign({
      plan: plan([step({ action: 'availability-probe', aims: 'availability', url: `${TARGET}/report` })], { goal: ['availability'] }),
      engagement: e,
      approved: ['s1'],
      phrase: PHRASE,
      acceptLeftovers: false,
      delayMs: 0,
      guard: false,
      fetchImpl: fetchOf(async () => {
        n++
        if (n > 2) await sleep(320)
        return new Response('report', { status: 200 })
      })
    })
    expect(n).toBe(5)
    expect(run.steps[0].status).toBe('proven')
    expect(run.steps[0].detail).toMatch(/not a denial of service/)
  })
})

describe('the record', () => {
  it('hides secret values in the audit log and in a masked address', () => {
    expect(maskUrl(`https://x.test/a?token=abc123&id=7`)).toContain('token=%5Bhidden%5D')
    expect(maskUrl(`https://x.test/a?token=abc123&id=7`)).toContain('id=7')
    expect(safeHeaders({ Cookie: 'a=b', 'X-Test': 'ok', Host: 'evil', 'bad name': 'x' })).toEqual({ Cookie: 'a=b', 'X-Test': 'ok' })
  })

  it('stores runs under ~/MacSec, one file each, and never the request bodies', async () => {
    const e = engagement()
    const run = await runCampaign({
      plan: plan([step({ action: 'replay-request', method: 'GET', expect: 'hello', aims: 'confidentiality', url: `${TARGET}/x`, headers: { Cookie: 'session=supersecret' } })]),
      engagement: e,
      approved: ['s1'],
      phrase: PHRASE,
      acceptLeftovers: false,
      delayMs: 0,
      guard: false,
      fetchImpl: fetchOf(async () => new Response('hello there', { status: 200 }))
    })
    const dirs = join(dir, 'impact-runs')
    const files = readdirSync(dirs)
    expect(files).toHaveLength(1)
    const stored = readFileSync(join(dirs, files[0]), 'utf8')
    expect(stored).toContain(run.id)
    expect(stored).not.toContain('supersecret')
  })

  it('keeps a normalised draft readable for the record', () => {
    const d = normaliseDraft({ client: 'Acme', authorityRef: 'R-1', authorizedBy: 'CISO', hosts: ['shop.example.test'], startsAt: iso(-1), endsAt: iso(3), caps: { requests: 10, writes: 1, minutes: 5 }, allowed: ['confidentiality', 'integrity'] })
    expect(d.client).toBe('Acme')
    expect(d.hosts).toEqual(['shop.example.test'])
    expect(new Date(d.endsAt).getTime()).toBeGreaterThan(Date.now())
  })
})
