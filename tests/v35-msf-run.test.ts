/** Metasploit may run, but only from a short list, only with a callback, and only on staging. */
import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { setRoot } from '../src/main/paths'
import { MODULES, RUN_MODULES, runArgs, validRunModule } from '../src/main/msf'
import { checkStep, planFromRules } from '../src/main/impact/planner'
import { setMsfRunRunner } from '../src/main/impact/actions'
import { runCampaign } from '../src/main/impact/campaign'
import { saveEngagement } from '../src/main/engagement'
import { exploitPhrase } from '../src/main/validate'
import type { Engagement, ImpactPlan, PlannedStep } from '../src/shared/impact'

const iso = (d: number): string => new Date(Date.now() + d * 86400_000).toISOString()
let dir = ''
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'macsec-msf-'))
  setRoot(dir)
})
afterEach(() => {
  setMsfRunRunner(null)
  rmSync(dir, { recursive: true, force: true })
})

const engagement = (over: Partial<Engagement> = {}): Engagement => ({
  id: 'eng-msf001',
  client: 'Acme',
  authorityRef: 'R-3',
  authorizedBy: 'CISO',
  hosts: ['shop.example.test'],
  allowPrivate: true,
  startsAt: iso(-1),
  endsAt: iso(5),
  caps: { requests: 100, writes: 0, minutes: 10 },
  allowed: ['confidentiality', 'integrity', 'availability'],
  createdAt: iso(0),
  used: { requests: 0, writes: 0 },
  ...over
})

const step = (over: Partial<PlannedStep> = {}): PlannedStep => ({
  id: 's1',
  action: 'msf-run',
  aims: 'integrity',
  url: 'http://shop.example.test:8080/',
  module: 'exploit/multi/http/apache_mod_cgi_bash_env_exec',
  why: 'the scan matched a known flaw to code execution',
  preview: [],
  ...over
})

const plan = (steps: PlannedStep[], over: Partial<ImpactPlan> = {}): ImpactPlan => ({ id: 'pl-msf001', engagementId: 'eng-msf001', target: 'http://shop.example.test', goal: ['integrity'], steps, source: 'rules', caps: { requests: 100, writes: 0, minutes: 10 }, notes: [], at: iso(0), ...over })
const PHRASE = exploitPhrase('shop.example.test')

describe('the run-only list', () => {
  it('never mixes the check list and the run list, and keeps crash-prone modules out', () => {
    const checks = new Set(MODULES.map((m) => m.module))
    for (const m of RUN_MODULES) {
      expect(checks.has(m.module)).toBe(false)
      expect(m.module).toMatch(/^exploit\/[a-z0-9_/]+$/)
    }
    const ids = RUN_MODULES.map((m) => m.module).join(' ')
    expect(ids).not.toMatch(/ms17_010|bluekeep|spring4shell|proxylogon|drupalgeddon/)
    expect(validRunModule('exploit/multi/http/apache_mod_cgi_bash_env_exec')).toBe(true)
    expect(validRunModule('exploit/multi/handler')).toBe(false)
    expect(validRunModule('auxiliary/scanner/smb/smb_ms17_010')).toBe(false)
  })

  it('writes one script, with a command payload and no handler', () => {
    const command = 'curl -sS -m 10 http://192.168.1.20:4000/macsec-abc || wget -qO- -T 10 http://192.168.1.20:4000/macsec-abc'
    const args = runArgs('exploit/multi/http/apache_mod_cgi_bash_env_exec', 'shop.example.test', 80, command)
    const script = args[3]
    expect(script).toContain('set PAYLOAD cmd/unix/generic')
    expect(script).toContain('set DisablePayloadHandler true')
    expect(script).toContain('run; exit -y')
    expect(script).not.toMatch(/meterpreter|set LHOST|sessions|shell\b/)
    expect(() => runArgs('exploit/multi/handler', 'shop.example.test', 80, command)).toThrow()
    expect(() => runArgs('exploit/multi/http/apache_mod_cgi_bash_env_exec', 'shop.example.test', 80, 'id')).toThrow()
  })
})

describe('the callback proof', () => {
  it('needs a callback: a run that nothing calls back from is not proven', async () => {
    setMsfRunRunner(async () => '[*] Exploit completed, but no session was created.')
    const e = saveEngagement({ client: 'Acme', authorityRef: 'R-3', authorizedBy: 'CISO', hosts: ['shop.example.test'], allowPrivate: true, startsAt: iso(-1), endsAt: iso(5), caps: { requests: 100, writes: 0, minutes: 10 }, allowed: ['integrity'] })
    const run = await runCampaign({ plan: plan([step()], { engagementId: e.id }), engagement: e, approved: ['s1'], phrase: PHRASE, acceptLeftovers: false, delayMs: 0, guard: false })
    expect(run.steps[0].status).toBe('not-proven')
    expect(run.steps[0].detail).toMatch(/nothing called back|not be able to reach/)
  }, 70000)

  it('proves code execution when the command calls back from the target', async () => {
    const e = saveEngagement({ client: 'Acme', authorityRef: 'R-3', authorizedBy: 'CISO', hosts: ['shop.example.test'], allowPrivate: true, startsAt: iso(-1), endsAt: iso(5), caps: { requests: 100, writes: 0, minutes: 10 }, allowed: ['integrity'] })
    setMsfRunRunner(async (_bin, args) => {
      // What a real target would do: run the command, which calls back to this Mac.
      const callback = /https?:\/\/[\w.:[\]-]+\/macsec-[a-z0-9]+/.exec(args[3])?.[0]
      expect(callback).toBeTruthy()
      await fetch(callback!, { headers: { 'User-Agent': 'curl/8.7.1' } })
      return '[+] Command shell session opened'
    })
    const run = await runCampaign({ plan: plan([step()], { engagementId: e.id }), engagement: e, approved: ['s1'], phrase: PHRASE, acceptLeftovers: false, delayMs: 0, guard: false })
    expect(run.steps[0].status).toBe('proven')
    expect(run.steps[0].evidence?.method).toBe('CALLBACK')
    expect(run.steps[0].evidence?.shows.join(' ')).toMatch(/curl|request arrived/)
    expect(run.steps[0].detail).toMatch(/Code execution|an attacker/)
  }, 70000)

  it('refuses to run when the engagement is not a staging one, because the callback cannot reach this Mac', async () => {
    const e = saveEngagement({ client: 'Acme', authorityRef: 'R-3', authorizedBy: 'CISO', hosts: ['shop.example.test'], allowPrivate: false, startsAt: iso(-1), endsAt: iso(5), caps: { requests: 100, writes: 0, minutes: 10 }, allowed: ['integrity'] })
    setMsfRunRunner(async () => 'should not run')
    const run = await runCampaign({ plan: plan([step()], { engagementId: e.id }), engagement: e, approved: ['s1'], phrase: PHRASE, acceptLeftovers: false, delayMs: 0, guard: false })
    expect(run.steps[0].status).toBe('failed')
    expect(run.steps[0].detail).toMatch(/staging/)
    expect(run.requests).toBe(0)
  })
})

describe('planning a run', () => {
  it('proposes a run only for a code-execution finding, and only with a module from the list', () => {
    const finding = { id: 'f1', tool: 'MacSec' as const, category: 'web' as const, severity: 'critical' as const, title: 'Remote code execution in the template engine', url: 'http://shop.example.test/render?tpl=x', confidence: 'possible' as const }
    const p = planFromRules({ target: 'http://shop.example.test', goal: ['integrity'], findings: [finding], caps: { requests: 100, writes: 0, minutes: 10 } })
    const run = p.steps.find((x) => x.action === 'msf-run')
    expect(run).toBeTruthy()
    expect(run?.module).toBe('')
    expect(p.notes.join(' ')).toMatch(/pick the Metasploit module/)
    const rejected = checkStep({ action: 'msf-run', url: 'http://shop.example.test/render', module: 'exploit/multi/handler' }, 'http://shop.example.test')
    expect('reason' in rejected).toBe(true)
    const allowed = checkStep({ action: 'msf-run', url: 'http://shop.example.test/render', module: 'exploit/multi/http/apache_mod_cgi_bash_env_exec' }, 'http://shop.example.test')
    expect('step' in allowed).toBe(true)
  })
})
