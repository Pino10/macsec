import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
import { checkFreeLlm, checkFreeLlmKey, FREELLM_DEFAULT_URL, freeLlmEnv, freeLlmModel, freeLlmModels, freeLlmUrl } from '../src/main/seckit/freellm'
import { explainFailure, reviewerRun } from '../src/main/seckit/reviewers'
import { commandToSkill, packContents, SKILL_PACKS } from '../src/main/seckit/skillpacks'

const fixture = (n: string): string => readFileSync(join(__dirname, 'fixtures', 'packs', n), 'utf8')

describe('Free LLM API', () => {
  it('keeps the address on this Mac or on https', () => {
    expect(freeLlmUrl('')).toBe(FREELLM_DEFAULT_URL)
    expect(freeLlmUrl('http://localhost:31415')).toBe('http://127.0.0.1:31415/v1')
    expect(freeLlmUrl('127.0.0.1:31415/v1/')).toBe('http://127.0.0.1:31415/v1')
    expect(freeLlmUrl('http://127.0.0.1:31415/v1/chat/completions')).toBe('http://127.0.0.1:31415/v1')
    expect(freeLlmUrl('https://llm.example.com')).toBe('https://llm.example.com/v1')
    expect(() => freeLlmUrl('http://192.168.1.5:3001')).toThrow(/https/)
    expect(() => freeLlmUrl('http://user:pw@127.0.0.1:31415')).toThrow(/key box/)
  })
  it('checks keys and model names', () => {
    expect(checkFreeLlmKey('  freellmapi-0123456789abcdef0123  ')).toBe('freellmapi-0123456789abcdef0123')
    expect(() => checkFreeLlmKey('Bearer freellmapi-0123456789abcdef')).toThrow()
    expect(() => checkFreeLlmKey('short')).toThrow()
    expect(freeLlmModel('')).toBe('auto')
    expect(freeLlmModel('auto:fast')).toBe('auto:fast')
    expect(freeLlmModel('groq/llama-3.3-70b')).toBe('groq/llama-3.3-70b')
    expect(() => freeLlmModel('auto; rm -rf')).toThrow()
  })
  it('lists auto first, then the models', () => {
    expect(freeLlmModels({ data: [{ id: 'gemini-2.5-flash' }, { id: 'auto' }, { id: 'codestral' }] })).toEqual(['auto', 'auto:fast', 'codestral', 'gemini-2.5-flash'])
    expect(freeLlmModels(null)).toEqual(['auto', 'auto:fast'])
  })
  it('tells running, wrong key and not running apart', async () => {
    const seen: string[] = []
    const ok = await checkFreeLlm('http://127.0.0.1:31415/v1', 'freellmapi-x', async (url, init) => {
      seen.push(url, String(init?.headers?.Authorization))
      return { ok: true, status: 200, json: async () => ({ data: [{ id: 'gemini-2.5-flash' }] }), text: async () => '' }
    })
    expect(ok.ok).toBe(true)
    expect(ok.models).toContain('gemini-2.5-flash')
    expect(seen).toEqual(['http://127.0.0.1:31415/v1/models', 'Bearer freellmapi-x'])
    const bad = await checkFreeLlm('', 'k', async () => ({ ok: false, status: 401, json: async () => ({}), text: async () => '' }))
    expect(bad.note).toMatch(/did not accept the key/)
    const off = await checkFreeLlm('', 'k', async () => {
      throw new Error('ECONNREFUSED')
    })
    expect(off.note).toMatch(/not answering/)
  })
  it('points Claude Code at /v1/messages with the key', () => {
    const env = freeLlmEnv({ baseUrl: 'http://localhost:31415/v1', model: 'auto' }, 'freellmapi-abc')
    expect(env.ANTHROPIC_BASE_URL).toBe('http://127.0.0.1:31415')
    expect(env.ANTHROPIC_AUTH_TOKEN).toBe('freellmapi-abc')
    expect(env.ANTHROPIC_MODEL).toBe('auto')
    expect(env.ANTHROPIC_API_KEY).toBe('')
  })
  it('runs claude-free read-only on the chosen model', () => {
    const r = reviewerRun('claude-free', '/bin/claude', 'Review', { local: { baseUrl: 'http://127.0.0.1:31415/v1', model: 'auto:fast', token: 'freellmapi-k' } })
    expect(r.args).toContain('plan')
    expect(r.args.join(' ')).toContain('--model auto:fast')
    expect(r.args.join(' ')).toContain('--disallowedTools Bash,Edit,Write')
    expect(r.env.ANTHROPIC_AUTH_TOKEN).toBe('freellmapi-k')
    expect(reviewerRun('claude', '/bin/claude', 'Review').env).toEqual({})
    expect(explainFailure('claude-free', 'Error: 429 rate limit')).toMatch(/free limit/)
    expect(explainFailure('claude-free', 'connect ECONNREFUSED 127.0.0.1:31415')).toMatch(/could not reach Free LLM API/)
  })
})

describe('Cloudflare and Anthropic skill packs', () => {
  it('are on the list with their licences', () => {
    const cf = SKILL_PACKS.find((p) => p.id === 'cloudflare')!
    const an = SKILL_PACKS.find((p) => p.id === 'anthropic')!
    expect(cf.repo).toBe('cloudflare/security-audit-skill')
    expect(an.repo).toBe('anthropics/claude-code-security-review')
    expect([cf.license, an.license]).toEqual(['MIT', 'MIT'])
  })
  it('turns /security-review into a skill a read-only review can follow', () => {
    const md = fixture('security-review.md')
    const skill = commandToSkill(md, 'security-review', 'Anthropic, MIT')
    expect(skill.startsWith('---\nname: security-review\ndescription: Complete a security review')).toBe(true)
    expect(skill).not.toContain('!`')
    expect(skill).not.toContain('allowed-tools')
    expect(skill).toContain('the output of `git diff --merge-base origin/HEAD`')
    expect(skill).toContain('HIGH-CONFIDENCE')
  })
  it('finds what each layout provides', () => {
    const root = mkdtempSync(join(tmpdir(), 'packs-'))
    mkdirSync(join(root, 'cf', 'skills', 'security-audit'), { recursive: true })
    writeFileSync(join(root, 'cf', 'skills', 'security-audit', 'SKILL.md'), '---\nname: security-audit\n---\n')
    mkdirSync(join(root, 'an', '.claude', 'commands'), { recursive: true })
    writeFileSync(join(root, 'an', '.claude', 'commands', 'security-review.md'), fixture('security-review.md'))
    expect(packContents(SKILL_PACKS.find((p) => p.id === 'cloudflare')!, join(root, 'cf'))).toEqual(['security-audit'])
    expect(packContents(SKILL_PACKS.find((p) => p.id === 'anthropic')!, join(root, 'an'))).toEqual(['security-review'])
    expect(packContents(SKILL_PACKS.find((p) => p.id === 'anthropic')!, join(root, 'cf'))).toEqual([])
  })
})
