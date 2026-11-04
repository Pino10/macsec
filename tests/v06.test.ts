import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
import { parseHadolint, parseZizmor } from '../src/main/scanners/parse'
import { findDockerfiles } from '../src/main/scanners/plan'
import { parsePassive } from '../src/main/seckit/recon'
import { findModel, plan, targetContext } from '../src/main/seckit/lmstudio'
import { SKILLS } from '../src/main/seckit/skills'

const fx = (n: string): string => readFileSync(join(__dirname, 'fixtures', n), 'utf8')

describe('zizmor and Hadolint (real output)', () => {
  it('reads zizmor findings for a risky workflow', () => {
    const f = parseZizmor(fx('zizmor.json'), '/tmp/sample')
    expect(f.length).toBeGreaterThan(3)
    const titles = f.map((x) => x.title).join('\n')
    expect(titles).toMatch(/template-injection|dangerous-triggers|unpinned-uses/)
    expect(f.every((x) => x.file === '.github/workflows/ci.yml' && x.category === 'config')).toBe(true)
    expect(f.find((x) => /artipacked/.test(x.title))?.line).toBe(10)
  })
  it('reads Hadolint and keeps the security-relevant rules', () => {
    const f = parseHadolint(fx('hadolint.json'), '/tmp/sample')
    expect(f.find((x) => x.title.includes('DL3007'))).toMatchObject({ severity: 'low', line: 1, file: 'Dockerfile' })
    expect(f.every((x) => x.tool === 'Hadolint')).toBe(true)
  })
  it('finds Dockerfiles but not in node_modules', () => {
    const root = mkdtempSync(join(tmpdir(), 'df-'))
    mkdirSync(join(root, 'api'))
    mkdirSync(join(root, 'node_modules', 'x'), { recursive: true })
    writeFileSync(join(root, 'Dockerfile'), 'FROM alpine')
    writeFileSync(join(root, 'api', 'prod.Dockerfile'), 'FROM alpine')
    writeFileSync(join(root, 'node_modules', 'x', 'Dockerfile'), 'FROM alpine')
    expect(findDockerfiles(root).sort()).toEqual(['Dockerfile', 'api/prod.Dockerfile'])
  })
})

describe('more passive recon sources', () => {
  it('keeps only names inside the domain', () => {
    expect(parsePassive('hackertarget', 'www.example.com,1.2.3.4\nevil.com,5.6.7.8\napi.example.com,1.1.1.1', 'example.com')).toEqual(['api.example.com', 'www.example.com'])
    expect(parsePassive('certspotter', JSON.stringify([{ dns_names: ['*.shop.example.com', 'example.com', 'other.org'] }]), 'example.com')).toEqual(['example.com', 'shop.example.com'])
    expect(parsePassive('otx', JSON.stringify({ passive_dns: [{ hostname: 'mail.example.com' }, { hostname: 'x.y' }] }), 'example.com')).toEqual(['mail.example.com'])
    expect(parsePassive('urlscan', JSON.stringify({ results: [{ page: { domain: 'cdn.example.com' }, task: { domain: 'example.com' } }] }), 'example.com')).toEqual(['cdn.example.com', 'example.com'])
    expect(parsePassive('anubis', 'not json', 'example.com')).toEqual([])
  })
})

describe('LM Studio context for Claude Code', () => {
  it('plans a reload when the model was loaded with a small context', () => {
    expect(targetContext(131072)).toBe(65536)
    expect(targetContext(40000)).toBe(40000)
    expect(plan({ key: 'qwen/qwen3-coder-30b', max_context_length: 262144, loaded_instances: [{ id: 'q', config: { context_length: 4096 } }] })).toMatchObject({ action: 'reload', target: 65536, current: 4096 })
    expect(plan({ key: 'q', max_context_length: 262144, loaded_instances: [{ id: 'q', config: { context_length: 40960 } }] }).action).toBe('none')
    expect(plan({ key: 'q', max_context_length: 262144 }).action).toBe('load')
    expect(plan({ key: 'tiny', max_context_length: 8192 }).action).toBe('too-small')
  })
  it('finds a model by key or loaded id', () => {
    const list = [{ key: 'openai/gpt-oss-20b', loaded_instances: [{ id: 'gpt-oss-20b' }] }, { key: 'google/gemma-3-12b' }]
    expect(findModel(list, 'gpt-oss-20b')?.key).toBe('openai/gpt-oss-20b')
    expect(findModel(list, 'google/gemma-3-12b')?.key).toBe('google/gemma-3-12b')
    expect(findModel(list, 'nope')).toBeNull()
  })
})

describe('review vectors', () => {
  it('has a skill for every area the plan names', () => {
    const plan = SKILLS['review-vectors'].body
    for (const name of [...plan.matchAll(/\| ([a-z-]+-(?:review|catalog|triage)) \|/g)].map((m) => m[1])) expect(SKILLS[name], name).toBeTruthy()
    expect(Object.keys(SKILLS).length).toBeGreaterThanOrEqual(20)
  })
})
