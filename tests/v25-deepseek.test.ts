import { mkdtempSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { beforeAll, describe, expect, it } from 'vitest'
import { chosenLocal, listServers, saveServer, setModelCrypto } from '../src/main/models'
import { setRoot, ensureDirs } from '../src/main/paths'
import { setSettings, getSettings } from '../src/main/settings'
import { anthropicBase, localModelEnv } from '../src/main/seckit/reviewers'

describe('DeepSeek for Claude Code', () => {
  beforeAll(() => {
    setRoot(mkdtempSync(join(tmpdir(), 'macsec-ds-')))
    ensureDirs()
    setModelCrypto({ available: () => true, encrypt: (s) => `enc:${s}`, decrypt: (s) => s.replace(/^enc:/, '') })
  })
  it('points Claude Code at DeepSeek with the saved key, kept out of the list', () => {
    const list = saveServer({ name: 'DeepSeek for Claude Code', baseUrl: 'https://api.deepseek.com/anthropic', api: 'anthropic', key: 'sk-test-123456' })
    expect(list[0].hasKey).toBe(true)
    expect(JSON.stringify(list)).not.toContain('sk-test')
    setSettings({ llm: { baseUrl: 'https://api.deepseek.com/anthropic', model: 'deepseek-v4-pro' } })
    const m = chosenLocal()
    expect(m.token).toBe('sk-test-123456')
    expect(anthropicBase(m.baseUrl)).toBe('https://api.deepseek.com/anthropic')
    const env = localModelEnv(m)
    expect(env.ANTHROPIC_BASE_URL).toBe('https://api.deepseek.com/anthropic')
    expect(env.ANTHROPIC_AUTH_TOKEN).toBe('sk-test-123456')
    expect(env.ANTHROPIC_MODEL).toBe('deepseek-v4-pro')
    expect(listServers()[0].baseUrl).toBe('https://api.deepseek.com/anthropic')
  })
  it('a local model has no key', () => {
    setSettings({ llm: { baseUrl: 'http://127.0.0.1:1234/v1', model: 'x' } })
    expect(chosenLocal().token).toBeUndefined()
  })
  it('refuses a server outside your network without https', () => {
    expect(() => saveServer({ name: 'x', baseUrl: 'http://api.deepseek.com/anthropic', api: 'anthropic' })).toThrow(/https/)
  })
})
