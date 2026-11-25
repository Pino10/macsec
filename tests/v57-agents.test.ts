import { readdirSync, readFileSync, statSync } from 'fs'
import { join } from 'path'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = { auth: 'login', key: 'sk-test-123' as string | null }
vi.mock('../src/main/settings', () => ({ getSettings: () => ({ claudeAuth: state.auth }) }))
vi.mock('../src/main/secrets', () => ({ getSecret: () => state.key }))

import { agentEnv, shellQuote } from '../src/main/agents'

describe('agentEnv', () => {
  beforeEach(() => {
    state.auth = 'login'
    state.key = 'sk-test-123'
    process.env.ANTHROPIC_API_KEY = 'from-the-shell'
  })
  it('uses the sign-in by default and never leaks a key from the shell', () => {
    expect(agentEnv().ANTHROPIC_API_KEY).toBeUndefined()
  })
  it('uses the Keychain key only when the person chose "API key"', () => {
    state.auth = 'key'
    expect(agentEnv().ANTHROPIC_API_KEY).toBe('sk-test-123')
  })
  it('does not set a key that is not there, and turns colours off', () => {
    state.auth = 'key'
    state.key = null
    const e = agentEnv()
    expect(e.NO_COLOR).toBe('1')
    expect(e.PATH).toContain('/opt/homebrew/bin')
  })
})

describe('shellQuote', () => {
  it('keeps hostile text as one harmless word', () => {
    expect(shellQuote("a'b; rm -rf ~ #")).toBe(`'a'\\''b; rm -rf ~ #'`)
    expect(shellQuote('$(whoami)`id`')).toBe("'$(whoami)`id`'")
  })
})

describe('AI agents stay read-only', () => {
  const files: string[] = []
  const walk = (d: string): void => {
    for (const n of readdirSync(d)) {
      const p = join(d, n)
      if (statSync(p).isDirectory()) walk(p)
      else if (/\.tsx?$/.test(n)) files.push(p)
    }
  }
  walk(join(__dirname, '..', 'src'))
  /** Patch generation edits a scratch copy and is the one place an agent may edit files. */
  const patch = (f: string): boolean => /[\\/]main[\\/]patch\.ts$/.test(f)
  it('no code asks an agent to skip its permission checks', () => {
    const bad = files.filter((f) => /dangerously-skip-permissions|bypassPermissions|--yolo|danger-full-access/.test(readFileSync(f, 'utf8')))
    expect(bad).toEqual([])
  })
  it('only patch generation lets an agent edit, and it works in a scratch copy', () => {
    expect(files.filter((f) => /acceptEdits/.test(readFileSync(f, 'utf8')) && !patch(f))).toEqual([])
    expect(readFileSync(files.find(patch)!, 'utf8')).toMatch(/scratch/)
  })
  it('every other --permission-mode is plan', () => {
    const bad: string[] = []
    for (const f of files.filter((x) => !patch(x))) for (const m of readFileSync(f, 'utf8').matchAll(/'--permission-mode'\s*,\s*([^,\]\n]+)/g)) if (!/^'plan'/.test(m[1].trim())) bad.push(`${f}: ${m[1]}`)
    expect(bad).toEqual([])
  })
})
