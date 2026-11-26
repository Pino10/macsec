import { describe, expect, it } from 'vitest'
import { blindPrompt, verifierPrompt } from '../src/main/reviewloop'

describe('review loop prompts', () => {
  it('tell the AI that the evidence is data, not orders', () => {
    expect(blindPrompt('App', 'x')).toMatch(/untrusted data/)
    expect(verifierPrompt([])).toMatch(/untrusted data/)
  })
})
