/** 1.34: blind parsing, the merge rules, and the verifier's answers. */
import { describe, expect, it } from 'vitest'
import { blindPrompt, combineFindings, parseBlind, parseVerdicts, verifierPrompt } from '../src/main/reviewloop'

const tool = { id: 't1', title: 'Missing screenshot protection', severity: 'medium' as const, location: 'main.jsbundle', evidence: 'no ScreenshotBlockEnabled' }

describe('the blind review', () => {
  it('keeps only findings with a location, and defaults the severity', () => {
    const f = parseBlind('{"findings":[{"title":"Exported activity","location":"AndroidManifest.xml","evidence":"exported=true"},{"title":"No place","severity":"high"}]}')
    expect(f).toHaveLength(2) // a finding without a location is shown as "not stated", not hidden
    expect(f[0]).toMatchObject({ title: 'Exported activity', severity: 'medium', confidence: 'possible' })
    expect(f[1].location).toBe('not stated')
  })
  it('does not put the tool findings into the blind prompt', () => {
    const p = blindPrompt('App', 'evidence only')
    expect(p).toContain('NOT seen any scanner')
    expect(p).not.toContain('Missing screenshot protection')
  })
})

describe('the merge', () => {
  it('merges the same place with a similar title, keeps both sources and does not confirm', () => {
    const blind = [{ id: 'b1', title: 'No screenshot protection on the app', severity: 'high' as const, location: 'main.jsbundle', evidence: 'no flag', why: '', fix: '', confidence: 'possible' as const }]
    const c = combineFindings([tool], blind)
    expect(c).toHaveLength(1)
    expect(c[0]).toMatchObject({ sources: ['tools', 'ai'], agreement: true, conflict: false })
    expect(c[0]).not.toHaveProperty('confidence')
  })
  it('does not merge the same title at a different place', () => {
    const blind = [{ id: 'b1', title: 'Missing screenshot protection', severity: 'medium' as const, location: 'Info.plist', evidence: '', why: '', fix: '', confidence: 'possible' as const }]
    const c = combineFindings([tool], blind)
    expect(c).toHaveLength(2)
    expect(c.every((x) => !x.agreement)).toBe(true)
  })
  it('keeps an AI-only finding', () => {
    const blind = [{ id: 'b1', title: 'Test host in bundle', severity: 'high' as const, location: 'main.jsbundle', evidence: 'ebankingtest', why: '', fix: '', confidence: 'possible' as const }]
    const c = combineFindings([], blind)
    expect(c[0]).toMatchObject({ sources: ['ai'], agreement: false })
  })
})

describe('the verifier', () => {
  it('hides the sources and turns missing answers into uncertain', () => {
    const combined = combineFindings([tool], [])
    const p = verifierPrompt(combined)
    expect(p).not.toContain('"tools"')
    expect(p).not.toContain('"ai"')
    const v = parseVerdicts('{"verdicts":[{"id":"comb-1","verdict":"refuted","reason":"flag is present"}]}', combined)
    expect(v[0].verifier).toMatchObject({ verdict: 'refuted' })
    const none = parseVerdicts('{"verdicts":[]}', combined)
    expect(none[0].verifier?.verdict).toBe('uncertain')
  })
})
