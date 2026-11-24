/** The estimates shown before a scan starts: stable, honest, and labelled as estimates. */
import { describe, expect, it } from 'vitest'
import { estimateReview, estimateWebScan, minutesText, tokensText } from '../src/shared/estimate'

describe('the web scan estimate', () => {
  it('grows with the options, and gentle pacing takes longer for the same requests', () => {
    const base = { mode: 'standard' as const, pacing: 'normal' as const, confirm: false, discover: false, autopilot: false, checklist: false, signedIn: false, white: false }
    const small = estimateWebScan(base)
    const fullInput = { ...base, confirm: true, discover: true, signedIn: true, autopilot: true }
    const full = estimateWebScan(fullInput)
    expect(full.requests).toBeGreaterThan(small.requests)
    expect(full.minutes).toBeGreaterThan(small.minutes)
    const gentle = estimateWebScan({ ...fullInput, pacing: 'gentle' })
    expect(gentle.requests).toBe(full.requests)
    expect(gentle.minutes).toBeGreaterThan(full.minutes)
    expect(full.heaviest).toMatch(/scan itself|discovery|confirmations/)
  })
  it('quick is smaller than thorough, and the text helpers read well', () => {
    const quick = estimateWebScan({ mode: 'quick', pacing: 'normal', confirm: false, discover: false, autopilot: false, checklist: false, signedIn: false, white: false })
    const thorough = estimateWebScan({ mode: 'thorough', pacing: 'normal', confirm: false, discover: false, autopilot: false, checklist: false, signedIn: false, white: false })
    expect(thorough.requests).toBeGreaterThan(quick.requests * 5)
    expect(minutesText(75)).toBe('1 h 15 min')
    expect(minutesText(9)).toBe('9 min')
    expect(tokensText(160_000)).toBe('160k')
    expect(tokensText(1_400_000)).toBe('1.4M')
  })
})

describe('the review estimate', () => {
  it('says which reviewers cost nothing and which have a bill', () => {
    expect(estimateReview({ depth: 'standard', reviewer: 'none' })).toMatchObject({ tokens: 0, costUsd: 0 })
    expect(estimateReview({ depth: 'standard', reviewer: 'claude' }).costUsd).toBeNull()
    expect(estimateReview({ depth: 'standard', reviewer: 'claude-local' }).costUsd).toBe(0)
    const api = estimateReview({ depth: 'deep', reviewer: 'model' })
    expect(api.costUsd).toBeGreaterThan(0)
    expect(api.note).toMatch(/rough bill|estimate|tokens/)
    expect(estimateReview({ depth: 'deep', reviewer: 'claude' }).tokens).toBeGreaterThan(estimateReview({ depth: 'quick', reviewer: 'claude' }).tokens)
  })
})
