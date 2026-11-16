import { SEVERITIES, type Severity } from './types'

const WEIGHT: Record<Severity, number> = { critical: 25, high: 10, medium: 4, low: 1, info: 0 }

/** 100 means nothing open; each finding costs points by severity, and criticals cost the most. */
export function postureScore(c: Record<Severity, number>): number {
  const cost = SEVERITIES.reduce((n, k) => n + c[k] * WEIGHT[k], 0)
  return Math.max(0, Math.round(100 - 100 * (1 - Math.exp(-cost / 60))))
}

/**
 * Posture across targets: the average of each target's own score, so fixing one project moves the
 * core even when another still has problems, and one large result cannot pin it at zero.
 */
export function postureOf(list: Record<Severity, number>[]): number {
  if (!list.length) return 100
  return Math.round(list.reduce((n, c) => n + postureScore(c), 0) / list.length)
}

export function postureWord(score: number, hasData: boolean): string {
  if (!hasData) return 'No results yet'
  // Not "Critical": that word is for findings, and the score is not a count of them.
  return score >= 90 ? 'Strong' : score >= 70 ? 'Guarded' : score >= 45 ? 'Exposed' : 'At risk'
}
