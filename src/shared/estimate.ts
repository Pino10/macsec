/** Honest, rough estimates shown before a scan starts. They are labelled as estimates, never promises. */

export type Pacing = 'normal' | 'gentle'

export interface ScanEstimate {
  requests: number
  minutes: number
  /** The biggest single source of requests, for the summary line. */
  heaviest: string
}

export interface ScanInput {
  mode: 'quick' | 'standard' | 'thorough'
  pacing: Pacing
  confirm: boolean
  discover: boolean
  autopilot: boolean
  checklist: boolean
  signedIn: boolean
  white: boolean
}

export function estimateWebScan(i: ScanInput): ScanEstimate {
  const base = i.mode === 'quick' ? 60 : i.mode === 'standard' ? 420 : 1400
  const parts: [string, number][] = [['the scan itself', base]]
  if (i.signedIn) parts.push(['the signed-in walk', 120])
  if (i.confirm) parts.push(['control confirmations', 260])
  if (i.discover) parts.push(['ffuf discovery', 465])
  if (i.autopilot) parts.push(['autopilot', 220])
  if (i.checklist) parts.push(['the checklist walk', 140])
  if (i.white) parts.push(['the code map', 80])
  const requests = parts.reduce((n, [, r]) => n + r, 0)
  const perMinute = i.pacing === 'gentle' ? 6 : 25
  const overhead = i.mode === 'quick' ? 1 : i.mode === 'standard' ? 4 : 15
  const minutes = Math.round(requests / perMinute + overhead + (i.confirm ? 6 : 0) + (i.autopilot ? 3 : 0))
  const heaviest = parts.sort((a, b) => b[1] - a[1])[0][0]
  return { requests, minutes, heaviest }
}

export interface ReviewEstimate {
  tokens: number
  /** Null when the reviewer is included in a plan or runs on this Mac. */
  costUsd: number | null
  minutes: number
  note: string
}

export interface ReviewInput {
  depth: 'quick' | 'standard' | 'deep'
  reviewer: string
}

export function estimateReview(i: ReviewInput): ReviewEstimate {
  const tokens = i.depth === 'quick' ? 40_000 : i.depth === 'standard' ? 160_000 : 480_000
  const scannerMinutes = i.depth === 'quick' ? 3 : i.depth === 'standard' ? 8 : 20
  if (i.reviewer === 'none') return { tokens: 0, costUsd: 0, minutes: scannerMinutes, note: 'Scanners only. No code leaves this Mac for an AI.' }
  if (i.reviewer === 'claude' || i.reviewer === 'codex' || i.reviewer === 'gemini') {
    return { tokens, costUsd: null, minutes: scannerMinutes + (i.depth === 'deep' ? 25 : 10), note: 'Included in your own plan. No API bill.' }
  }
  if (i.reviewer === 'claude-local' || i.reviewer === 'claude-free') {
    return { tokens, costUsd: 0, minutes: scannerMinutes + (i.depth === 'deep' ? 45 : 20), note: i.reviewer === 'claude-free' ? 'Free LLM API: free within your keys, slower.' : 'Your own model on this Mac: no cost, slower.' }
  }
  return { tokens, costUsd: Math.round((tokens / 1_000_000) * 3 * 100) / 100, minutes: scannerMinutes + (i.depth === 'deep' ? 40 : 15), note: 'An API model: about $3 per million tokens, so this is a rough bill.' }
}

export const minutesText = (m: number): string => (m < 60 ? `${m} min` : `${Math.floor(m / 60)} h ${m % 60 ? `${m % 60} min` : ''}`.trim())
export const tokensText = (t: number): string => (t >= 1_000_000 ? `${(t / 1_000_000).toFixed(1)}M` : `${Math.round(t / 1000)}k`)
