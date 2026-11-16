import type { SessionInfo } from '../shared/types'
import { latestPerTarget } from '../shared/latest'
import { postureOf, postureWord } from '../shared/posture'

export interface TrayModel {
  title: string
  lines: { label: string; session?: string }[]
}

/** What the menu says, worked out from the sessions. Pure, so it can be tested. */
export function trayModel(sessions: SessionInfo[]): TrayModel {
  const latest = latestPerTarget(sessions)
  const running = sessions.filter((s) => s.status === 'running')
  const lines: TrayModel['lines'] = []
  if (latest.length) {
    const score = postureOf(latest.map((s) => s.counts))
    lines.push({ label: `Posture: ${postureWord(score, true).toLowerCase()}, ${score} out of 100` })
  } else lines.push({ label: 'No tests yet' })
  for (const s of running.slice(0, 5)) {
    const step = s.steps.find((x) => x.status === 'running')?.label ?? 'Starting'
    lines.push({ label: `Testing ${s.title}: ${step}`.slice(0, 80), session: s.id })
  }
  const title = running.length ? ` ${running.length} running` : latest.length ? ` ${postureOf(latest.map((s) => s.counts))}` : ''
  return { title, lines }
}
