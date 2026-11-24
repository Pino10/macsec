/**
 * The keystone: a controlled proof comes back to the finding it was built from.
 *
 * A finding says "possible" until something proves it. When a run proves a step that names a
 * finding (`step.from`), that finding becomes confirmed, wears the proof, and carries the
 * engagement that allowed the run. Without this, the app proves things and forgets them.
 */
import type { ImpactPlan, ImpactRun } from '../../shared/impact'
import type { Finding } from '../../shared/types'

export interface LinkResult {
  findings: Finding[]
  linked: string[]
}

export function attachProof(findings: Finding[], run: ImpactRun, plan: ImpactPlan, engagementRef: string): LinkResult {
  const linked: string[] = []
  const byId = new Map(run.steps.map((s) => [s.step, s]))
  const out = findings.map((f) => {
    const step = plan.steps.find((s) => s.from === f.id)
    if (!step) return f
    const result = byId.get(step.id)
    if (!result || result.status !== 'proven') return f
    linked.push(f.id)
    const shows = (result.evidence?.shows ?? []).slice(0, 8)
    return {
      ...f,
      confidence: 'confirmed' as const,
      // The proof the finding now wears: the request that was really sent, and what it showed.
      proof: result.evidence
        ? {
            request: `${result.evidence.method} ${result.evidence.url}`,
            reproduce: `MacSec controlled proof run ${run.id}, step ${step.id}`,
            status: result.evidence.status,
            contentType: result.evidence.contentType,
            bytes: result.evidence.bytes,
            sha256: result.evidence.sha256,
            at: result.evidence.at,
            shows
          }
        : f.proof,
      controlled: { runId: run.id, engagementRef, at: run.finishedAt, shows },
      aiNote: `${f.aiNote ? `${f.aiNote} ` : ''}Proven by a controlled proof (run ${run.id}, engagement ${engagementRef}).`
    }
  })
  return { findings: out, linked }
}
