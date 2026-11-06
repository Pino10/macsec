/**
 * Deep audit for MacSec: Cloudflare's security audit and Anthropic's security review, run through
 * Claude Code on the AI the person picked. The shared parts (the command, the checks, reading the
 * results) are in seckit/deepaudit.ts; this file connects them to a MacSec code review session.
 */
import { randomUUID } from 'crypto'
import { existsSync, mkdirSync, readFileSync } from 'fs'
import { join } from 'path'
import type { ChildProcess } from 'child_process'
import type { DeepEngine, Finding } from '../shared/types'
import { findCli } from './agents'
import { runCli, type AiResult } from './aireview'
import { dirs } from './paths'
import { fid } from './scanners/parse'
import { ensureLmContext } from './seckit/lmstudio'
import { changedFiles, checkCitations, deepClaudeArgs, deepFindingsFromJson, deepMarkdown, deepPlan, deepPrompt, engineList, readDeepResults, treeSignature, type DeepFinding, type DeepPlanLine, type DeepResult, type DeepReviewer } from './seckit/deepaudit'
import { explainFailure, localModelEnv, type LocalModel } from './seckit/reviewers'
import { installPack, packFile, packPluginDir, packState } from './seckit/skillpacks'

export const packsRoot = (): string => join(dirs.tools(), 'skill-packs')
const ENGINE_PACK = { cloudflare: 'cloudflare', anthropic: 'anthropic' } as const
export const ENGINE_NAME = { cloudflare: 'Cloudflare security audit', anthropic: 'Claude Code security review' } as const

/** What will happen, for the panel shown before a deep audit starts. */
export function deepPlanFor(o: { engine: DeepEngine; reviewer: DeepReviewer; local?: LocalModel }): DeepPlanLine[] {
  const packs = engineList(o.engine).map((e) => ({ id: ENGINE_PACK[e], name: ENGINE_PACK[e], commit: packState(packsRoot(), ENGINE_PACK[e]).commit }))
  return deepPlan({ engine: o.engine, reviewer: o.reviewer, model: o.local?.model, packs, app: 'MacSec', outFolder: '~/MacSec/sessions/<session>/deep-audit' })
}

const minutes = (engine: 'cloudflare' | 'anthropic', reviewer: string): number => (engine === 'cloudflare' ? 360 : 60) * (reviewer === 'claude-local' || reviewer === 'claude-free' ? 1.5 : 1)

const SEVERITY_TITLE = (f: DeepFinding): string => (f.state === 'confirmed' ? f.title : `Needs checking: ${f.title}`)

function toFinding(f: DeepFinding): Finding {
  return {
    id: fid('Deep audit', f.file, f.line, f.title),
    tool: 'Deep audit',
    category: 'ai',
    severity: f.severity,
    title: SEVERITY_TITLE(f),
    file: f.file,
    line: f.line,
    description: [f.description, f.note].filter(Boolean).join(' '),
    fix: f.fix,
    why: f.why,
    impact: f.impact,
    fixCode: f.fixCode,
    verify: f.verify,
    verdict: f.state === 'confirmed' ? 'confirmed' : 'unreviewed'
  }
}

function dedupe(list: DeepFinding[]): DeepFinding[] {
  const key = (f: DeepFinding): string => `${f.file ?? ''}:${f.line ?? ''}:${f.title.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim()}`
  const out: DeepFinding[] = []
  for (const f of list) {
    const at = out.findIndex((g) => key(g) === key(f))
    if (at < 0) out.push(f)
    else if (out[at].state !== 'confirmed' && f.state === 'confirmed') out[at] = f
  }
  return out
}

/** The deep audit step of a review session: returns what the AI step normally returns. */
export async function deepAuditStep(o: {
  workDir: string
  root: string
  name: string
  engine: DeepEngine
  reviewer: 'claude' | 'claude-local' | 'claude-free'
  local?: LocalModel
  onChild: (c: ChildProcess) => void
  onStatus: (text: string) => void
}): Promise<AiResult & { problems: string[]; counts: DeepResult['counts']; session: string }> {
  const bin = findCli('claude')
  if (!bin) throw new Error('Claude Code’s command line tool is not installed (the Claude desktop app is separate). Install it on the Tools page.')
  const engines = engineList(o.engine)
  for (const e of engines) {
    if (!packPluginDir(packsRoot(), ENGINE_PACK[e])) {
      o.onStatus(`Getting the ${ENGINE_NAME[e]} skills`)
      await installPack(packsRoot(), ENGINE_PACK[e])
    }
  }
  if (o.reviewer === 'claude-local' && o.local) {
    const ctx = await ensureLmContext(o.local.baseUrl, o.local.model, o.local.token)
    if (!ctx.ok) throw new Error(ctx.note)
  }
  const before = treeSignature(o.root)
  const results: DeepResult[] = []
  let session = ''
  for (const [i, e] of engines.entries()) {
    const outDir = join(o.workDir, e)
    mkdirSync(outDir, { recursive: true, mode: 0o700 })
    const run = deepClaudeArgs({
      prompt: deepPrompt({ engine: e, name: o.name, root: o.root, outDir }),
      outDir,
      root: o.root,
      plugins: [packPluginDir(packsRoot(), ENGINE_PACK[e])!],
      session: { id: randomUUID(), name: `MacSec deep audit: ${o.name}` },
      model: o.reviewer === 'claude' ? undefined : o.local?.model,
      localEnv: o.reviewer === 'claude' || !o.local ? undefined : localModelEnv(o.local)
    })
    session = run.args[run.args.indexOf('--session-id') + 1]
    const label = `${ENGINE_NAME[e]}${engines.length > 1 ? ` (${i + 1} of ${engines.length})` : ''}`
    const t0 = Date.now()
    o.onStatus(`${label} is working`)
    const r = await runCli(bin, run.args, run.cwd, o.onChild, minutes(e, o.reviewer) * 60_000, () => o.onStatus(`${label}: working… ${Math.round((Date.now() - t0) / 60000)} min`), run.env)
    const wrote = existsSync(join(outDir, 'findings.json')) || existsSync(join(outDir, 'REPORT.md'))
    if (!wrote && (r.code !== 0 || !r.out.trim())) {
      if (/log ?in|auth|credential|api key/i.test(r.err)) throw new Error('Claude Code is not signed in. Run claude once in Terminal to sign in.')
      throw new Error(explainFailure(o.reviewer, r.err))
    }
    let res = readDeepResults(outDir, o.root, e === 'cloudflare' ? packFile(packsRoot(), 'cloudflare', 'skills', 'security-audit', 'report-schema.json') : null)
    if (!res.fromFiles) {
      const saved = join(outDir, 'REPORT.md')
      const fromText = checkCitations(o.root, deepFindingsFromJson(r.out || (existsSync(saved) ? readFileSync(saved, 'utf8') : '')))
      res = { ...res, findings: fromText.findings, problems: [...res.problems, ...fromText.problems], counts: { confirmed: fromText.findings.filter((f) => f.state === 'confirmed').length, needsChecking: fromText.findings.filter((f) => f.state === 'needs-checking').length, rejected: 0 } }
    }
    if (!res.report) res.report = r.out.replace(/```json[\s\S]*?```/g, '').trim()
    results.push(res)
  }
  const changed = changedFiles(before, treeSignature(o.root))
  const warning = changed.length ? `These files changed while the audit ran: ${changed.slice(0, 8).join(', ')}${changed.length > 8 ? `, and ${changed.length - 8} more` : ''}. The audit is not allowed to change your project, so if you did not edit them yourself, treat this audit as untrusted.` : null
  const findings = dedupe(results.flatMap((r) => r.findings))
  const counts = { confirmed: findings.filter((f) => f.state === 'confirmed').length, needsChecking: findings.filter((f) => f.state !== 'confirmed').length, rejected: results.reduce((n, r) => n + r.counts.rejected, 0) }
  const problems = [...results.flatMap((r) => r.problems), ...(warning ? [warning] : [])]
  const merged: DeepResult = { report: results.map((r) => r.report).filter(Boolean).join('\n\n'), findings, counts, problems, fromFiles: results.some((r) => r.fromFiles) }
  const report = `${deepMarkdown(merged, o.name, engines.map((e) => ENGINE_NAME[e]))}${merged.report ? `\n\n## The audit’s own report\n${merged.report}` : ''}`
  return { report, findings: findings.map(toFinding), verdicts: new Map(), details: new Map(), problems, counts, session }
}
