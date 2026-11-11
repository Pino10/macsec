/**
 * Recon as a MacSec session: the shared recon engine (seckit/recon.ts) with live progress, findings
 * you can filter and export, and an optional AI write-up with the recon skills. Read-only, and
 * domains not on this Mac need your confirmation.
 */
import { existsSync, readFileSync, writeFileSync } from 'fs'
import { join } from 'path'
import type { Finding, FindingCategory, ReconRequest, SessionInfo, SessionStep } from '../shared/types'
import { beginOp, endOp, SessionRun } from './engine'
import { createSession, listSessions, readSession, saveAiReport, sessionDir } from './sessions'
import { reconDelta, type ReconSnapshot } from './seckit/recondelta'
import { normalizeTarget, reconPrompt, runRecon, type ReconFinding, type ReconResult } from './seckit/recon'
import { summarizeWithAi } from './aisummary'
import { runTool } from './engine'
import { installTool, isInstalled, toolDef, toolPath } from './toolbox'
import { log } from './logs'

const CATEGORY: Record<ReconFinding['kind'], FindingCategory> = { secret: 'secret', exposure: 'web', sourcemap: 'web', headers: 'web', takeover: 'network', subdomain: 'recon', endpoint: 'recon', tech: 'recon', listing: 'web', errorpage: 'web', cors: 'web', methods: 'web', cdn: 'recon', version: 'recon' }

export function toFinding(f: ReconFinding): Finding {
  return { id: f.id, tool: f.kind === 'version' ? 'Version match' : f.kind === 'listing' ? 'Folder listing' : f.kind === 'errorpage' ? 'Error page' : f.kind === 'cors' ? 'Cross-origin check' : f.kind === 'cdn' ? 'CDN or firewall' : f.kind === 'methods' ? 'Methods' : f.kind === 'sourcemap' ? 'Source map check' : f.kind === 'takeover' ? 'Takeover check' : f.kind === 'secret' ? 'JavaScript keys' : f.kind === 'exposure' ? 'Exposed files' : 'Recon', category: CATEGORY[f.kind], severity: f.severity, title: f.title, url: f.url, description: f.description, fix: f.fix, confidence: f.confidence, proof: f.proof }
}

export const isLocalDomain = (d: string): boolean => /\.(test|localhost)$/.test(d) || d === 'localhost'

export function startRecon(req: ReconRequest): SessionInfo {
  const { domain } = normalizeTarget(req.target)
  if (!isLocalDomain(domain) && !req.authorized) throw new Error('Confirm that you own this domain or have written permission to assess it.')
  const info = createSession('recon', domain, req.target.trim())
  info.mode = req.depth === 'deep' ? 'thorough' : req.depth === 'passive' ? 'quick' : 'standard'
  info.reviewer = req.reviewer
  void run(info.id, req).catch((e) => log('error', `Recon: ${(e as Error).message}`, info.id))
  return info
}

async function run(id: string, req: ReconRequest): Promise<void> {
  const op = beginOp(id)
  const s = new SessionRun(id, op)
  const steps = new Map<string, SessionStep>()
  try {
    // subfinder is installed into MacSec the first time recon needs it.
    const sf = toolDef('subfinder')
    if (sf && !isInstalled(sf)) await installTool('subfinder', () => undefined).catch(() => undefined)
    const result: ReconResult = await runRecon(req.target, {
      depth: req.depth,
      userAgent: 'MacSec recon (read-only)',
      cancelled: () => s.cancelled,
      step: (sid, label, status, detail) => {
        let st = steps.get(sid)
        if (!st) {
          st = s.step(sid, label)
          steps.set(sid, st)
        }
        s.set(st, { label, status, detail, ...(status === 'running' ? { startedAt: new Date().toISOString() } : st.startedAt ? { ms: Date.now() - new Date(st.startedAt).getTime() } : {}) })
      },
      line: (t) => {
        const cur = [...steps.values()].find((x) => x.status === 'running')
        if (cur) s.line(cur, t)
      },
      tool: (n) => (n === 'subfinder' && sf && isInstalled(sf) ? toolPath('subfinder') : null),
      run: async (bin, args, timeoutMs) => runTool({ name: 'subfinder', bin, args, timeoutMs, absolute: true }, op, s.raw).catch(() => '')
    })
    writeFileSync(join(s.raw, 'recon.json'), JSON.stringify({ hosts: result.hosts, js: result.js, endpoints: result.endpoints, params: result.params, urls: result.urls.length, pages: result.pages ?? [] }))
    writeFileSync(join(s.raw, 'urls.txt'), result.urls.join('\n'))
    try {
      const prev = previousRecon(id, result.domain)
      if (prev) writeFileSync(join(s.raw, 'delta.json'), JSON.stringify(reconDelta(prev, { hosts: result.hosts.map((h) => h.host), endpoints: result.endpoints, findings: result.findings.map((f) => ({ id: f.id, title: f.title, severity: f.severity })) })))
    } catch {
      /* the comparison is a bonus: never let it stop a recon */
    }
    s.add(result.findings.map(toFinding))
    if (req.reviewer !== 'none' && !s.cancelled) {
      const ai = s.step('ai', 'AI: the attack surface and where to look first')
      await s.run(ai, async () => {
        const r = await summarizeWithAi(req.reviewer, reconPrompt(result), op, s.raw)
        for (const f of s.findings) {
          const d = r.details.get(f.id)
          if (d) {
            f.verdict = d.verdict
            f.aiNote = d.reason
          }
        }
        saveAiReport(id, r.report)
        return []
      })
    }
    s.finish()
  } catch (e) {
    s.finish((e as Error).message)
  } finally {
    endOp(id)
  }
}

/** The newest earlier recon of the same domain that finished and saved its results. */
function previousRecon(currentId: string, domain: string): ReconSnapshot | null {
  for (const info of listSessions()) {
    if (info.kind !== 'recon' || info.id === currentId || info.createdAt >= readSession(currentId).createdAt) continue
    const raw = join(sessionDir(info.id), 'raw', 'recon.json')
    const fnd = join(sessionDir(info.id), 'findings.json')
    if (!existsSync(raw) || !existsSync(fnd) || !info.target.toLowerCase().includes(domain.toLowerCase())) continue
    const r = JSON.parse(readFileSync(raw, 'utf8')) as { hosts?: { host: string }[]; endpoints?: string[] }
    const f = JSON.parse(readFileSync(fnd, 'utf8')) as { id: string; title: string; severity: string }[]
    return { session: info.id, at: info.createdAt, hosts: (r.hosts ?? []).map((h) => h.host), endpoints: r.endpoints ?? [], findings: f.map((x) => ({ id: x.id, title: x.title, severity: x.severity })) }
  }
  return null
}

export function reconData(id: string): unknown {
  const f = join(sessionDir(id), 'raw', 'recon.json')
  if (!existsSync(f)) return null
  const data = JSON.parse(readFileSync(f, 'utf8')) as Record<string, unknown>
  const d = join(sessionDir(id), 'raw', 'delta.json')
  if (existsSync(d)) data.delta = JSON.parse(readFileSync(d, 'utf8'))
  return data
}
