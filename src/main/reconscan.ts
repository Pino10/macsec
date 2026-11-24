/**
 * Recon as a MacSec session: the shared recon engine (seckit/recon.ts) with live progress, findings
 * you can filter and export, and an optional AI write-up with the recon skills. Read-only, and
 * domains not on this Mac need your confirmation.
 */
import { deepHosts } from './recondeep'
import { existsSync, readFileSync, writeFileSync } from 'fs'
import { join } from 'path'
import type { Finding, FindingCategory, ReconRequest, SessionInfo, SessionStep } from '../shared/types'
import { crawlJs } from './jsdeep'
import { beginOp, endOp, SessionRun } from './engine'
import { createSession, listSessions, readSession, saveAiReport, sessionDir } from './sessions'
import { reconDelta, type ReconSnapshot } from './seckit/recondelta'
import { inScope, interestingUrls, normalizeTarget, paramsOf, reconPrompt, runRecon, type ReconFinding, type ReconResult } from './seckit/recon'
import { summarizeWithAi } from './aisummary'
import { runTool } from './engine'
import { installTool, isInstalled, toolDef, toolPath } from './toolbox'
import { log } from './logs'
import { fid } from './scanners/parse'

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
    // gau: URLs the internet already knows, from other archives. Passive: it never touches the target.
    if (!s.cancelled) {
      const gauDef = toolDef('gau')
      if (gauDef && !isInstalled(gauDef)) await installTool('gau', () => undefined).catch(() => undefined)
      if (gauDef && isInstalled(gauDef)) {
        const st = s.step('gau', 'URLs the internet already knows (gau)')
        await s.run(st, async (note, line) => {
          const out = await runTool({ name: 'gau', bin: 'gau', args: ['--threads', '5', '--timeout', '20', '--subs', '--json', result.domain], timeoutMs: 6 * 60_000 }, op, s.raw, line).catch((e) => {
            note(`gau did not run: ${(e as Error).message}`)
            return ''
          })
          const known = new Set(result.urls)
          const fresh = parseGau(out, result.domain).filter((u) => !known.has(u))
          result.urls = [...result.urls, ...fresh].slice(0, 20000)
          result.params = paramsOf(result.urls)
          const worth = interestingUrls(fresh).slice(0, 40)
          note(`${fresh.length} new URLs from the archives, ${worth.length} worth a look`)
          return worth.map((u) => {
            const p = new URL(u)
            return {
              id: fid('gau', u),
              tool: 'gau',
              category: 'recon' as const,
              severity: 'info' as const,
              confidence: 'confirmed' as const,
              title: `Archived: ${p.pathname.slice(0, 90)}`,
              url: u,
              file: u,
              description: 'Seen in a public archive (Wayback, Common Crawl and others). Check whether it still answers, and whether it should be public.'
            }
          })
        })
      }
    }
    writeFileSync(join(s.raw, 'recon.json'), JSON.stringify({ hosts: result.hosts, js: result.js, endpoints: result.endpoints, params: result.params, urls: result.urls.length, pages: result.pages ?? [] }))
    writeFileSync(join(s.raw, 'urls.txt'), result.urls.join('\n'))
    try {
      const prev = previousRecon(id, result.domain)
      if (prev) writeFileSync(join(s.raw, 'delta.json'), JSON.stringify(reconDelta(prev, { hosts: result.hosts.map((h) => h.host), endpoints: result.endpoints, findings: result.findings.map((f) => ({ id: f.id, title: f.title, severity: f.severity })) })))
    } catch {
      /* the comparison is a bonus: never let it stop a recon */
    }
    s.add(result.findings.map(toFinding))
    // The deeper JavaScript pass: routes, hidden chunks, rebuilt source and risks. Not for passive recon, which never touches the target.
    if (req.depth !== 'passive' && result.js.length && !s.cancelled) {
      const st = s.step('jsdeep', 'JavaScript analysis: routes, hidden chunks, source maps, risks')
      await s.run(st, async (note) => {
        const r = await crawlJs({ scripts: result.js.map((j) => j.url), allowed: (u) => { try { return inScope(new URL(u).hostname, result.domain) } catch { return false } }, cancelled: () => s.cancelled, note, sourceDir: join(s.raw, 'sources'), cap: req.depth === 'deep' ? 250 : 120 })
        writeFileSync(join(s.raw, 'js-map.json'), JSON.stringify({ scripts: r.scripts, endpoints: r.endpoints, routes: r.routes, graphql: r.graphql, envVars: r.envVars, hosts: r.hosts, refs: r.refs }, null, 1))
        note(`${r.scripts.length} scripts (${r.chunksFound} found through chunk lists), ${r.routes.length} routes, ${r.graphql.length} GraphQL operations, ${r.scripts.filter((x) => x.sourceMap?.recovered).length} source maps rebuilt`)
        // Source maps the first pass already reported are not reported twice.
        const known = new Set(s.findings.map((x) => x.url))
        return r.findings.filter((x) => !(x.title.startsWith('Source map public') && known.has(x.url)))
      })
    }
    // The deeper pass over the live hosts: headers, certificates, firewall, versions to live CVEs, DevOps tools, takeovers.
    if (req.depth !== 'passive' && result.hosts.some((h) => h.live) && !s.cancelled) {
      const st = s.step('hostsdeep', 'Each live host: headers, certificate, firewall, versions and DevOps tools')
      await s.run(st, async (note) => {
        const live = result.hosts.filter((h) => h.live).map((h) => ({ host: h.host, url: h.live!.url, status: h.live!.status, cname: h.cname }))
        return deepHosts(live, { cancelled: () => s.cancelled, paused: () => op.paused, note, maxHosts: req.depth === 'deep' ? 60 : 25 })
      })
    }
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
  const jm = join(sessionDir(id), 'raw', 'js-map.json')
  if (!existsSync(f) && !existsSync(jm)) return null
  const data = (existsSync(f) ? JSON.parse(readFileSync(f, 'utf8')) : { hosts: [], js: [], endpoints: [], params: [], urls: 0, pages: [] }) as Record<string, unknown>
  if (existsSync(jm)) data.jsmap = { ...(JSON.parse(readFileSync(jm, 'utf8')) as object), sources: existsSync(join(sessionDir(id), 'raw', 'sources')) }
  const d = join(sessionDir(id), 'raw', 'delta.json')
  if (existsSync(d)) data.delta = JSON.parse(readFileSync(d, 'utf8'))
  return data
}

/** gau's answer: one JSON object per line, or plain URLs. Same domain only, de-duplicated, capped. */
export function parseGau(text: string, domain: string): string[] {
  const out = new Set<string>()
  for (const line of text.split('\n')) {
    const raw = line.trim()
    if (!raw) continue
    let url = raw
    if (raw.startsWith('{')) {
      try {
        url = String((JSON.parse(raw) as { url?: string }).url ?? '')
      } catch {
        continue
      }
    }
    try {
      const p = new URL(url)
      if (!/^https?:$/.test(p.protocol) || !inScope(p.hostname, domain)) continue
      p.hash = ''
      out.add(p.href)
    } catch {
      // Not an address.
    }
    if (out.size >= 20000) break
  }
  return [...out]
}
