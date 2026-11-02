/**
 * Special audits, built from MacSec's other tests:
 *
 *   Full audit       a code review and a web scan of the same project, then one AI report that
 *                    connects them (a route the code leaves open and the page that shows it)
 *   Portfolio sweep  keys and vulnerable packages across every project in your www folder
 *   Change review    Claude Code's own /security-review of the changes on the current branch
 */
import { spawn } from 'child_process'
import { randomUUID } from 'crypto'
import { existsSync, readdirSync, readFileSync, statSync } from 'fs'
import { join } from 'path'
import type { AuditRequest, Finding, SessionInfo } from '../shared/types'
import { beginOp, endOp, runTool, SessionRun } from './engine'
import { createSession, readSession, saveAiReport, sessionDetail } from './sessions'
import { startReview } from './review'
import { startWebScan } from './webscan'
import { getSettings } from './settings'
import { parseGitleaks, parseOsv } from './scanners/parse'
import { addEvidence } from './evidence'
import { installTool, isInstalled, toolDef } from './toolbox'
import { summarizeWithAi } from './aisummary'
import { agentEnv, findCli } from './agents'
import { pluginArgs } from './skills'
import { log } from './logs'

export function startAudit(req: AuditRequest): SessionInfo {
  if (req.kind === 'portfolio') {
    const info = createSession('audit', 'Portfolio sweep', getSettings().wwwPath)
    void portfolio(info.id).catch((e) => log('error', `Portfolio sweep: ${(e as Error).message}`, info.id))
    return info
  }
  const name = req.path.split('/').pop() ?? req.path
  if (req.kind === 'changes') {
    if (!existsSync(join(req.path, '.git'))) throw new Error('Change review needs a Git project: it reviews the changes on the current branch.')
    const info = createSession('audit', `Changes in ${name}`, req.path)
    info.reviewer = 'claude'
    void changes(info.id, req.path).catch((e) => log('error', `Change review: ${(e as Error).message}`, info.id))
    return info
  }
  const info = createSession('audit', `Full audit of ${name}`, req.site)
  info.reviewer = req.reviewer
  info.depth = req.depth
  void full(info.id, req).catch((e) => log('error', `Full audit: ${(e as Error).message}`, info.id))
  return info
}

async function waitFor(id: string, cancelled: () => boolean): Promise<void> {
  while (!cancelled() && readSession(id).status === 'running') await new Promise((r) => setTimeout(r, 1500))
}

async function full(id: string, req: Extract<AuditRequest, { kind: 'full' }>): Promise<void> {
  const op = beginOp(id)
  const s = new SessionRun(id, op)
  const code = s.step('code', 'Code review of the project')
  const web = s.step('web', `Web scan of ${req.site}`)
  const ai = req.reviewer !== 'none' ? s.step('ai', 'AI: one report across the code and the live site') : null
  try {
    let codeId = ''
    let webId = ''
    await s.run(code, async (note) => {
      const r = startReview({ source: { kind: 'local', path: req.path }, reviewer: req.reviewer, depth: req.depth, focus: 'security', keepCode: false })
      codeId = (await r).id
      s.info.children = [codeId]
      note('Running as its own session')
      await waitFor(codeId, () => s.cancelled)
      const d = sessionDetail(codeId)
      if (d.aiReport) note(`${d.findings.length} findings, with an AI review`)
      return d.findings.map((f) => ({ ...f, tool: `Code: ${f.tool}` }))
    })
    await s.run(web, async (note) => {
      webId = startWebScan({ target: { kind: 'url', url: req.site }, mode: req.depth === 'deep' ? 'thorough' : req.depth === 'quick' ? 'quick' : 'standard', authorized: req.authorized, reviewer: 'none' }).id
      s.info.children = [codeId, webId].filter(Boolean)
      note('Running as its own session')
      await waitFor(webId, () => s.cancelled)
      return sessionDetail(webId).findings.map((f) => ({ ...f, tool: `Site: ${f.tool}` }))
    })
    if (ai)
      await s.run(ai, async () => {
        const codeReport = codeId ? sessionDetail(codeId).aiReport ?? '' : ''
        const context = `This is a full audit: the project's source code and the running site at ${req.site}. Connect them: a route the code leaves unprotected and the page the scan found, a key in the code and the same key in public JavaScript, a package flaw and the feature the site exposes. ${codeReport ? `\n\nThe code reviewer's report:\n${codeReport.slice(0, 30000)}` : ''}`
        const r = await summarizeWithAi(req.reviewer, (await import('./aisummary')).summaryPrompt('web', `${req.site} and its source code`, context, s.findings.filter((f) => f.severity !== 'info')), op, s.raw)
        saveAiReport(id, r.report)
        return []
      })
    s.finish()
  } catch (e) {
    s.finish((e as Error).message)
  } finally {
    endOp(id)
  }
}

async function portfolio(id: string): Promise<void> {
  const op = beginOp(id)
  const s = new SessionRun(id, op)
  const www = getSettings().wwwPath
  const projects = existsSync(www) ? readdirSync(www).filter((n) => !n.startsWith('.') && statSync(join(www, n)).isDirectory()) : []
  s.info.files = projects.length
  const prep = s.step('prepare', 'Get Gitleaks and OSV-Scanner ready')
  const steps = projects.map((p) => ({ p, st: s.step(`p-${p}`, p) }))
  try {
    await s.run(prep, async () => {
      for (const t of ['gitleaks', 'osv-scanner']) {
        const d = toolDef(t)
        if (d && !isInstalled(d)) await installTool(t, () => undefined)
      }
    })
    for (const { p, st } of steps) {
      await s.run(st, async (note) => {
        const root = join(www, p)
        const out: Finding[] = []
        const git = existsSync(join(root, '.git'))
        note(git ? 'Keys in files and history' : 'Keys in files')
        const gl = join(s.raw, `gitleaks-${p}.json`)
        await runTool({ name: `gitleaks-${p}`, bin: 'gitleaks', args: [git ? 'git' : 'dir', '.', '--report-format', 'json', '--report-path', gl, '--no-banner', '--redact', '--exit-code', '0', '--log-level', 'error'], cwd: root, timeoutMs: 15 * 60_000, output: gl }, op, s.raw)
          .then((t) => out.push(...parseGitleaks(t, root)))
          .catch(() => undefined)
        note('Vulnerable packages')
        const osv = join(s.raw, `osv-${p}.json`)
        await runTool({ name: `osv-${p}`, bin: 'osv-scanner', args: ['scan', 'source', '-r', '--format', 'json', '--output', osv, '.'], cwd: root, timeoutMs: 15 * 60_000, output: osv }, op, s.raw)
          .then((t) => out.push(...parseOsv(t, root)))
          .catch(() => undefined)
        // Evidence comes from each project; the file names then say which project it is.
        return addEvidence(root, out).map((f) => ({ ...f, file: f.file ? `${p}/${f.file}` : p, id: `${p}-${f.id}` }))
      })
    }
    s.finish()
  } catch (e) {
    s.finish((e as Error).message)
  } finally {
    endOp(id)
  }
}

/** Claude Code's built-in /security-review, as a normal session you can continue. */
async function changes(id: string, path: string): Promise<void> {
  const op = beginOp(id)
  const s = new SessionRun(id, op)
  const st = s.step('claude', 'Claude Code /security-review of the current branch')
  try {
    await s.run(st, async (note) => {
      const bin = findCli('claude')
      if (!bin) throw new Error('Claude Code’s command line tool is not installed. Set it up on Tools.')
      s.info.claudeSession = randomUUID()
      const args = ['-p', '/security-review', '--output-format', 'text', '--permission-mode', 'plan', '--allowedTools', 'Read,Grep,Glob,Skill,Bash(git diff:*),Bash(git status:*),Bash(git log:*),Bash(git show:*)', '--session-id', s.info.claudeSession, '--name', `MacSec change review: ${path.split('/').pop()}`, ...pluginArgs()]
      const text = await new Promise<string>((resolve, reject) => {
        const child = spawn(bin, args, { cwd: path, env: agentEnv(), stdio: ['ignore', 'pipe', 'pipe'] })
        op.children.add(child)
        let out = ''
        let err = ''
        child.stdout.on('data', (d) => {
          out += d.toString()
          note('Reading the changes…')
        })
        child.stderr.on('data', (d) => (err += d.toString()))
        child.on('error', reject)
        child.on('exit', (code) => {
          op.children.delete(child)
          if (out.trim()) resolve(out)
          else reject(new Error(`Claude Code stopped without a report (code ${code}). ${err.trim().split('\n').pop() ?? ''}`))
        })
      })
      saveAiReport(id, text)
      s.info.codePath = path
      return parseSecurityReview(text, path)
    })
    s.finish()
  } catch (e) {
    s.finish((e as Error).message)
  } finally {
    endOp(id)
  }
}

/** Reads the findings out of /security-review's write-up ("Vuln 1: ..." with a severity and a file). */
export function parseSecurityReview(text: string, root: string): Finding[] {
  const out: Finding[] = []
  const blocks = text.split(/\n(?=#+\s*Vuln\s*\d+|##?#?\s*\d+\.\s)/i)
  for (const b of blocks) {
    const title = /#+\s*(?:Vuln\s*\d+:?\s*)?(.+)/i.exec(b)?.[1]?.trim()
    const sev = /Severity\**:?\**\s*(Critical|High|Medium|Low)/i.exec(b)?.[1]?.toLowerCase() as Finding['severity'] | undefined
    if (!title || !sev) continue
    const where = /`([^`\s]+\.[A-Za-z]+):(\d+)`/.exec(b)
    out.push({ id: `sr-${out.length}`, tool: 'Claude Code /security-review', category: 'ai', severity: sev, title, file: where?.[1], line: where ? Number(where[2]) : undefined, description: b.replace(/^#+.*\n/, '').trim().slice(0, 1500), verdict: 'confirmed' })
  }
  return addEvidence(root, out)
}

export const readText = (p: string): string => (existsSync(p) ? readFileSync(p, 'utf8') : '')
