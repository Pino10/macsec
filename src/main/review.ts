/**
 * A code review session, start to finish:
 *  1. Get the code: your project in place (read-only), or a private copy of a repository.
 *  2. Work out the languages, then run every scanner that fits, one after another.
 *  3. Merge the findings (scanners overlap) and save them.
 *  4. The AI reviewer reads the code, checks the scanner findings and hunts for logic flaws.
 *  5. Delete the private copy, unless you asked to keep it for fixing.
 */
import { spawn, type ChildProcess } from 'child_process'
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'fs'
import { join } from 'path'
import type { Finding, ReviewRequest, SessionInfo, SessionStep } from '../shared/types'
import { createSession, discardCode, readSession, saveAiReport, saveFindings, saveSession, sessionCodeDir, sessionDir } from './sessions'
import { cloneInto } from './projects'
import { planScanners, projectStats, SKIP_DIRS, type ScannerRun } from './scanners/plan'
import { countBySeverity, mergeFindings } from './scanners/parse'
import { installTool, isInstalled, toolDef, toolEnv, toolPath } from './toolbox'
import { reviewPrompt, reviewWithClaude, reviewWithCodex, reviewWithModel, type AiResult } from './aireview'
import { log } from './logs'
import { beginOp, cancelOp, endOp, type Op } from './engine'
import { getSettings } from './settings'


type Running = Op

export function cancelSession(id: string): void {
  cancelOp(id)
}

function sourceLabel(req: ReviewRequest): { title: string; target: string } {
  const s = req.source
  if (s.kind === 'local') return { title: s.path.split('/').pop() ?? s.path, target: s.path }
  if (s.kind === 'github') return { title: s.repo, target: `github.com/${s.repo}` }
  const name = s.url.replace(/\.git$/, '').split('/').filter(Boolean)
  return { title: name.slice(-1)[0] ?? 'repository', target: s.url.replace(/^https:\/\/[^@/]+@/, 'https://') }
}

/** Source files for the AI to read, skipping dependencies and build output. */
export function sourceFiles(root: string, limit = 20000): string[] {
  const out: string[] = []
  const walk = (dir: string, rel: string, depth: number): void => {
    if (depth > 12 || out.length >= limit) return
    let names: string[]
    try {
      names = readdirSync(dir)
    } catch {
      return
    }
    for (const n of names) {
      const p = join(dir, n)
      const r = rel ? `${rel}/${n}` : n
      let st
      try {
        st = statSync(p)
      } catch {
        continue
      }
      if (st.isDirectory()) {
        if (!SKIP_DIRS.has(n) && !n.startsWith('.')) walk(p, r, depth + 1)
      } else if (/\.(php|js|jsx|mjs|cjs|ts|tsx|vue|svelte|py|go|rb|java|kt|cs|swift|rs|c|cc|cpp|h|scala|sol|ex|exs|dart|sh|sql|ya?ml|json|xml|tf|env\.example|blade\.php|twig|html?)$/i.test(n) && st.size < 400_000 && !/(\.min\.|lock\.json$|\.lock$)/.test(n)) {
        out.push(r)
      }
    }
  }
  walk(root, '', 0)
  return out
}

function runScanner(run: ScannerRun, root: string, rawDir: string, r: Running, args = run.args): Promise<string> {
  return new Promise((resolve, reject) => {
    mkdirSync(join(toolEnv().TMPDIR as string), { recursive: true })
    const child = spawn(toolPath(run.bin), args, { cwd: run.cwd ?? root, env: toolEnv(), stdio: ['ignore', 'pipe', 'pipe'] })
    r.children.add(child)
    let out = ''
    let err = ''
    child.stdout.on('data', (d) => {
      if (out.length < 200 * 1024 * 1024) out += d.toString()
    })
    child.stderr.on('data', (d) => {
      err += d.toString()
      if (err.length > 200_000) err = err.slice(-100_000)
    })
    const timer = setTimeout(() => child.kill('SIGTERM'), run.timeoutMs)
    child.on('error', (e) => {
      clearTimeout(timer)
      r.children.delete(child)
      reject(e)
    })
    child.on('exit', (code, signal) => {
      clearTimeout(timer)
      r.children.delete(child)
      writeFileSync(join(rawDir, `${run.id}.log`), err.slice(-50_000))
      if (r.cancelled) return reject(new Error('Cancelled.'))
      if (signal) return reject(new Error(`${run.tool} took too long and was stopped.`))
      const report = run.output && existsSync(run.output) ? readFileSync(run.output, 'utf8') : out
      if (!run.output) writeFileSync(join(rawDir, `${run.id}.jsonl`), out)
      // Several tools exit non-zero when they find something; what matters is the report.
      if (!report.trim() && code !== 0) return reject(new Error(err.trim().split('\n').filter(Boolean).slice(-2).join(' ') || `${run.tool} stopped (code ${code}).`))
      resolve(report)
    })
  })
}

export async function startReview(req: ReviewRequest): Promise<SessionInfo> {
  const { title, target } = sourceLabel(req)
  const info = createSession('code-review', title, target)
  info.reviewer = req.reviewer
  info.depth = req.depth
  saveSession(info)
  void runReview(info.id, req).catch((err) => log('error', `Review failed: ${(err as Error).message}`, info.id))
  return info
}

async function runReview(id: string, req: ReviewRequest): Promise<void> {
  const r: Running = beginOp(id)
  const info = readSession(id)
  const dir = sessionDir(id)
  const raw = join(dir, 'raw')
  const remote = req.source.kind !== 'local'
  const step = (s: SessionStep): SessionStep => {
    info.steps.push(s)
    saveSession(info)
    return s
  }
  const set = (s: SessionStep, patch: Partial<SessionStep>): void => {
    Object.assign(s, patch)
    saveSession(info)
  }
  let findings: Finding[] = []

  try {
    // 1. The code.
    const prep = step({ id: 'source', label: remote ? 'Downloading a private copy' : 'Reading the project', status: 'running' })
    let root: string
    const t0 = Date.now()
    if (req.source.kind === 'local') {
      root = req.source.path
      if (!existsSync(root)) throw new Error('That project folder is not there any more.')
    } else {
      root = sessionCodeDir(id)
      const url = req.source.kind === 'github' ? `https://github.com/${req.source.repo}.git` : req.source.url
      await cloneInto(url, root, req.depth === 'deep', (c) => r.children.add(c as unknown as ChildProcess))
    }
    info.codePath = root
    const stats = projectStats(root)
    info.languages = stats.languages
    info.files = stats.files
    set(prep, { status: 'done', ms: Date.now() - t0, detail: `${stats.files.toLocaleString()} files${stats.languages.length ? `: ${stats.languages.slice(0, 4).join(', ')}` : ''}` })
    log('info', `Reviewing ${info.title}: ${stats.files} files, ${stats.languages.join(', ') || 'no known languages'}`, id)

    // 2. Scanners.
    const runs = planScanners(root, stats, req.depth, raw).filter((s) => !req.skip?.includes(s.id))
    const steps = runs.map((s) => step({ id: s.id, label: s.label, status: 'waiting' }))
    for (const [i, run] of runs.entries()) {
      if (r.cancelled) break
      const st = steps[i]
      set(st, { status: 'running' })
      const t = Date.now()
      try {
        const def = toolDef(run.id)
        if (def && !isInstalled(def)) {
          set(st, { detail: `Installing ${def.name} into MacSec first` })
          await installTool(def.id, () => undefined)
        }
        let report: string
        try {
          report = await runScanner(run, root, raw, r)
        } catch (e) {
          if (!run.retryArgs || r.cancelled) throw e
          log('warn', `${run.tool} failed, trying again with its core rules: ${(e as Error).message}`, id)
          report = await runScanner(run, root, raw, r, run.retryArgs)
        }
        const found = run.parse(report, root)
        findings.push(...found)
        set(st, { status: 'done', findings: found.length, ms: Date.now() - t, detail: found.length ? `${found.length} found` : 'Nothing found' })
        log('info', `${run.tool}: ${found.length} findings`, id)
      } catch (e) {
        if (r.cancelled) break
        set(st, { status: 'failed', ms: Date.now() - t, detail: (e as Error).message.slice(0, 300) })
        log('error', `${run.tool}: ${(e as Error).message}`, id)
      }
      findings = mergeFindings(findings)
      info.counts = countBySeverity(findings)
      saveFindings(id, findings)
      saveSession(info)
    }

    // 3. The AI reviewer.
    if (req.reviewer !== 'none' && !r.cancelled) {
      const name = req.reviewer === 'claude' ? 'Claude Code' : req.reviewer === 'codex' ? 'Codex' : getSettings().llm.model || 'Your model'
      const ai = step({ id: 'ai', label: `${name} reviews the code and checks the findings`, status: 'running' })
      const t = Date.now()
      try {
        const prompt = reviewPrompt(info.title, req.focus, req.depth, findings.filter((f) => f.category !== 'dependency'))
        let res: AiResult
        const beat = (): void => set(ai, { detail: `Reading… ${Math.round((Date.now() - t) / 60000)} min` })
        if (req.reviewer === 'claude') res = await reviewWithClaude(root, prompt, req.depth, (c) => r.children.add(c), beat)
        else if (req.reviewer === 'codex') res = await reviewWithCodex(root, prompt, req.depth, join(raw, 'codex-last.md'), (c) => r.children.add(c), beat)
        else res = await reviewWithModel(root, info.title, sourceFiles(root), findings, req.focus, req.depth, (l) => set(ai, { detail: l }), () => r.cancelled)
        for (const f of findings) if (res.verdicts.has(f.id)) f.verdict = res.verdicts.get(f.id)
        findings = mergeFindings([...findings, ...res.findings])
        saveAiReport(id, res.report)
        const fp = [...res.verdicts.values()].filter((v) => v === 'false-positive').length
        set(ai, { status: 'done', ms: Date.now() - t, findings: res.findings.length, detail: `${res.findings.length} found${fp ? `, ${fp} scanner alarms judged false` : ''}` })
      } catch (e) {
        set(ai, { status: r.cancelled ? 'skipped' : 'failed', ms: Date.now() - t, detail: (e as Error).message.slice(0, 300) })
        log('error', `AI review: ${(e as Error).message}`, id)
      }
    }

    // False alarms the AI ruled out do not count towards the totals.
    info.counts = countBySeverity(findings.filter((f) => f.verdict !== 'false-positive'))
    saveFindings(id, findings)
    info.status = r.cancelled ? 'cancelled' : 'done'
  } catch (e) {
    info.status = r.cancelled ? 'cancelled' : 'failed'
    info.error = (e as Error).message
    log('error', info.error, id)
  } finally {
    endOp(id)
    info.finishedAt = new Date().toISOString()
    if (remote) {
      if (req.keepCode && info.status === 'done') info.codeKept = true
      else {
        discardCode(id)
        info.codeKept = false
        info.codePath = undefined
      }
    }
    info.steps = info.steps.map((s) => (s.status === 'running' || s.status === 'waiting' ? { ...s, status: 'skipped' } : s))
    saveSession(info)
    log('info', `Review ${info.status}: ${Object.entries(info.counts).filter(([, n]) => n).map(([k, n]) => `${n} ${k}`).join(', ') || 'nothing found'}`, id)
  }
}
