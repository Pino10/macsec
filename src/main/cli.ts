/**
 * The headless command line, so MacSec can gate a build instead of only being opened by a person.
 *
 *   MacSec --headless scan --path <folder> [--depth quick|standard|deep] [--fail-on high]
 *          [--baseline <file>] [--json] [--install-missing]
 *   MacSec --headless baseline --path <folder> [--file <file>]
 *   MacSec --headless bench
 *
 * Exit codes: 0 clean (or only known findings), 1 threshold reached, 2 error, 3 tools missing.
 * The review engine is imported lazily, so the argument rules can be tested without Electron.
 */
import { existsSync, statSync } from 'fs'
import { join, resolve } from 'path'
import type { ReviewDepth, Severity } from '../shared/types'
import { baselineOf, exitCodeFor, newFindings, readBaseline, worstOf, writeBaseline } from './baseline'

export interface CliOptions {
  command: 'scan' | 'baseline' | 'bench' | 'help'
  path?: string
  file?: string
  depth: ReviewDepth
  failOn: Severity | 'none'
  json: boolean
  installMissing: boolean
  baseline: boolean
}

const DEPTHS: ReviewDepth[] = ['quick', 'standard', 'deep']
const SEVS: (Severity | 'none')[] = ['critical', 'high', 'medium', 'low', 'info', 'none']

export const HELP = `MacSec, from the command line

  MacSec --headless scan --path <folder> [options]
  MacSec --headless baseline --path <folder> [--file <file>]
  MacSec --headless bench

Options:
  --path <folder>      the project to review (required for scan and baseline)
  --depth <level>      quick, standard (default) or deep
  --fail-on <level>    critical, high (default), medium, low, none
  --baseline <file>    the baseline file (default: <folder>/.macsec-baseline.json)
  --no-baseline        ignore the baseline
  --json               print the result as JSON
  --install-missing    install the scanners MacSec needs before the review

Exit codes: 0 clean, 1 threshold reached, 2 error, 3 scanners missing.`

export function parseCli(argv: string[]): CliOptions | { error: string } {
  const args = argv[0] === '--headless' ? argv.slice(1) : argv
  const help: CliOptions = { command: 'help', depth: 'quick', failOn: 'none', json: false, installMissing: false, baseline: false }
  if (args[0] === '--help' || args[0] === '-h' || !args.length) return help
  const command = (args[0] ?? 'help') as CliOptions['command']
  if (!['scan', 'baseline', 'bench', 'help'].includes(command)) return { error: `Unknown command "${args[0]}". Try --help.` }
  if (command === 'bench') return { command, depth: 'quick', failOn: 'none', json: false, installMissing: false, baseline: false }
  const out: CliOptions = { command, depth: 'standard', failOn: 'high', json: false, installMissing: false, baseline: true }
  for (let i = 1; i < args.length; i++) {
    const a = args[i]
    const value = (): string | null => (i + 1 < args.length && !args[i + 1].startsWith('--') ? args[++i] : null)
    if (a === '--path' || a === '--file') {
      const v = value()
      if (!v) return { error: `${a} needs a folder or file.` }
      out.path = resolve(v)
    } else if (a === '--depth') {
      const v = value()
      if (!v || !DEPTHS.includes(v as ReviewDepth)) return { error: '--depth takes quick, standard or deep.' }
      out.depth = v as ReviewDepth
    } else if (a === '--fail-on') {
      const v = value()
      if (!v || !SEVS.includes(v as Severity | 'none')) return { error: '--fail-on takes critical, high, medium, low, info or none.' }
      out.failOn = v as Severity | 'none'
    } else if (a === '--baseline') {
      const v = value()
      if (!v) return { error: '--baseline needs a file.' }
      out.file = resolve(v)
      out.baseline = true
    } else if (a === '--no-baseline') out.baseline = false
    else if (a === '--json') out.json = true
    else if (a === '--install-missing') out.installMissing = true
    else if (a === '--help' || a === '-h') return help
    else return { error: `Unknown option "${a}". Try --help.` }
  }
  if ((out.command === 'scan' || out.command === 'baseline') && !out.path) return { error: '--path is required.' }
  if (out.path && (!existsSync(out.path) || (out.command === 'scan' && !statSync(out.path).isDirectory()))) return { error: `"${out.path}" is not a folder MacSec can read.` }
  return out
}

const log = (s: string): void => void process.stdout.write(`${s}\n`)

/** Scores for the built-in checks, printed as a table. No network, no tools. */
async function bench(): Promise<number> {
  const { runBenchmarks } = await import('./benchmarks')
  const rows = runBenchmarks()
  log('check                        precision  recall')
  for (const r of rows) log(`${r.name.padEnd(28)} ${String(r.precision).padStart(9)}  ${String(r.recall).padStart(6)}`)
  const bad = rows.filter((r) => r.precision < 0.8 || r.recall < 0.8)
  log(bad.length ? `\n${bad.length} check(s) below 0.8` : '\nEvery check is at 0.8 or better.')
  return bad.length ? 1 : 0
}

export async function runCli(argv: string[]): Promise<number> {
  const parsed = parseCli(argv)
  if ('error' in parsed) {
    log(`MacSec: ${parsed.error}`)
    return 2
  }
  const opts = parsed
  if (opts.command === 'help') {
    log(HELP)
    return 0
  }
  if (opts.command === 'bench') return bench()

  const dir = opts.path as string
  const { startReview } = await import('./review')
  const { finishEvents } = await import('./engine')
  const { sessionDetail, listSessions } = await import('./sessions')
  const { installTool, isInstalled, toolDef } = await import('./toolbox')

  // The scans a review always runs need these. Say so plainly instead of failing deep inside.
  const needed = ['semgrep', 'gitleaks', 'osv-scanner']
  const missing = needed.filter((id) => {
    const d = toolDef(id)
    return d ? !isInstalled(d) : false
  })
  if (missing.length && !opts.installMissing) {
    log(`MacSec: these scanners are not installed: ${missing.join(', ')}. Open MacSec and install them, or add --install-missing.`)
    return 3
  }
  if (missing.length) {
    for (const id of missing) {
      log(`Installing ${id}…`)
      await installTool(id, (p, l) => {
        if (l) log(`${l}${p === null ? '' : ` ${p}%`}`)
      })
    }
  }

  if (opts.command === 'baseline') {
    const latest = listSessions().find((s) => s.kind === 'code-review' && s.status === 'done' && s.target === dir)
    if (!latest) {
      log(`MacSec: no finished review of ${dir}. Run scan first.`)
      return 2
    }
    const d = sessionDetail(latest.id)
    const file = opts.file ?? join(dir, '.macsec-baseline.json')
    writeBaseline(file, baselineOf(d.findings, dir))
    log(`Wrote ${d.findings.filter((f) => f.severity !== 'info' && f.verdict !== 'false-positive').length} findings to ${file}`)
    return 0
  }

  const info = await startReview({ source: { kind: 'local', path: dir }, depth: opts.depth, reviewer: 'none', focus: 'security', keepCode: false })
  log(`Review ${info.id} started (${opts.depth}).`)
  const done = await new Promise<{ status: string; error?: string }>((resolve) => {
    const onDone = (s: { id: string; status: string; error?: string }): void => {
      if (s.id !== info.id) return
      finishEvents.off('finished', onDone)
      resolve(s)
    }
    finishEvents.on('finished', onDone)
    // A session may finish between the call and this line.
    const finished = listSessions().find((s) => s.id === info.id)
    if (finished && finished.status !== 'running') {
      finishEvents.off('finished', onDone)
      resolve(finished)
    }
  })
  const detail = sessionDetail(info.id)
  const baselinePath = opts.file ?? join(dir, '.macsec-baseline.json')
  const baseline = opts.baseline ? readBaseline(baselinePath) : null
  const fresh = newFindings(detail.findings, baseline)
  const worst = worstOf(fresh)
  const code = done.status === 'failed' ? 2 : exitCodeFor(fresh, opts.failOn)
  if (opts.json) {
    log(
      JSON.stringify(
        {
          session: info.id,
          status: done.status,
          depth: opts.depth,
          worst,
          counts: detail.findings.reduce<Record<string, number>>((m, f) => ((m[f.severity] = (m[f.severity] ?? 0) + 1), m), {}),
          newFindings: fresh.map((f) => ({ title: f.title, severity: f.severity, file: f.file, url: f.url, checkId: f.checkId })),
          baselined: baseline ? baseline.findings.length : 0,
          failOn: opts.failOn,
          exitCode: code
        },
        null,
        2
      )
    )
  } else {
    log(`\n${done.status === 'failed' ? `Review failed: ${done.error ?? 'see the log'}` : `Review finished: ${detail.findings.length} findings`}`)
    log(`New since the baseline: ${fresh.length}${worst ? ` (worst ${worst})` : ''}. Fail on: ${opts.failOn}.`)
    for (const f of fresh.slice(0, 25)) log(`  [${f.severity}] ${f.title}${f.file ? ` : ${f.file}` : f.url ? ` : ${f.url}` : ''}`)
    if (fresh.length > 25) log(`  … and ${fresh.length - 25} more`)
    log(code === 0 ? 'OK' : 'FAILED')
  }
  return code
}
