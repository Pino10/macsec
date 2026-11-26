/**
 * Patch generation, in a scratch copy and never in the project until a person types the confirmation.
 *
 * propose: copy the project, let the chosen AI edit only the copy, diff it, run the project's own
 * tests, and never touch the project. apply: only with the exact phrase and only when the tests
 * passed; a reverse copy is kept for one-click rollback. Nothing here runs a shell on user text.
 */
import { execFile } from 'child_process'
import { cpSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'fs'
import { join } from 'path'
import { randomUUID } from 'crypto'
import type { Finding, PatchRecord, SessionDetail } from '../shared/types'
import { findCli } from './agents'
import { runCli } from './aireview'
import { readSession, sessionDetail } from './sessions'
import { dirs } from './paths'
import { gitBin } from './git'

const SKIP = new Set(['node_modules', 'vendor', '.git', 'dist', 'build', '.next', 'target', 'Pods', 'DerivedData', '.venv', 'venv', '__pycache__', '.cache', 'coverage'])


function run(bin: string, args: string[], cwd: string, timeoutMs: number): Promise<{ code: number; out: string; err: string }> {
  return new Promise((resolve) => {
    execFile(bin, args, { cwd, timeout: timeoutMs, maxBuffer: 16 * 1024 * 1024 }, (e, out, err) => resolve({ code: e ? 1 : 0, out: out?.toString() ?? '', err: err?.toString() ?? '' }))
  })
}

/** Copy the project without the folders that make a copy slow; dependencies are linked back in. */
export function copyProject(source: string, dest: string): void {
  mkdirSync(dest, { recursive: true, mode: 0o700 })
  cpSync(source, dest, { recursive: true, filter: (src) => !SKIP.has(src.split('/').pop() ?? '') })
  for (const dir of ['node_modules', 'vendor']) {
    const from = join(source, dir)
    if (existsSync(from) && !existsSync(join(dest, dir))) {
      try {
        symlinkSync(from, join(dest, dir), 'dir')
      } catch {
        // A link is a convenience for tests; the patch can still be reviewed without it.
      }
    }
  }
}

/** The project's own test command, if it has one. No guessing. */
export function testCommand(root: string): { bin: string; args: string[] } | null {
  try {
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { scripts?: Record<string, string> }
    if (pkg.scripts?.test) return { bin: 'npm', args: ['test', '--silent'] }
  } catch {
    // Not a Node project.
  }
  try {
    const c = JSON.parse(readFileSync(join(root, 'composer.json'), 'utf8')) as { scripts?: Record<string, string> }
    if (c.scripts?.test) return { bin: 'composer', args: ['test'] }
  } catch {
    // Not a Composer project.
  }
  if (existsSync(join(root, 'pytest.ini')) || existsSync(join(root, 'pyproject.toml')) || readdirSync(root).some((f) => f.endsWith('_test.py'))) return { bin: 'pytest', args: ['-q'] }
  return null
}

const prompt = (f: Finding): string => `You are fixing exactly one security finding in a scratch copy of a project. Change only what the finding needs.

FINDING: ${f.title}
SEVERITY: ${f.severity}
WHERE: ${f.file ?? f.url ?? 'not said'}${f.line ? `:${f.line}` : ''}
DESCRIPTION: ${(f.description ?? '').slice(0, 2000)}
SUGGESTED FIX: ${(f.fix ?? 'not given').slice(0, 2000)}

Rules:
- Read the relevant files first.
- Make the smallest change that fixes this finding without changing behaviour otherwise.
- Do not touch tests, CI files, package manifests or anything outside the project.
- Do not add dependencies, run network commands, or write scripts that execute on load.
- If the finding is a false positive or the fix would be unsafe, change nothing and explain why in one sentence.
Reply at the end with: SUMMARY: one sentence.`

const SETTINGS = (dir: string): string => {
  const file = join(dir, 'settings.json')
  const deny = [
    'Read(//**/.ssh/**)', 'Read(//**/.aws/**)', 'Read(//**/.gnupg/**)', 'Read(//**/.kube/**)', 'Read(//**/.docker/**)',
    'Read(//**/Library/Keychains/**)', 'Read(//**/.netrc)', 'Read(//**/.npmrc)', 'Read(//**/.git-credentials)', 'Read(//**/id_rsa)', 'Read(//**/id_ed25519)'
  ]
  try {
    writeFileSync(file, JSON.stringify({ permissions: { deny } }, null, 2))
    return file
  } catch {
    return ''
  }
}

export interface PatchDeps {
  editor?: (scratch: string, f: Finding) => Promise<void>
  testRunner?: (bin: string, args: string[], cwd: string) => Promise<{ code: number; out: string; err: string }>
}

export async function proposePatch(sessionId: string, findingId: string, deps: PatchDeps = {}): Promise<PatchRecord> {
  const s = readSession(sessionId)
  const d: SessionDetail = sessionDetail(sessionId)
  const f = d.findings.find((x) => x.id === findingId)
  if (!f) throw new Error('That finding is not in this result.')
  if (!s.codePath) throw new Error('The code is no longer on this Mac. Keep the code next time, or review a local project.')
  const id = `patch-${randomUUID().slice(0, 8)}`
  const dir = join(dirs.root(), 'patches', id)
  const scratch = join(dir, 'work')
  cpSync(s.codePath, scratch, { recursive: true, filter: (src) => !SKIP.has(src.split('/').pop() ?? '') })
  for (const name of ['node_modules', 'vendor']) {
    const from = join(s.codePath, name)
    if (existsSync(from) && !existsSync(join(scratch, name))) {
      try {
        symlinkSync(from, join(scratch, name), 'dir')
      } catch {
        // Optional for tests.
      }
    }
  }
  const g = gitBin()
  await run(g, ['init', '-q'], scratch, 20_000)
  await run(g, ['add', '-A'], scratch, 60_000)
  await run(g, ['-c', 'user.email=macsec@local', '-c', 'user.name=MacSec', 'commit', '-qm', 'baseline'], scratch, 120_000)

  const before = (await run(g, ['status', '--porcelain'], scratch, 20_000)).out
  if (deps.editor) await deps.editor(scratch, f)
  else {
    const bin = findCli('claude')
    if (!bin) throw new Error('Claude Code is not installed. Set it up on Tools, or apply a patch by hand.')
    const settings = SETTINGS(dir)
    const r = await runCli(bin, ['-p', prompt(f), '--permission-mode', 'acceptEdits', '--allowedTools', 'Read,Edit,Write', '--strict-mcp-config', ...(settings ? ['--settings', settings] : [])], scratch, () => {}, 10 * 60_000, () => {})
    if (r.code !== 0) throw new Error(`The AI stopped without a patch. ${r.err.trim().split('\n').slice(-2).join(' ')}`.trim())
  }
  await run(g, ['add', '-A'], scratch, 60_000)
  const diff = (await run(g, ['diff', '--cached'], scratch, 60_000)).out
  const changed = (await run(g, ['diff', '--cached', '--name-only'], scratch, 60_000)).out.split('\n').filter(Boolean)
  const record: PatchRecord = { id, sessionId, findingId, title: f.title, createdAt: new Date().toISOString(), dir, scratch, diff, files: changed, tests: { ran: false, passed: false, command: '', output: '' }, applied: false, rolledBack: false }
  if (!diff.trim() || before.includes('??')) {
    // The baseline commit makes untracked files tracked, so a diff of nothing means no edit.
    record.error = 'The AI did not change any file. The finding may be a false positive, or it needs a decision a patch cannot make.'
    writeFileSync(join(dir, 'record.json'), JSON.stringify(record, null, 2))
    return record
  }
  const cmd = testCommand(scratch)
  if (!cmd) {
    record.tests = { ran: false, passed: false, command: '', output: 'No test command found (package.json scripts.test, composer test, or pytest). The patch is not appliable.' }
  } else {
    const tr = deps.testRunner ? await deps.testRunner(cmd.bin, cmd.args, scratch) : await run(cmd.bin, cmd.args, scratch, 5 * 60_000)
    record.tests = { ran: true, passed: tr.code === 0, command: `${cmd.bin} ${cmd.args.join(' ')}`, output: (tr.out + tr.err).slice(-6000) }
  }
  writeFileSync(join(dir, 'record.json'), JSON.stringify(record, null, 2))
  return record
}

export function listPatches(sessionId?: string): PatchRecord[] {
  const root = join(dirs.root(), 'patches')
  if (!existsSync(root)) return []
  const out: PatchRecord[] = []
  for (const id of readdirSync(root)) {
    const file = join(root, id, 'record.json')
    if (!existsSync(file)) continue
    try {
      const r = JSON.parse(readFileSync(file, 'utf8')) as PatchRecord
      if (!sessionId || r.sessionId === sessionId) out.push(r)
    } catch {
      // A broken record is skipped, not guessed.
    }
  }
  return out.sort((a, b) => b.createdAt.localeCompare(a.createdAt))
}

/** Apply only with the typed phrase and only after the project's tests passed. */
/** Patch ids are made by MacSec: patch- and eight hex digits. Anything else could point outside the patches folder. */
export function checkPatchId(id: string): string {
  if (typeof id !== 'string' || !/^patch-[0-9a-f]{8}$/.test(id)) throw new Error('That fix is not on this Mac.')
  return id
}

export async function applyPatch(id: string, phrase: string): Promise<PatchRecord> {
  checkPatchId(id)
  const file = join(dirs.root(), 'patches', id, 'record.json')
  if (!existsSync(file)) throw new Error('That patch is not on this Mac.')
  const r = JSON.parse(readFileSync(file, 'utf8')) as PatchRecord
  if (r.applied) throw new Error('That patch is already applied.')
  if (phrase !== `APPLY ${id}`) throw new Error(`Type "APPLY ${id}" to apply this patch.`)
  if (!r.tests.ran || !r.tests.passed) throw new Error('The project’s tests did not pass on the patched copy. It cannot be applied.')
  if (!r.files.length) throw new Error('This patch changes no file.')
  const project = readSession(r.sessionId).codePath
  if (!project) throw new Error('The project is no longer on this Mac.')
  // Store the originals first, so a rollback is one click and never a guess.
  const backup = join(r.dir, 'backup')
  mkdirSync(backup, { recursive: true })
  for (const rel of r.files) {
    const from = join(project, rel)
    if (!existsSync(from)) continue
    mkdirSync(join(backup, rel, '..'), { recursive: true })
    cpSync(from, join(backup, rel))
  }
  const g = gitBin()
  const patchFile = join(r.dir, 'change.patch')
  writeFileSync(patchFile, r.diff)
  const applied = existsSync(join(project, '.git'))
    ? await run(g, ['apply', patchFile], project, 60_000)
    : await run('patch', ['-p1', '-i', patchFile], project, 60_000)
  if (applied.code !== 0) throw new Error(`The patch did not apply: ${applied.err.trim().split('\n').slice(-2).join(' ')}`)
  r.applied = true
  r.appliedAt = new Date().toISOString()
  writeFileSync(file, JSON.stringify(r, null, 2))
  return r
}

export async function rollbackPatch(id: string): Promise<PatchRecord> {
  checkPatchId(id)
  const file = join(dirs.root(), 'patches', id, 'record.json')
  if (!existsSync(file)) throw new Error('That patch is not on this Mac.')
  const r = JSON.parse(readFileSync(file, 'utf8')) as PatchRecord
  if (!r.applied) throw new Error('That patch was not applied.')
  const project = readSession(r.sessionId).codePath
  if (!project) throw new Error('The project is no longer on this Mac.')
  const backup = join(r.dir, 'backup')
  for (const rel of r.files) {
    const from = join(backup, rel)
    const to = join(project, rel)
    if (existsSync(from)) cpSync(from, to)
    else if (existsSync(to)) rmSync(to, { force: true })
  }
  r.applied = false
  r.rolledBack = true
  writeFileSync(file, JSON.stringify(r, null, 2))
  return r
}

export function discardPatch(id: string): void {
  checkPatchId(id)
  const dir = join(dirs.root(), 'patches', id)
  if (existsSync(dir)) rmSync(dir, { recursive: true, force: true })
}
