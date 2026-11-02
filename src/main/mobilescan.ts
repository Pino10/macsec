/**
 * A mobile app check. Everything is read-only and stays on this Mac:
 *
 *   Source folder   mobsfscan's Android and iOS rules, the manifest and Info.plist settings,
 *                   and keys left in the code
 *   .apk            the decoded manifest (Androguard), native libraries' hardening, and keys
 *                   in the app's files
 *   .ipa            Info.plist settings, the app binary's hardening (PIE, canaries, ARC,
 *                   encryption), and keys in the app's files
 *
 * A built app is unpacked into the session's folder and removed when the check is done.
 */
import { execFile } from 'child_process'
import { copyFileSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync } from 'fs'
import { basename, extname, join, relative } from 'path'
import type { Finding, MobileScanRequest, SessionInfo } from '../shared/types'
import { beginOp, endOp, runTool, SessionRun } from './engine'
import { createSession, saveAiReport, sessionDir } from './sessions'
import { checkAndroidManifest, checkInfoPlist, hardening, hardeningFindings, parseMobsfscan, type Hardening } from './scanners/mobile'
import { parseGitleaks } from './scanners/parse'
import { addEvidence } from './evidence'
import { installTool, isInstalled, toolDef } from './toolbox'
import { extract } from './download'
import { summarizeWithAi, summaryPrompt } from './aisummary'
import { log } from './logs'

const SKIP = new Set(['node_modules', 'build', 'Pods', '.gradle', '.git', 'DerivedData', '.dart_tool', 'vendor'])

/** Files with a given name in a project, skipping build output and dependencies. */
export function findFiles(root: string, match: (name: string) => boolean, limit = 50): string[] {
  const out: string[] = []
  const walk = (dir: string, depth: number): void => {
    if (depth > 12 || out.length >= limit) return
    let names: string[]
    try {
      names = readdirSync(dir)
    } catch {
      return
    }
    for (const n of names) {
      const p = join(dir, n)
      let st
      try {
        // lstat: links inside an unpacked app are never followed out of it.
        st = lstatSync(p)
      } catch {
        continue
      }
      if (st.isSymbolicLink()) continue
      if (st.isDirectory()) {
        if (!SKIP.has(n) && !n.startsWith('.')) walk(p, depth + 1)
      } else if (match(n)) out.push(p)
    }
  }
  walk(root, 0)
  return out
}

/** Installs a tool into MacSec the first time it is needed, saying so in the step. */
async function ensure(id: string, note?: (d: string) => void): Promise<void> {
  const d = toolDef(id)
  if (!d || isInstalled(d)) return
  note?.(`Installing ${d.name} into MacSec first`)
  await installTool(id, (p) => note?.(`Installing ${d.name} into MacSec first${p !== null ? `, ${Math.round(p)}%` : ''}`))
}

export function mobileKind(path: string): 'source' | 'apk' | 'ipa' {
  const e = extname(path).toLowerCase()
  return e === '.apk' ? 'apk' : e === '.ipa' ? 'ipa' : 'source'
}

export function startMobileScan(req: MobileScanRequest): SessionInfo {
  if (!existsSync(req.path)) throw new Error('That app or folder is not there any more.')
  const kind = mobileKind(req.path)
  if (kind === 'source' && !statSync(req.path).isDirectory()) throw new Error('Choose an app’s source folder, or a built .apk or .ipa file.')
  const info = createSession('mobile-scan', basename(req.path).replace(/\.(apk|ipa)$/i, ''), req.path)
  info.reviewer = req.reviewer
  info.mode = undefined
  if (kind === 'source') info.codePath = req.path
  void runMobile(info.id, req, kind).catch((e) => log('error', `Mobile check: ${(e as Error).message}`, info.id))
  return info
}

/**
 * Apps are zip files from outside. On macOS, bsdtar (tar) unpacks them: it refuses paths with
 * "..", absolute paths and writing through links, so nothing lands outside the session.
 */
async function unpackApp(zip: string, dest: string): Promise<void> {
  if (process.platform !== 'darwin') return extract(zip, dest)
  await new Promise<void>((resolve, reject) => execFile('/usr/bin/tar', ['-xf', zip, '-C', dest], { timeout: 10 * 60_000 }, (e, _o, err) => (e ? reject(new Error(`Could not unpack the app: ${String(err).trim().split('\n').pop()}`)) : resolve())))
}

/** Converts a binary plist to XML with macOS's own plutil; XML plists are read as they are. */
function plistXml(file: string): Promise<string> {
  const raw = readFileSync(file)
  if (!raw.subarray(0, 6).toString('latin1').startsWith('bplist')) return Promise.resolve(raw.toString('utf8'))
  return new Promise((resolve, reject) =>
    execFile('/usr/bin/plutil', ['-convert', 'xml1', '-o', '-', file], { maxBuffer: 20 * 1024 * 1024 }, (e, out) => (e ? reject(new Error('This Info.plist is in binary form and macOS’s plutil could not read it.')) : resolve(out)))
  )
}

async function runMobile(id: string, req: MobileScanRequest, kind: 'source' | 'apk' | 'ipa'): Promise<void> {
  const op = beginOp(id)
  const s = new SessionRun(id, op)
  const unpacked = join(sessionDir(id), 'unpacked')
  const root = kind === 'source' ? req.path : unpacked
  let mobsfRules = new Set<string>()
  const st = {
    unpack: kind !== 'source' ? s.step('unpack', `Unpack the ${kind === 'apk' ? 'Android' : 'iOS'} app`) : null,
    mobsf: kind === 'source' ? s.step('mobsfscan', 'mobsfscan: Android and iOS security rules') : null,
    settings: s.step('settings', kind === 'apk' ? 'Decode and check the Android manifest' : kind === 'ipa' ? 'Check Info.plist settings' : 'Check the manifest and Info.plist settings'),
    binary: kind !== 'source' ? s.step('binary', kind === 'apk' ? 'Check native libraries are hardened' : 'Check the app binary is hardened') : null,
    keys: s.step('gitleaks', 'Look for keys and passwords in the app'),
    ai: req.reviewer !== 'none' ? s.step('ai', 'AI: what matters most and how to fix it') : null
  }
  try {
    if (st.unpack)
      await s.run(st.unpack, async (note) => {
        rmSync(unpacked, { recursive: true, force: true })
        mkdirSync(unpacked, { recursive: true })
        // Both formats are zip files; extract() uses macOS's unzip with an argument list.
        if (statSync(req.path).size > 4 * 1024 ** 3) throw new Error('This app is larger than 4 GB, too large to unpack.')
        const copy = join(sessionDir(id), 'app.zip')
        copyFileSync(req.path, copy)
        await unpackApp(copy, unpacked)
        rmSync(copy, { force: true })
        note(`${findFiles(unpacked, () => true, 100000).length} files`)
      })

    if (st.mobsf)
      await s.run(st.mobsf, async (note, line) => {
        // mobsfscan runs its rules with Semgrep, which must be on MacSec's path too.
        await ensure('semgrep', note)
        await ensure('mobsfscan', note)
        const out = join(s.raw, 'mobsfscan.json')
        await runTool({ name: 'mobsfscan', bin: 'mobsfscan', args: ['--json', '-o', out, root], timeoutMs: 30 * 60_000, output: out }, op, s.raw, line)
        const text = readFileSync(out, 'utf8')
        try {
          mobsfRules = new Set(Object.keys((JSON.parse(text) as { results?: object }).results ?? {}))
        } catch {
          // An empty report.
        }
        return addEvidence(root, parseMobsfscan(text, root))
      })

    await s.run(st.settings, async (note, line) => {
      const found: Finding[] = []
      if (kind === 'apk') {
        await ensure('androguard', note)
        const out = join(s.raw, 'AndroidManifest.xml')
        await runTool({ name: 'androguard', bin: 'androguard', args: ['axml', '-o', out, req.path], timeoutMs: 5 * 60_000, output: out }, op, s.raw, line)
        found.push(...checkAndroidManifest(readFileSync(out, 'utf8')))
      } else {
        const manifests = kind === 'source' ? findFiles(root, (n) => n === 'AndroidManifest.xml') : []
        const plists = findFiles(root, (n) => n === 'Info.plist').filter((p) => kind === 'source' || /Payload\/[^/]+\.app\/Info\.plist$/.test(p))
        for (const m of manifests) found.push(...checkAndroidManifest(readFileSync(m, 'utf8'), relative(root, m), mobsfRules))
        for (const p of plists) found.push(...checkInfoPlist(await plistXml(p), relative(root, p), mobsfRules))
        note(`${manifests.length + plists.length} settings ${manifests.length + plists.length === 1 ? 'file' : 'files'} read`)
      }
      return found
    })

    if (st.binary)
      await s.run(st.binary, async (note) => {
        const list: { file: string; h: Hardening }[] = []
        if (kind === 'apk') {
          const lib = join(unpacked, 'lib')
          if (existsSync(lib) && lstatSync(lib).isDirectory()) for (const f of findFiles(lib, (n) => n.endsWith('.so'), 500)) list.push({ file: relative(unpacked, f), h: hardening(readFileSync(f)) })
        } else {
          const app = findFiles(unpacked, (n) => n === 'Info.plist').find((p) => /Payload\/[^/]+\.app\/Info\.plist$/.test(p))
          if (!app) throw new Error('No app was found inside this .ipa.')
          const dir = join(app, '..')
          const exe = /<key>CFBundleExecutable<\/key>\s*<string>([^<]+)<\/string>/.exec(await plistXml(app))?.[1]
          // The executable's name comes from the app: it must be a plain file name inside the app.
          if (exe && !/[/\\]|^\.\.?$/.test(exe) && existsSync(join(dir, exe)) && lstatSync(join(dir, exe)).isFile()) list.push({ file: relative(unpacked, join(dir, exe)), h: hardening(readFileSync(join(dir, exe))) })
          const fw = join(dir, 'Frameworks')
          if (existsSync(fw))
            for (const f of readdirSync(fw).filter((n) => n.endsWith('.framework'))) {
              const bin = join(fw, f, f.replace(/\.framework$/, ''))
              if (existsSync(bin) && lstatSync(bin).isFile()) list.push({ file: relative(unpacked, bin), h: { ...hardening(readFileSync(bin)), sharedLib: true } })
            }
          if (list[0]?.h.format === 'mach-o' && list[0].h.encrypted) note('The app is encrypted by the App Store, so only its headers can be read')
        }
        if (!list.length) note('No compiled code found')
        else if (!st.binary?.detail) note(`${list.length} compiled ${list.length === 1 ? 'file' : 'files'} checked`)
        return hardeningFindings(list)
      })

    await s.run(st.keys, async (note, line) => {
      await ensure('gitleaks', note)
      const out = join(s.raw, 'gitleaks.json')
      await runTool({ name: 'gitleaks', bin: 'gitleaks', args: ['dir', root, '--report-format', 'json', '--report-path', out, '--no-banner', '--redact', '--exit-code', '0', '--log-level', 'error'], timeoutMs: 20 * 60_000, output: out }, op, s.raw, line)
      const found = parseGitleaks(readFileSync(out, 'utf8'), root).map((f) => ({ ...f, category: 'secret' as const }))
      return kind === 'source' ? addEvidence(root, found) : found
    })

    if (st.ai)
      await s.run(st.ai, async () => {
        const what = kind === 'source' ? 'The app’s source code' : kind === 'apk' ? 'A built Android app (.apk)' : 'A built iOS app (.ipa)'
        const r = await summarizeWithAi(req.reviewer, summaryPrompt('mobile', s.info.title, `${what}. Map each finding to OWASP MASVS where it fits.`, s.findings.filter((f) => f.severity !== 'info')), op, s.raw)
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
    s.finish()
  } catch (e) {
    s.finish((e as Error).message)
  } finally {
    rmSync(unpacked, { recursive: true, force: true })
    endOp(id)
    log('info', `Mobile check of ${s.info.title} ${s.info.status}`, id)
  }
}
