/**
 * A mobile app check. It reads the app and stays on this Mac, unless the person also asks for the live
 * phone test (mobilelive.ts), which runs an Android .apk on a test phone they choose and only watches it:
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
import { copyFileSync, cpSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'fs'
import { basename, join, relative } from 'path'
import type { Finding, MobileScanRequest, SessionInfo } from '../shared/types'
import { beginOp, endOp, runTool, SessionRun } from './engine'
import { createSession, saveAiReport, sessionDir } from './sessions'
import { checkAndroidManifest, checkFirebaseConfig, checkInfoPlist, checkNetworkSecurityConfig, checkProvisioning, checkTargetSdk, hardening, hardeningFindings, parseMobsfscan, type Hardening } from './scanners/mobile'
import { parseGitleaks, parseOsv } from './scanners/parse'
import { addEvidence } from './evidence'
import { installTool, isInstalled, toolDef, toolPath } from './toolbox'
import { findAdb, getFridaServer, liveTest, packageFromManifest, realExec, validSerial } from './mobilelive'
import { extract } from './download'
import { codeText, onlineChecks, scanCode, signingFindings, type Refs } from './mobilestatic'
import { summarizeWithAi, summaryPrompt } from './aisummary'
import { log } from './logs'
import { appInArchive, baseApkIn, deepLinks, entitlementFindings, formatOf, frameworkNames, privacyManifest, protoManifestToXml, sdkFindings, urlFindings, type MobileFormat } from './mobiledeep'
import { bundleFindings, infoPlistExtra, provisioningFindings, signedEntitlementFindings, signingAuthorityFindings } from './ioschecks'
import { androidManifestGaps, keychainClasses, pinningGap, resilienceGap, screenshotGap, webviewGap } from './mobilegaps'

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
  const f = formatOf(path, existsSync(path) && statSync(path).isDirectory())
  return f === 'apk' || f === 'apks' || f === 'aab' ? 'apk' : f === 'ipa' || f === 'xcarchive' ? 'ipa' : 'source'
}

export function startMobileScan(req: MobileScanRequest): SessionInfo {
  if (!existsSync(req.path)) throw new Error('That app or folder is not there any more.')
  const kind = mobileKind(req.path)
  const format = formatOf(req.path, statSync(req.path).isDirectory())
  if (req.live) {
    if (format !== 'apk') throw new Error('The live phone test works with a built Android app (.apk).')
    if (!req.live.confirmed) throw new Error('Confirm that you are allowed to test this app on that phone first.')
    if (!validSerial(req.live.serial)) throw new Error('Choose a test phone first.')
  }
  if (req.online && kind === 'source') throw new Error('Online checks are for a built app (.apk or .ipa).')
  if (kind === 'source' && !statSync(req.path).isDirectory()) throw new Error('Choose an app’s source folder (or Xcode project), or a built .apk, .aab, .apks, .ipa or .xcarchive.')
  const info = createSession('mobile-scan', basename(req.path).replace(/\.(apk|ipa|aab|apks|xcarchive)$/i, ''), req.path)
  info.reviewer = req.reviewer
  info.mode = undefined
  if (kind === 'source') info.codePath = req.path
  void runMobile(info.id, req, kind, format).catch((e) => log('error', `Mobile check: ${(e as Error).message}`, info.id))
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
const runApple = (bin: string, args: string[]): Promise<string> =>
  new Promise((resolve) => execFile(bin, args, { maxBuffer: 30 * 1024 * 1024 }, (_e, out) => resolve(out?.toString() ?? '')))

function plistXml(file: string): Promise<string> {
  const raw = readFileSync(file)
  if (!raw.subarray(0, 6).toString('latin1').startsWith('bplist')) return Promise.resolve(raw.toString('utf8'))
  return new Promise((resolve, reject) =>
    execFile('/usr/bin/plutil', ['-convert', 'xml1', '-o', '-', file], { maxBuffer: 20 * 1024 * 1024 }, (e, out) => (e ? reject(new Error('This Info.plist is in binary form and macOS’s plutil could not read it.')) : resolve(out)))
  )
}

async function runMobile(id: string, req: MobileScanRequest, kind: 'source' | 'apk' | 'ipa', format: MobileFormat): Promise<void> {
  /** The .apk to read: the one chosen, or the base .apk taken out of a .apks set. */
  let apkPath = req.path
  const op = beginOp(id)
  const s = new SessionRun(id, op)
  const unpacked = join(sessionDir(id), 'unpacked')
  const root = kind === 'source' ? req.path : unpacked
  let mobsfRules = new Set<string>()
  const st = {
    unpack: kind !== 'source' ? s.step('unpack', `Unpack the ${kind === 'apk' ? 'Android' : 'iOS'} app${format === 'aab' ? ' bundle' : format === 'apks' ? ' set' : format === 'xcarchive' ? ' archive' : ''}`) : null,
    mobsf: kind === 'source' ? s.step('mobsfscan', 'mobsfscan: Android and iOS security rules') : null,
    settings: s.step('settings', kind === 'apk' ? 'Decode and check the Android manifest' : kind === 'ipa' ? 'Check Info.plist settings' : 'Check the manifest and Info.plist settings'),
    binary: kind !== 'source' ? s.step('binary', kind === 'apk' ? 'Check native libraries are hardened' : 'Check the app binary is hardened') : null,
    deps: kind === 'source' ? s.step('deps', 'Vulnerable libraries (osv-scanner)') : null,
    keys: s.step('gitleaks', 'Look for keys and passwords in the app'),
    deep: kind !== 'source' ? s.step('deep', 'Read the app’s code: pinning, root checks, weak crypto, signing') : null,
    online: req.online && kind !== 'source' ? s.step('online', 'Ask once whether the cloud addresses in the app are open') : null,
    live: req.live && kind === 'apk' ? s.step('live', 'Run the app on a test phone and watch it') : null,
    ai: req.reviewer !== 'none' ? s.step('ai', 'AI: what matters most and how to fix it') : null
  }
  try {
    if (st.unpack)
      await s.run(st.unpack, async (note) => {
        rmSync(unpacked, { recursive: true, force: true })
        mkdirSync(unpacked, { recursive: true })
        // Both formats are zip files; extract() uses macOS's unzip with an argument list.
        if (statSync(req.path).size > 4 * 1024 ** 3) throw new Error('This app is larger than 4 GB, too large to unpack.')
        if (format === 'xcarchive') {
          // An archive is a folder: copy the app out of it, without following links.
          const app = appInArchive(req.path)
          if (!app) throw new Error('No app was found inside this archive (Products/Applications).')
          const dest = join(unpacked, 'Payload', basename(app))
          mkdirSync(dest, { recursive: true })
          cpSync(app, dest, { recursive: true, verbatimSymlinks: true })
        } else {
          const copy = join(sessionDir(id), 'app.zip')
          copyFileSync(req.path, copy)
          if (format === 'apks') {
            // A set of split .apk files: the base one holds the code and the manifest.
            const outer = join(sessionDir(id), 'apks')
            rmSync(outer, { recursive: true, force: true })
            mkdirSync(outer, { recursive: true })
            await unpackApp(copy, outer)
            const names = findFiles(outer, (n) => n.endsWith('.apk'), 200).map((p) => relative(outer, p))
            const base = baseApkIn(names)
            if (!base) throw new Error('No base .apk was found inside this .apks set.')
            apkPath = join(sessionDir(id), 'base.apk')
            copyFileSync(join(outer, base), apkPath)
            rmSync(outer, { recursive: true, force: true })
            copyFileSync(apkPath, copy)
          }
          await unpackApp(copy, unpacked)
          rmSync(copy, { force: true })
        }
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
        const out = join(s.raw, 'AndroidManifest.xml')
        if (format === 'aab') {
          // A bundle keeps its manifest as protobuf: turn it back into text first.
          const pb = join(unpacked, 'base', 'manifest', 'AndroidManifest.xml')
          if (!existsSync(pb)) throw new Error('No manifest was found in this .aab (base/manifest).')
          writeFileSync(out, protoManifestToXml(readFileSync(pb)))
        } else {
          await ensure('androguard', note)
          await runTool({ name: 'androguard', bin: 'androguard', args: ['axml', '-o', out, apkPath], timeoutMs: 5 * 60_000, output: out }, op, s.raw, line)
        }
        found.push(...checkAndroidManifest(readFileSync(out, 'utf8')), ...checkTargetSdk(readFileSync(out, 'utf8')), ...deepLinks(readFileSync(out, 'utf8')))
        if (format === 'aab') note('The bundle’s network rules are not decoded: build an .apk or .apks for that check')
        // The app's network rules are a binary XML file inside it: decode that too.
        for (const f of format === 'aab' ? [] : findFiles(unpacked, (n) => n.endsWith('.xml'), 300).filter((p) => /\/res\/xml\/[^/]*network[^/]*config[^/]*\.xml$/i.test(p)).slice(0, 3)) {
          const dec = join(s.raw, `nsc-${found.length}.xml`)
          try {
            await runTool({ name: 'androguard', bin: 'androguard', args: ['axml', '-o', dec, f], timeoutMs: 2 * 60_000, output: dec }, op, s.raw, line)
            found.push(...checkNetworkSecurityConfig(readFileSync(dec, 'utf8'), relative(unpacked, f)))
          } catch {
            // Not decodable: skip it.
          }
        }
        for (const f of findFiles(unpacked, (n) => n === 'google-services.json', 5)) found.push(...checkFirebaseConfig(readFileSync(f, 'utf8'), relative(unpacked, f)))
      } else {
        const manifests = kind === 'source' ? findFiles(root, (n) => n === 'AndroidManifest.xml') : []
        const plists = findFiles(root, (n) => n === 'Info.plist').filter((p) => kind === 'source' || /Payload\/[^/]+\.app\/Info\.plist$/.test(p))
        for (const m of manifests) {
          const xml = readFileSync(m, 'utf8')
          found.push(...checkAndroidManifest(xml, relative(root, m), mobsfRules), ...checkTargetSdk(xml, relative(root, m)), ...deepLinks(xml, relative(root, m)), ...androidManifestGaps(xml, relative(root, m)))
        }
        for (const p of plists) {
          const xml = await plistXml(p)
          found.push(...checkInfoPlist(xml, relative(root, p), mobsfRules), ...infoPlistExtra(xml, relative(root, p)))
        }
        // Source projects keep the network rules and the Firebase settings as plain files.
        for (const f of findFiles(root, (n) => /^network[_-]?security[_-]?config\.xml$/i.test(n), 10)) found.push(...checkNetworkSecurityConfig(readFileSync(f, 'utf8'), relative(root, f)))
        for (const f of findFiles(root, (n) => n === 'google-services.json' || n === 'GoogleService-Info.plist', 10)) found.push(...checkFirebaseConfig(readFileSync(f, 'utf8'), relative(root, f)))
        // A built iOS app carries its signing profile: it shows whether this is a development build.
        if (kind === 'ipa') {
          const app = findFiles(unpacked, (n) => n === 'Info.plist').find((p) => /Payload\/[^/]+\.app\/Info\.plist$/.test(p))
          const dir = app ? join(app, '..') : null
          for (const f of findFiles(unpacked, (n) => n === 'embedded.mobileprovision', 3)) {
            const rel = relative(unpacked, f)
            const profile = (await runApple('/usr/bin/security', ['cms', '-D', '-i', f])) || readFileSync(f, 'latin1')
            found.push(...checkProvisioning(profile, rel), ...provisioningFindings(profile, rel))
          }
          // What the signed app requests, not what the profile merely permits.
          if (dir) {
            const ent = await runApple('/usr/bin/codesign', ['-d', '--entitlements', ':-', dir])
            if (ent.trim()) found.push(...signedEntitlementFindings(ent, relative(unpacked, dir)))
            const dv = await runApple('/usr/bin/codesign', ['-dv', '--verbose=4', dir])
            found.push(...signingAuthorityFindings(dv, relative(unpacked, dir)))
          }
        }
        // Source projects keep entitlements in plain .entitlements files.
        if (kind === 'source') for (const f of findFiles(root, (n) => n.endsWith('.entitlements'), 10)) found.push(...entitlementFindings(readFileSync(f, 'utf8'), relative(root, f)))
        // The privacy manifest: Apple asks every app (and each SDK) for one.
        if (kind === 'ipa' || plists.length) {
          const pm: { path: string; text: string }[] = []
          for (const f of findFiles(root, (n) => n === 'PrivacyInfo.xcprivacy', 30)) pm.push({ path: relative(root, f), text: await plistXml(f).catch(() => '') })
          found.push(...privacyManifest(pm, true))
        }
        note(`${manifests.length + plists.length} settings ${manifests.length + plists.length === 1 ? 'file' : 'files'} read`)
      }
      return found
    })

    if (st.binary)
      await s.run(st.binary, async (note) => {
        const list: { file: string; h: Hardening }[] = []
        if (kind === 'apk') {
          // In an .apk the libraries are in lib/, in an .aab in base/lib/ (and in feature modules).
          for (const f of findFiles(unpacked, (n) => n.endsWith('.so'), 500).filter((p) => /(^|\/)lib\/[^/]+\/[^/]+\.so$/.test(relative(unpacked, p)))) list.push({ file: relative(unpacked, f), h: hardening(readFileSync(f)) })
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

    if (st.deps)
      await s.run(st.deps, async (note, line) => {
        await ensure('osv-scanner', note)
        const osv = join(s.raw, 'osv.json')
        await runTool({ name: 'osv-scanner', bin: 'osv-scanner', args: ['scan', 'source', '-r', '--format', 'json', '--output', osv, '.'], cwd: root, timeoutMs: 15 * 60_000, output: osv }, op, s.raw, line)
        return addEvidence(root, parseOsv(readFileSync(osv, 'utf8'), root))
      })

    await s.run(st.keys, async (note, line) => {
      await ensure('gitleaks', note)
      const out = join(s.raw, 'gitleaks.json')
      await runTool({ name: 'gitleaks', bin: 'gitleaks', args: ['dir', root, '--report-format', 'json', '--report-path', out, '--no-banner', '--redact', '--exit-code', '0', '--log-level', 'error'], timeoutMs: 20 * 60_000, output: out }, op, s.raw, line)
      const found = parseGitleaks(readFileSync(out, 'utf8'), root).map((f) => ({ ...f, category: 'secret' as const }))
      return kind === 'source' ? addEvidence(root, found) : found
    })

    let refs: Refs = { firebase: [], s3: [], gcs: [] }
    if (st.deep)
      await s.run(st.deep, async (note) => {
        const files = findFiles(unpacked, (n) => (kind === 'apk' ? /^classes\d*\.dex$/.test(n) : true), 20000)
        let bufs: Buffer[]
        const out: Finding[] = []
        if (kind === 'apk') {
          bufs = files.slice(0, 20).map((p) => readFileSync(p))
          for (const b of findFiles(unpacked, (n) => /^index\.android\.bundle$|\.jsbundle$/i.test(n), 5)) bufs.push(readFileSync(b))
          if (format === 'apk') out.push(...signingFindings(readFileSync(req.path), unpacked))
          else note(format === 'aab' ? 'The store signs a bundle itself, so signing is not checked' : 'Signing is not checked in a .apks set')
        } else {
          const app = findFiles(unpacked, (n) => n === 'Info.plist').find((p) => /Payload\/[^/]+\.app\/Info\.plist$/.test(p))
          const dir = app ? join(app, '..') : null
          const exe = dir ? /<key>CFBundleExecutable<\/key>\s*<string>([^<]+)<\/string>/.exec(readFileSync(app!, 'latin1'))?.[1] : null
          const bin = dir && exe && !/[/\\]|^\.\.?$/.test(exe) ? join(dir, exe) : null
          bufs = bin && existsSync(bin) && lstatSync(bin).isFile() && statSync(bin).size < 400 * 1024 * 1024 ? [readFileSync(bin)] : []
          const jsb = dir ? join(dir, 'main.jsbundle') : null
          if (jsb && existsSync(jsb)) bufs.push(readFileSync(jsb))
        }
        if (!bufs.length) {
          note('No compiled code found')
          return out
        }
        const nsc = findFiles(unpacked, (n) => n.endsWith('.xml'), 300).some((p) => /network[^/]*config/i.test(p) && /<pin-set/i.test(readFileSync(p, 'latin1')))
        const text = codeText(bufs)
        const r = scanCode(text, kind === 'apk' ? 'android' : 'ios', { hasPinSet: nsc })
        refs = r.refs
        const appDirs = kind === 'ipa' ? findFiles(unpacked, (n) => n === 'Info.plist').filter((p) => /Payload\/[^/]+\.app\/Info\.plist$/.test(p)).map((p) => join(p, '..')) : []
        r.findings.push(
          ...sdkFindings(kind === 'apk' ? text : `${text}\n${appDirs.map(frameworkNames).join('\n')}`, kind === 'apk' ? 'android' : 'ios'),
          ...urlFindings(text),
          ...bundleFindings(text, kind === 'apk' ? 'assets/index.android.bundle' : 'main.jsbundle'),
          ...resilienceGap(text, kind === 'apk' ? 'android' : 'ios', kind === 'apk' ? 'classes.dex' : 'main.jsbundle'),
          ...webviewGap(text, kind === 'apk' ? 'android' : 'ios', kind === 'apk' ? 'AndroidManifest.xml' : 'main.jsbundle')
        )
        if (kind === 'apk') r.findings.push(...screenshotGap('android', text, false, 'classes.dex'), ...pinningGap(text, 'android', 'res/xml/network_security_config.xml'))
        else r.findings.push(...keychainClasses(text, 'app'))
        note(`${bufs.length} compiled ${bufs.length === 1 ? 'file' : 'files'} read, ${r.hosts.length} servers named`)
        return [...out, ...r.findings]
      })

    if (st.online)
      await s.run(st.online, async (note) => {
        const n = refs.firebase.length + refs.s3.length + refs.gcs.length
        if (!n) {
          note('No Firebase, S3 or Google Storage addresses in the app')
          return []
        }
        note(`${n} cloud ${n === 1 ? 'address' : 'addresses'}, one read-only request each`)
        return onlineChecks(refs)
      })

    if (st.live && req.live) {
      const live = req.live
      await s.run(st.live, async (note) => {
        const adb = findAdb()
        if (!adb) throw new Error('adb was not found. Install Android Studio (free), or run: brew install --cask android-platform-tools')
        const manifest = join(s.raw, 'AndroidManifest.xml')
        const pkg = existsSync(manifest) ? packageFromManifest(readFileSync(manifest, 'utf8')) : null
        if (!pkg) throw new Error('Could not read the app’s package name from its manifest.')
        await ensure('frida-tools', note).catch((e) => note(`Frida could not be installed (${(e as Error).message}), so the app will not be watched`))
        const frida = isInstalled(toolDef('frida-tools')!) ? toolPath('frida') : null
        return liveTest({ exec: realExec, adb, frida, serial: live.serial, apk: req.path, pkg, confirmed: live.confirmed, note, fridaServer: (arch) => getFridaServer(realExec, toolPath('frida'), arch, note), scriptPath: join(s.raw, 'watch.js'), cancelled: () => s.cancelled })
      })
    }

    if (st.ai)
      await s.run(st.ai, async () => {
        const what = kind === 'source' ? 'The app’s source code' : kind === 'apk' ? `A built Android app (${format === 'apk' ? '.apk' : '.' + format})` : `A built iOS app (${format === 'ipa' ? '.ipa' : '.xcarchive'})`
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
    rmSync(join(sessionDir(id), 'base.apk'), { force: true })
    endOp(id)
    log('info', `Mobile check of ${s.info.title} ${s.info.status}`, id)
  }
}
