import { app, BrowserWindow, dialog, ipcMain, Notification, safeStorage, session, shell, type IpcMainInvokeEvent } from 'electron'
import { execFile } from 'child_process'
import type { Server } from 'http'
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'fs'
import { join, normalize, resolve, sep } from 'path'
import { pathToFileURL } from 'url'
import { release } from 'os'
import type { FreeLlmInfo, IntegrationsInfo, SkillPackInfo, ApiScanRequest, Channels, Events, ReviewRequest, ScanMode, WebScanRequest, ReconRequest, SessionInfo } from '../shared/types'
import { dirs, ensureDirs } from './paths'
import { getSettings, setSettings } from './settings'
import { getSecret, setSecret, setSecretsCrypto } from './secrets'
import { configureGitHub } from './seckit/ghapi'
import { USER_AGENT } from './download'
import { FREE_KEY, freeConfig } from './freellm'
import { checkFreeLlm, checkFreeLlmKey, FREELLM_MODELS, freeLlmModel, freeLlmUrl } from './seckit/freellm'
import { ensureSkills, listSkills } from './skills'
import { setModelCrypto, detectLlms, testLlm, listServers, saveServer, deleteServer } from './models'
import { jobs } from './jobs'
import { log, logEvents, listLogs, clearLogs } from './logs'
import { checkUpdates, checkUpdatesDaily, installTool, listTools, removeTool, toolDef, toolEnv, toolPath, updateToolData } from './toolbox'
import { dockerPath, localSites, startWebScan } from './webscan'
import { ciWorkflow, compareFindings, preCommitHook, previousSession, toDefectDojo, toSarif } from './exports'
import { runCheckup } from './checkup'
import { parseTrivy } from './scanners/parse'
import { installPack, packState, removePack, SKILL_PACKS } from './seckit/skillpacks'
import { checkHookUrl, hookBody, raycastScripts, sendHook, type HookKind } from './webhooks'
import { MCP_PORT, mcpToken, mcpUrl, startMcpServer } from './mcp'
import { macsecCli, macsecTools } from './mcptools'
import { loadSpec, startApiScan } from './apiscan'
import { startMobileScan } from './mobilescan'
import { reconData, startRecon } from './reconscan'
import { readRequest, saveRequest, stripSecrets, triageFinding } from './sessions'
import { checkForUpdate, installUpdate } from './updater'
import { installForClaude, installedForClaude, removeFromClaude } from './seckit/skills'
import { azureLogin, cloudStatus, isLocalHost } from './infraaudit'
import { optionalTools } from './optional'
import { startAudit } from './audit'
import { cancelOp, finishEvents } from './engine'
import { accounts, azureProjects, connectAzure, connectGitHub, githubRepos, importIntoWww, listLocal } from './projects'
import { cancelSession, startReview } from './review'
import { deleteSession, listSessions, readSession, recoverSessions, saveSession, sessionCodeDir, sessionDetail, sessionDir, sessionEvents, discardCode } from './sessions'
import { sessionHtml } from './report'
import { projectStats } from './scanners/plan'
import { findApp, findCli, installAgent, listAgents, openBurp, openTerminal, shellQuote } from './agents'

const isMac = process.platform === 'darwin'
const RENDERER_URL = !app.isPackaged ? process.env.ELECTRON_RENDERER_URL : undefined
const RENDERER_FILE = join(__dirname, '../renderer/index.html')
let mainWindow: BrowserWindow | null = null
let material: 'liquid-glass' | 'vibrancy' | 'none' = 'none'

class ValidationError extends Error {}

const macMajor = (): number => (isMac ? parseInt(release().split('.')[0], 10) - 9 : 0)

function liquidGlass(): { addView: (h: Buffer, o?: object) => number } | null {
  if (!isMac || macMajor() < 26) return null
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require('electron-liquid-glass')
  } catch {
    return null
  }
}

function send<K extends keyof Events>(event: K, payload: Events[K]): void {
  mainWindow?.webContents.send(event, payload)
}

function isAppUrl(url: string): boolean {
  if (RENDERER_URL) return url.startsWith(RENDERER_URL)
  return url === pathToFileURL(RENDERER_FILE).href || url.startsWith(pathToFileURL(RENDERER_FILE).href + '#')
}

const isWebUrl = (u: unknown): u is string => typeof u === 'string' && /^https:\/\/[^\s]+$/.test(u)

function createWindow(): void {
  const glass = liquidGlass()
  material = glass ? 'liquid-glass' : isMac ? 'vibrancy' : 'none'
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 840,
    minWidth: 1000,
    minHeight: 660,
    show: false,
    title: 'MacSec',
    titleBarStyle: isMac ? 'hiddenInset' : 'default',
    trafficLightPosition: { x: 20, y: 20 },
    transparent: material === 'liquid-glass',
    vibrancy: material === 'vibrancy' ? 'sidebar' : undefined,
    visualEffectState: 'active',
    backgroundColor: material === 'none' ? '#0b0f14' : '#00000000',
    webPreferences: { preload: join(__dirname, '../preload/index.js'), contextIsolation: true, nodeIntegration: false, sandbox: true, webSecurity: true, spellcheck: false }
  })
  if (glass && mainWindow) {
    const win = mainWindow
    win.webContents.once('did-finish-load', () => {
      try {
        glass.addView(win.getNativeWindowHandle(), {})
      } catch {
        // The CSS fallback still looks right.
      }
    })
  }
  mainWindow.once('ready-to-show', () => mainWindow?.show())
  mainWindow.on('closed', () => {
    mainWindow = null
  })
  if (RENDERER_URL) void mainWindow.loadURL(RENDERER_URL)
  else void mainWindow.loadFile(RENDERER_FILE)
}

/** The sign-in windows, which may browse your site; every other window is locked down. */
const loginContents = new Set<number>()

/** No navigation away, no popups, no webviews, no permissions. */
function hardenWebContents(): void {
  app.on('web-contents-created', (_e, contents) => {
    contents.on('will-navigate', (event, url) => {
      if (!isAppUrl(url) && !loginContents.has(contents.id)) event.preventDefault()
    })
    contents.on('will-attach-webview', (event) => event.preventDefault())
    contents.setWindowOpenHandler(({ url }) => {
      // In a sign-in window, pop-ups (single sign-on) open in the same window.
      if (loginContents.has(contents.id) && /^https?:\/\//.test(url)) void contents.loadURL(url)
      else if (isWebUrl(url)) void shell.openExternal(url)
      return { action: 'deny' }
    })
  })
  session.defaultSession.setPermissionRequestHandler((_wc, permission, callback) => callback(permission === 'clipboard-sanitized-write'))
  session.defaultSession.setPermissionCheckHandler((_wc, permission) => permission === 'clipboard-sanitized-write')
}

type ChannelName = keyof Channels
/** Only the app's own window may ask, and every error reaches it as a plain message. */
function handle<K extends ChannelName>(channel: K, fn: (...args: Channels[K]['args']) => Promise<Channels[K]['result']> | Channels[K]['result']): void {
  ipcMain.handle(channel, async (e: IpcMainInvokeEvent, ...args) => {
    const frame = e.senderFrame
    if (!mainWindow || !frame || frame !== mainWindow.webContents.mainFrame || !isAppUrl(frame.url)) throw new Error('Request refused.')
    try {
      return await fn(...(args as Channels[K]['args']))
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      if (!(err instanceof ValidationError)) log('error', `${channel}: ${msg}`)
      throw new Error(msg)
    }
  })
}

/**
 * Tests that can be run again: each start handler is kept, and the request it got is saved with
 * the session (without cookies, tokens or sign-in headers), so "Test again" repeats it exactly.
 */
type StartChannel = 'review:start' | 'web:start' | 'api:start' | 'mobile:start' | 'audit:start' | 'recon:start'
const starters = new Map<StartChannel, (req: unknown) => SessionInfo | Promise<SessionInfo>>()
function handleStart(channel: StartChannel, fn: (req: never) => SessionInfo | Promise<SessionInfo>): void {
  const run = async (req: unknown): Promise<SessionInfo> => {
    const info = await fn(req as never)
    saveRequest(info.id, channel, stripSecrets(req))
    return info
  }
  starters.set(channel, run)
  handle(channel, run as never)
}
export async function rerunSession(id: string): Promise<SessionInfo> {
  const saved = readRequest(id)
  if (!saved) throw new ValidationError('This test was made by an older MacSec and cannot be repeated. Start it again from its page.')
  const fn = starters.get(saved.channel as StartChannel)
  if (!fn) throw new ValidationError('This kind of test cannot be repeated.')
  // A folder you picked in a dialog for the first run may be used again.
  const p = (saved.req as { path?: unknown; source?: { path?: unknown } } | null)
  for (const x of [p?.path, p?.source?.path]) if (typeof x === 'string' && existsSync(x)) picked.add(resolve(x))
  return fn(saved.req)
}

/** A folder the window names must be inside the www folder, or one you picked in a dialog. */
const picked = new Set<string>()
function allowedProject(path: unknown): string {
  if (typeof path !== 'string') throw new ValidationError('Choose a project.')
  const p = resolve(path)
  const www = resolve(getSettings().wwwPath)
  if (!(p.startsWith(www + sep) || picked.has(p)) || !existsSync(p)) throw new ValidationError('That folder is not one of your projects.')
  return p
}

const pick = <T extends string>(v: unknown, ok: readonly T[], d: T): T => (ok.includes(v as T) ? (v as T) : d)
const MODES = ['quick', 'standard', 'thorough'] as const
const REVIEWERS = ['none', 'claude', 'claude-local', 'claude-free', 'codex', 'gemini', 'model'] as const

function validWeb(req: unknown): WebScanRequest {
  const r = (req ?? {}) as Partial<WebScanRequest>
  const t = r.target as WebScanRequest['target'] | undefined
  let target: WebScanRequest['target']
  if (t?.kind === 'local' && typeof t.name === 'string') target = { kind: 'local', name: t.name }
  else if (t?.kind === 'url' && typeof t.url === 'string' && /^https?:\/\/[^\s'"<>]+$/.test(t.url.trim())) target = { kind: 'url', url: new URL(t.url.trim()).href }
  else throw new ValidationError('Enter the address to scan, starting with http:// or https://.')
  return { target, mode: pick<ScanMode>(r.mode, MODES, 'standard'), authorized: r.authorized === true, headers: typeof r.headers === 'string' ? r.headers.slice(0, 4000) : undefined, reviewer: pick(r.reviewer, REVIEWERS, 'none') }
}

/** A host name or IP address only: never something a tool could read as an option. */
export function validHost(v: unknown): string {
  const h = typeof v === 'string' ? v.trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/[/:].*$/, '') : ''
  if (!h || h.length > 253 || h.startsWith('-') || !/^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(h)) throw new ValidationError('Enter a server name or IP address, such as example.com or 203.0.113.10.')
  return h
}

function validApi(req: unknown): ApiScanRequest {
  const r = (req ?? {}) as Partial<ApiScanRequest>
  const a = (r.auth ?? { kind: 'none' }) as ApiScanRequest['auth']
  return {
    spec: String(r.spec ?? ''),
    baseUrl: typeof r.baseUrl === 'string' ? r.baseUrl.trim() : '',
    auth: { kind: pick(a.kind, ['none', 'bearer', 'header'] as const, 'none'), value: typeof a.value === 'string' ? a.value.trim() : undefined, header: typeof a.header === 'string' ? a.header.trim() : undefined },
    mode: pick<ScanMode>(r.mode, MODES, 'standard'),
    authorized: r.authorized === true,
    reviewer: pick(r.reviewer, REVIEWERS, 'none')
  }
}

function validReview(req: unknown): ReviewRequest {
  const r = (req ?? {}) as Partial<ReviewRequest>
  const s = r.source as ReviewRequest['source'] | undefined
  if (!s) throw new ValidationError('Choose what to review.')
  let source: ReviewRequest['source']
  if (s.kind === 'local') source = { kind: 'local', path: allowedProject(s.path) }
  else if (s.kind === 'github' && typeof s.repo === 'string' && /^[\w.-]+\/[\w.-]+$/.test(s.repo)) source = { kind: 'github', repo: s.repo }
  else if (s.kind === 'azure' && typeof s.url === 'string' && /^https:\/\/[^\s'"]+$/.test(s.url)) source = { kind: 'azure', url: s.url }
  else throw new ValidationError('That source is not valid.')
  return {
    source,
    reviewer: pick(r.reviewer, ['none', 'claude', 'codex', 'model'] as const, 'claude'),
    depth: pick(r.depth, ['quick', 'standard', 'deep'] as const, 'standard'),
    focus: pick(r.focus, ['security', 'bugs', 'all'] as const, 'security'),
    keepCode: r.keepCode === true,
    skip: Array.isArray(r.skip) ? r.skip.filter((x): x is string => typeof x === 'string') : []
  }
}

/**
 * Opens your site in a private MacSec window. You sign in as usual and close the window; the
 * cookies for that site become the login for this scan. They live in memory only.
 */
function signIn(url: string): Promise<{ cookie: string; count: number } | null> {
  return new Promise((resolve) => {
    const partition = `macsec-login-${Date.now()}`
    const win = new BrowserWindow({
      width: 1100,
      height: 800,
      parent: mainWindow ?? undefined,
      title: 'Sign in, then close this window',
      backgroundColor: '#ffffff',
      webPreferences: { partition, sandbox: true, contextIsolation: true, nodeIntegration: false, javascript: true }
    })
    loginContents.add(win.webContents.id)
    win.on('page-title-updated', (e) => {
      e.preventDefault()
      win.setTitle(`Sign in, then close this window: ${new URL(win.webContents.getURL() || url).host}`)
    })
    const ses = win.webContents.session
    win.on('close', async () => {
      loginContents.delete(win.webContents.id)
      const host = new URL(url).hostname
      const all = await ses.cookies.get({})
      const mine = all.filter((c) => {
        const d = (c.domain ?? '').replace(/^\./, '')
        return d && (host === d || host.endsWith(`.${d}`))
      })
      resolve(mine.length ? { cookie: `Cookie: ${mine.map((c) => `${c.name}=${c.value}`).join('; ')}`, count: mine.length } : null)
      void ses.clearStorageData()
    })
    void win.loadURL(url)
  })
}

async function exportPdf(id: string): Promise<string | null> {
  const detail = sessionDetail(id)
  const html = join(sessionDir(id), 'report.html')
  writeFileSync(html, sessionHtml(detail))
  const win = new BrowserWindow({ show: false, webPreferences: { javascript: false, sandbox: true, contextIsolation: true } })
  try {
    await win.loadFile(html)
    const pdf = await win.webContents.printToPDF({ printBackground: true, pageSize: 'A4' })
    const out = join(sessionDir(id), `${detail.title.replace(/[^A-Za-z0-9._-]+/g, '-')}-security-report.pdf`)
    writeFileSync(out, pdf)
    return out
  } finally {
    win.destroy()
  }
}

function registerIpc(): void {
  handle('app:info', () => ({ version: app.getVersion(), root: dirs.root(), material }))
  handle('app:open-folder', async (which) => {
    const map = { root: dirs.root(), tools: dirs.tools(), sessions: dirs.sessions(), extensions: dirs.extensions() }
    const p = map[which as keyof typeof map]
    if (!p) throw new ValidationError('Unknown folder.')
    mkdirSync(p, { recursive: true })
    await shell.openPath(p)
  })
  handle('app:open-external', async (url) => {
    if (!isWebUrl(url)) throw new ValidationError('Only https addresses can be opened.')
    await shell.openExternal(url)
  })
  handle('settings:get', () => getSettings())
  handle('settings:set', (patch) => {
    const p = (patch ?? {}) as Record<string, unknown>
    const safe: Parameters<typeof setSettings>[0] = {}
    if (p.llm && typeof p.llm === 'object') {
      const l = p.llm as { baseUrl?: unknown; model?: unknown }
      safe.llm = { baseUrl: typeof l.baseUrl === 'string' ? l.baseUrl : getSettings().llm.baseUrl, model: typeof l.model === 'string' ? l.model : getSettings().llm.model }
    }
    if (['none', 'claude', 'codex', 'model'].includes(p.reviewer as string)) safe.reviewer = p.reviewer as never
    if (typeof p.notifications === 'boolean') safe.notifications = p.notifications
    if (p.claudeAuth === 'account' || p.claudeAuth === 'key') safe.claudeAuth = p.claudeAuth
    return setSettings(safe)
  })
  handle('settings:choose-www', async () => {
    if (!mainWindow) return null
    const r = await dialog.showOpenDialog(mainWindow, { title: 'Choose your projects folder', properties: ['openDirectory', 'createDirectory'] })
    if (r.canceled || !r.filePaths[0]) return null
    return setSettings({ wwwPath: r.filePaths[0] })
  })

  // Tools
  handle('tools:list', () => listTools())
  handle('tools:install', async (ids) => {
    const list = (Array.isArray(ids) ? ids : []).filter((id) => typeof id === 'string' && toolDef(id) && toolDef(id)!.method !== 'app')
    for (const id of list) {
      await jobs.run(`Installing ${toolDef(id)!.name}`, (u) => installTool(id, u)).catch((e) => log('error', `${toolDef(id)!.name}: ${(e as Error).message}`))
    }
    return listTools()
  })
  handle('tools:remove', async (id) => {
    await removeTool(String(id))
    return listTools()
  })
  handle('tools:update-data', () => jobs.run('Updating scanner databases', (u) => updateToolData(u)))
  handle('tools:check-updates', async () => {
    await checkUpdates()
    return listTools()
  })

  // Projects
  handle('projects:local', () => listLocal())
  handle('projects:import', async () => {
    if (!mainWindow) return null
    const r = await dialog.showOpenDialog(mainWindow, { title: 'Import a project into your www folder', buttonLabel: 'Import', properties: ['openDirectory'] })
    if (r.canceled || !r.filePaths[0]) return null
    const target = importIntoWww(r.filePaths[0])
    log('info', `Imported ${target}`)
    return listLocal()
  })
  handle('projects:pick', async () => {
    if (!mainWindow) return null
    const r = await dialog.showOpenDialog(mainWindow, { title: 'Review a folder', buttonLabel: 'Choose', properties: ['openDirectory'] })
    if (r.canceled || !r.filePaths[0]) return null
    const p = resolve(r.filePaths[0])
    picked.add(p)
    const s = projectStats(p)
    return { name: p.split('/').pop() ?? p, path: p, languages: s.languages.slice(0, 3), git: s.git }
  })
  handle('accounts:get', () => accounts())
  handle('accounts:github', (token) => connectGitHub(typeof token === 'string' ? token : null).catch((e) => Promise.reject(new ValidationError((e as Error).message))))
  handle('accounts:azure', (org, pat) => connectAzure(typeof org === 'string' ? org : null, typeof pat === 'string' ? pat : null).catch((e) => Promise.reject(new ValidationError((e as Error).message))))
  handle('github:repos', () => githubRepos().catch((e) => Promise.reject(new ValidationError((e as Error).message))))
  handle('azure:projects', (path) => azureProjects(String(path ?? '')).catch((e) => Promise.reject(new ValidationError((e as Error).message))))

  // Reviews and sessions
  handleStart('review:start', (req) => startReview(validReview(req)))
  handle('sessions:list', () => listSessions())
  handle('sessions:rerun', (id) => rerunSession(String(id)))
  handle('sessions:rerun-latest', async () => {
    // The newest finished test of each target, run again.
    const seen = new Set<string>()
    const out: SessionInfo[] = []
    for (const s of listSessions()) {
      const key = `${s.kind}|${s.target}`
      if (s.status === 'running' || seen.has(key)) continue
      seen.add(key)
      if (!readRequest(s.id)) continue
      out.push(await rerunSession(s.id).catch(() => null as never))
    }
    return out.filter(Boolean)
  })
  handle('findings:triage', (sid, fidv, t) => {
    const triage = t === 'fixed' || t === 'accepted' || t === 'not-a-problem' ? t : null
    return triageFinding(String(sid), String(fidv), triage)
  })
  // ---- Findings over time and exports
  handle('sessions:compare', (id) => {
    const s = readSession(String(id))
    const prev = previousSession(listSessions(), s)
    if (!prev) return { previous: null, added: [], fixed: [], still: 0 }
    const c = compareFindings(sessionDetail(s.id).findings, sessionDetail(prev.id).findings)
    return { previous: { id: prev.id, at: prev.createdAt }, ...c }
  })
  handle('sessions:export', async (id, format) => {
    const d = sessionDetail(String(id))
    if (!mainWindow) return null
    const ext = format === 'sarif' ? 'sarif' : format === 'cyclonedx' ? 'cdx.json' : 'json'
    let text: string
    if (format === 'sarif') text = JSON.stringify(toSarif(d.findings, app.getVersion()), null, 2)
    else if (format === 'defectdojo') text = JSON.stringify(toDefectDojo(d.findings, d), null, 2)
    else if (format === 'cyclonedx') {
      const sbom = join(sessionDir(d.id), 'raw', 'sbom.cdx.json')
      if (!existsSync(sbom)) throw new ValidationError('This session has no SBOM. Run a Standard or Deep code review (Syft makes it).')
      text = readFileSync(sbom, 'utf8')
    } else if (format === 'json') text = JSON.stringify({ session: { ...d, findings: undefined }, findings: d.findings }, null, 2)
    else throw new ValidationError('Choose SARIF, DefectDojo, CycloneDX or JSON.')
    const r = await dialog.showSaveDialog(mainWindow, { title: 'Export findings', defaultPath: join(app.getPath('downloads'), `macsec-${d.id}.${ext}`) })
    if (r.canceled || !r.filePath) return null
    writeFileSync(r.filePath, text)
    shell.showItemInFolder(r.filePath)
    return r.filePath
  })
  // Pre-commit hook and CI workflow: saved where you choose, never written into a project on its own.
  const saveInto = async (title: string, defaultPath: string, text: string, mode = 0o644): Promise<string | null> => {
    if (!mainWindow) return null
    const r = await dialog.showSaveDialog(mainWindow, { title, defaultPath })
    if (r.canceled || !r.filePath) return null
    writeFileSync(r.filePath, text, { mode })
    shell.showItemInFolder(r.filePath)
    return r.filePath
  }
  handle('projects:save-hook', (path) => {
    const p = allowedProject(path)
    const hooks = join(p, '.git', 'hooks')
    return saveInto('Save the pre-commit hook (choose .git/hooks/pre-commit to turn it on)', existsSync(hooks) ? join(hooks, 'pre-commit') : join(p, 'pre-commit'), preCommitHook(join(dirs.bin(), 'gitleaks')), 0o755)
  })
  handle('projects:save-ci', (path, kind) => {
    const p = allowedProject(path)
    const k = kind === 'azure' ? 'azure' : 'github'
    return saveInto(k === 'github' ? 'Save the GitHub Actions workflow' : 'Save the Azure Pipelines file', k === 'github' ? join(p, '.github', 'workflows', 'security.yml') : join(p, 'azure-pipelines-security.yml'), ciWorkflow(k))
  })
  // Mac check-up
  const checkupFile = (): string => join(dirs.config(), 'checkup.json')
  handle('checkup:run', async () => {
    const r = await jobs.run('Checking this Mac', () => runCheckup())
    writeFileSync(checkupFile(), JSON.stringify(r, null, 2), { mode: 0o600 })
    log('info', `Mac check-up: ${r.score} of 100`)
    return r
  })
  handle('checkup:last', () => {
    try {
      return JSON.parse(readFileSync(checkupFile(), 'utf8'))
    } catch {
      return null
    }
  })
  // Local Docker images, scanned with Trivy
  handle('docker:images', async () => {
    const docker = dockerPath()
    if (!docker) return { running: false, images: [] }
    const out = await new Promise<string>((res) => execFile(docker, ['images', '--format', '{{json .}}'], { timeout: 20000, maxBuffer: 8 * 1024 * 1024 }, (_e, o) => res(String(o))))
    const images = out.split('\n').filter(Boolean).map((l) => {
      try {
        const j = JSON.parse(l) as { Repository: string; Tag: string; Size: string; CreatedSince: string }
        return { ref: `${j.Repository}:${j.Tag}`, size: j.Size, created: j.CreatedSince }
      } catch {
        return null
      }
    }).filter((x): x is { ref: string; size: string; created: string } => !!x && !x.ref.includes('<none>'))
    return { running: true, images }
  })
  handle('docker:scan', async (ref) => {
    if (typeof ref !== 'string' || !/^[a-z0-9][a-z0-9._/:@-]{0,250}$/i.test(ref) || ref.startsWith('-')) throw new ValidationError('That is not an image name.')
    const docker = dockerPath()
    if (!docker) throw new ValidationError('Docker is not running.')
    const def = toolDef('trivy')
    if (def && !(await listTools()).find((t) => t.id === 'trivy')?.installed) await installTool('trivy', () => undefined)
    const out = join(dirs.logs(), `trivy-image-${Date.now()}.json`)
    await jobs.run(`Scanning ${ref}`, () => new Promise<void>((res, rej) => execFile(toolPath('trivy'), ['image', '--quiet', '--scanners', 'vuln,secret,misconfig', '--format', 'json', '--output', out, ref], { timeout: 30 * 60_000, env: toolEnv() }, (e, _o, err) => (e && !existsSync(out) ? rej(new Error(String(err).trim().split('\n').pop())) : res()))))
    const findings = parseTrivy(readFileSync(out, 'utf8'), '/')
    rmSync(out, { force: true })
    log('info', `Scanned image ${ref}: ${findings.length} findings`)
    return findings
  })
  // Skill packs
  const packsRoot = (): string => join(dirs.tools(), 'skill-packs')
  const packList = (): SkillPackInfo[] => SKILL_PACKS.map((p) => ({ name: p.name, repo: p.repo, license: p.license, about: p.about, ...packState(packsRoot(), p.id), id: p.id }))
  handle('packs:list', () => packList())
  handle('packs:install', async (id) => {
    if (!SKILL_PACKS.some((p) => p.id === id)) throw new ValidationError('That skill pack is not on the list.')
    const st = await jobs.run(`Getting the ${SKILL_PACKS.find((p) => p.id === id)!.name} skills`, () => installPack(packsRoot(), String(id)))
    log('info', `${st.loaded.length} skills from ${id}, commit ${st.commit}`)
    return packList()
  })
  handle('packs:remove', (id) => {
    removePack(packsRoot(), String(id))
    return packList()
  })
  // Integrations: MCP, CLI, webhooks, Raycast, Apple Shortcuts
  const cliPath = (): string => join(dirs.bin(), 'macsec')
  const raycastDir = (): string => join(dirs.root(), 'raycast')
  let mcpServer: Server | null = null
  let mcpError: string | null = null
  const startMcp = async (): Promise<void> => {
    if (mcpServer) return
    try {
      mcpServer = await startMcpServer({ tools: macsecTools({
        sessions: () => listSessions(),
        session: (id) => sessionDetail(id),
        compare: (id) => {
          const cur = readSession(id)
          const prev = previousSession(listSessions(), cur)
          return prev ? { previous: prev.id, ...compareFindings(sessionDetail(cur.id).findings, sessionDetail(prev.id).findings) } : { previous: null }
        },
        projects: () => listLocal(),
        review: (path, depth) => startReview(validReview({ source: { kind: 'local', path }, reviewer: getSettings().reviewer, depth, focus: 'security', keepCode: false })),
        checkup: () => runCheckup()
      }), version: app.getVersion(), onCall: (name) => log('info', `AI tool used ${name}`) })
      mcpError = null
    } catch (e) {
      mcpError = `Could not listen on port ${MCP_PORT}: ${(e as Error).message}`
    }
  }
  const integrations = (): IntegrationsInfo => {
    const w = getSettings().webhook
    return {
      webhook: w ? { ...w, saved: !!getSecret('webhook-url') } : null,
      raycastDir: raycastDir(),
      raycastInstalled: existsSync(join(raycastDir(), 'macsec-sessions.sh')),
      cli: cliPath(),
      shortcuts: [
        { title: 'Mac check-up', command: `"${cliPath()}" checkup` },
        { title: 'Latest sessions as JSON', command: `"${cliPath()}" sessions --json` },
        { title: 'Review a folder in www', command: `"${cliPath()}" review shop` }
      ],
      mcp: { enabled: !!getSettings().mcpEnabled, running: !!mcpServer, url: mcpUrl(MCP_PORT), command: `claude mcp add --transport http --scope user macsec ${mcpUrl(MCP_PORT)} --header "Authorization: Bearer ${mcpToken()}"`, error: mcpError }
    }
  }
  handle('integrations:get', () => integrations())
  handle('mcp:enable', async (on) => {
    setSettings({ mcpEnabled: on === true })
    if (on === true) {
      await startMcp()
      writeCli()
    } else {
      mcpServer?.close()
      mcpServer = null
    }
    return integrations()
  })
  const writeCli = (): void => {
    writeFileSync(cliPath(), macsecCli(join(dirs.config(), 'mcp-token'), MCP_PORT), { mode: 0o755 })
  }
  // ---- Free LLM API: your free keys behind one address, for Claude Code reviews
  let freeCheck: { ok: boolean | null; note: string; models: string[] } = { ok: null, note: '', models: [...FREELLM_MODELS] }
  const freeInfo = async (): Promise<FreeLlmInfo> => ({ ...freeConfig(), hasKey: !!getSecret(FREE_KEY), claudeCode: (await listAgents()).some((a) => a.id === 'claude' && a.installed), ...freeCheck })
  const runFreeCheck = async (): Promise<void> => {
    const key = getSecret(FREE_KEY)
    if (!key) {
      freeCheck = { ok: false, note: 'Paste the unified key from Free LLM API’s Keys page.', models: [...FREELLM_MODELS] }
      return
    }
    const r = await checkFreeLlm(freeConfig().baseUrl, key)
    freeCheck = { ok: r.ok, note: r.note, models: r.ok ? r.models : [...FREELLM_MODELS] }
  }
  handle('freellm:get', () => freeInfo())
  handle('freellm:check', async () => {
    await runFreeCheck()
    return freeInfo()
  })
  handle('freellm:save', async (o) => {
    if (!o || typeof o !== 'object') throw new ValidationError('That is not a Free LLM API setting.')
    try {
      const baseUrl = freeLlmUrl(String(o.baseUrl ?? ''))
      const model = freeLlmModel(String(o.model ?? ''))
      if (o.key === null) setSecret(FREE_KEY, null)
      else if (typeof o.key === 'string' && o.key.trim()) setSecret(FREE_KEY, checkFreeLlmKey(o.key))
      setSettings({ freellm: { baseUrl, model } })
    } catch (e) {
      throw new ValidationError((e as Error).message)
    }
    await runFreeCheck()
    if (freeCheck.ok) log('info', 'Free LLM API is connected')
    return freeInfo()
  })
  handle('webhook:set', (cfg, url) => {
    if (cfg === null) {
      setSettings({ webhook: undefined })
      setSecret('webhook-url', null)
      return integrations()
    }
    const c = cfg as { kind: HookKind; events: 'errors' | 'all' }
    if (!['slack', 'teams', 'discord', 'generic'].includes(c.kind)) throw new ValidationError('Choose Slack, Teams, Discord or another address.')
    if (typeof url === 'string' && url.trim()) {
      try {
        setSecret('webhook-url', checkHookUrl(c.kind, url))
      } catch (e) {
        throw new ValidationError((e as Error).message)
      }
    }
    if (!getSecret('webhook-url')) throw new ValidationError('Paste the webhook address.')
    setSettings({ webhook: { kind: c.kind, events: c.events === 'all' ? 'all' : 'errors' } })
    return integrations()
  })
  handle('webhook:test', async () => {
    const w = getSettings().webhook
    const url = getSecret('webhook-url')
    if (!w || !url) throw new ValidationError('Save a webhook first.')
    await sendHook(w.kind, url, hookBody(w.kind, 'MacSec', 'info', 'Test message', 'MacSec can post here.')).catch((e) => {
      throw new ValidationError((e as Error).message)
    })
  })
  handle('raycast:install', () => {
    writeCli()
    mkdirSync(raycastDir(), { recursive: true })
    for (const f of raycastScripts(cliPath(), 'MacSec')) writeFileSync(join(raycastDir(), f.file), f.text, { mode: 0o755 })
    void shell.openPath(raycastDir())
    return integrations()
  })
  if (getSettings().mcpEnabled) void startMcp().then(writeCli)
  // When a session ends: a webhook message and, when MacSec is in the background, a notification.
  finishEvents.on('finished', (info: SessionInfo) => {
    const bad = info.counts.critical + info.counts.high
    const title = info.status === 'failed' ? `${info.title} failed` : `${info.title}: ${bad ? `${info.counts.critical} critical, ${info.counts.high} high` : 'nothing serious'}`
    const body = info.status === 'failed' ? info.error : `${Object.values(info.counts).reduce((a, b) => a + b, 0)} findings. Target: ${info.target}`
    const w = getSettings().webhook
    const url = getSecret('webhook-url')
    if (w && url && (info.status === 'failed' || bad > 0 || w.events === 'all')) void sendHook(w.kind, url, hookBody(w.kind, 'MacSec', info.status === 'failed' || bad ? 'error' : 'success', title, body)).catch(() => undefined)
    if (getSettings().notifications && Notification.isSupported() && !mainWindow?.isFocused()) new Notification({ title, body: body?.slice(0, 180), silent: !bad }).show()
  })

  handle('app:check-update', () => checkForUpdate())
  handle('app:install-update', () => installUpdate((p, l) => log('info', `${l ?? 'Updating'}${p !== null ? ` ${Math.round(p)}%` : ''}`)))
  handle('sessions:get', (id) => sessionDetail(String(id)))
  handle('sessions:delete', (id) => {
    cancelSession(String(id))
    deleteSession(String(id))
    return listSessions()
  })
  handle('sessions:cancel', (id) => {
    cancelSession(String(id))
    cancelOp(String(id))
  })
  handle('web:sites', () => localSites())
  handleStart('web:start', (req) => {
    try {
      return startWebScan(validWeb(req))
    } catch (e) {
      throw new ValidationError((e as Error).message)
    }
  })
  handle('burp:open', () => openBurp())
  handleStart('audit:start', (req) => {
    const r = (req ?? {}) as { kind?: string; path?: unknown; site?: unknown; reviewer?: unknown; depth?: unknown; authorized?: unknown }
    try {
      if (r.kind === 'portfolio') return startAudit({ kind: 'portfolio' })
      if (r.kind === 'changes') return startAudit({ kind: 'changes', path: allowedProject(r.path) })
      if (r.kind === 'full') {
        const site = typeof r.site === 'string' ? r.site.trim() : ''
        if (!/^https?:\/\/[^\s]+$/.test(site)) throw new ValidationError('Enter the site’s address.')
        return startAudit({ kind: 'full', path: allowedProject(r.path), site: new URL(site).href.replace(/\/$/, ''), reviewer: pick(r.reviewer, REVIEWERS, 'claude'), depth: pick(r.depth, ['quick', 'standard', 'deep'] as const, 'standard'), authorized: r.authorized === true })
      }
      if (r.kind === 'cloud') return startAudit({ kind: 'cloud', provider: pick((r as { provider?: unknown }).provider, ['azure', 'aws'] as const, 'azure'), reviewer: pick(r.reviewer, REVIEWERS, 'none') })
      if (r.kind === 'server') {
        const host = validHost((r as { host?: unknown }).host)
        if (!isLocalHost(host) && r.authorized !== true) throw new ValidationError('Confirm that you own this server or have permission to test it.')
        return startAudit({ kind: 'server', host, ports: pick((r as { ports?: unknown }).ports, ['top100', 'top1000'] as const, 'top100'), reviewer: pick(r.reviewer, REVIEWERS, 'none'), authorized: r.authorized === true })
      }
      throw new ValidationError('Choose an audit.')
    } catch (e) {
      throw new ValidationError((e as Error).message)
    }
  })
  handle('web:login', (url) => {
    if (typeof url !== 'string' || !/^https?:\/\/[^\s]+$/.test(url)) throw new ValidationError('Enter the site’s address first.')
    return signIn(url)
  })
  handle('api:load-spec', async () => {
    if (!mainWindow) return null
    const r = await dialog.showOpenDialog(mainWindow, { title: 'Load an API description', buttonLabel: 'Load', properties: ['openFile'], filters: [{ name: 'Postman, OpenAPI, Swagger or HAR', extensions: ['json', 'yaml', 'yml', 'har'] }] })
    if (r.canceled || !r.filePaths[0]) return null
    try {
      return loadSpec(r.filePaths[0])
    } catch (e) {
      throw new ValidationError((e as Error).message)
    }
  })
  handle('mobile:pick', async (what) => {
    if (!mainWindow) return null
    const r = await dialog.showOpenDialog(mainWindow, what === 'file'
      ? { title: 'Choose a built app', buttonLabel: 'Check', properties: ['openFile'], filters: [{ name: 'Android or iOS app', extensions: ['apk', 'ipa'] }] }
      : { title: 'Choose the app’s source folder', buttonLabel: 'Check', properties: ['openDirectory'] })
    if (r.canceled || !r.filePaths[0]) return null
    const p = resolve(r.filePaths[0])
    picked.add(p)
    return p
  })
  handleStart('mobile:start', (req) => {
    const r = (req ?? {}) as { path?: unknown; reviewer?: unknown }
    try {
      return startMobileScan({ path: allowedProject(r.path), reviewer: pick(r.reviewer, REVIEWERS, 'none') })
    } catch (e) {
      throw new ValidationError((e as Error).message)
    }
  })
  handle('cloud:status', () => cloudStatus())
  handle('cloud:azure-login', async () => {
    await azureLogin().catch((e) => {
      throw new ValidationError(`Azure sign-in did not finish: ${(e as Error).message}`)
    })
    return cloudStatus()
  })
  handle('tools:optional', () => optionalTools())
  handleStart('recon:start', (req) => {
    const r = (req ?? {}) as Partial<ReconRequest>
    if (typeof r.target !== 'string') throw new ValidationError('Enter a domain, such as example.com.')
    try {
      return startRecon({ target: r.target, depth: pick(r.depth, ['passive', 'standard', 'deep'] as const, 'standard'), reviewer: pick(r.reviewer, REVIEWERS, 'none'), authorized: r.authorized === true })
    } catch (e) {
      throw new ValidationError((e as Error).message)
    }
  })
  handle('recon:data', (id) => reconData(String(id)) as never)
  handle('ai:claude-skills', (on) => {
    if (on === true) installForClaude('macsec')
    else if (on === false) removeFromClaude('macsec')
    return { installed: installedForClaude('macsec') }
  })
  handleStart('api:start', (req) => {
    try {
      return startApiScan(validApi(req))
    } catch (e) {
      throw new ValidationError((e as Error).message)
    }
  })
  handle('sessions:pdf', async (id) => {
    const out = await exportPdf(String(id))
    if (out) shell.showItemInFolder(out)
    return out
  })
  handle('sessions:discard-code', (id) => {
    const s = readSession(String(id))
    if (s.codeKept) {
      discardCode(s.id)
      s.codeKept = false
      s.codePath = undefined
      saveSession(s)
    }
    return s
  })
  handle('sessions:open', async (id, what, file, line) => {
    const s = readSession(String(id))
    const code = s.codePath && existsSync(s.codePath) ? s.codePath : null
    if (what === 'folder') return void (await shell.openPath(sessionDir(s.id)))
    if (!code) throw new ValidationError('The code for this session is no longer on this Mac.')
    // A file must be inside the reviewed code.
    if (what === 'file') {
      const p = normalize(join(code, String(file ?? '')))
      if (!p.startsWith(normalize(code) + sep)) throw new ValidationError('That file is outside the project.')
      const vscode = findCli('cursor') ?? findCli('code')
      if (vscode) return void openTerminal(code, `${shellQuote(vscode)} --goto ${shellQuote(`${p}:${line ?? 1}`)} && exit`)
      return void (await shell.openPath(p))
    }
    if (what === 'code') return void (await shell.openPath(code))
    // Continue in Claude Code or Codex in Terminal, with the report ready to read.
    const report = join(sessionDir(s.id), 'findings.json')
    const ask = `Read the security review in ${report}${existsSync(join(sessionDir(s.id), 'ai-report.md')) ? ` and ${join(sessionDir(s.id), 'ai-report.md')}` : ''}. Go through the confirmed findings, most severe first, and help me fix them one by one.`
    if (what === 'codex') return void (await openTerminal(code, `codex ${shellQuote(ask)}`))
    // The review was a normal Claude Code session: pick up that same conversation.
    if (s.claudeSession && /^[0-9a-f-]{36}$/.test(s.claudeSession)) {
      return void (await openTerminal(code, `claude --resume ${s.claudeSession} || claude ${shellQuote(ask)}`))
    }
    // Remote Control makes the same session reachable at claude.ai and in the Claude app on your
    // phone. Older Claude Code versions without it start a normal session instead.
    const name = `MacSec: ${s.title}`.slice(0, 60)
    await openTerminal(code, `claude --remote-control ${shellQuote(name)} ${shellQuote(ask)} || claude ${shellQuote(ask)}`)
  })
  sessionEvents.on('updated', (s) => {
    send('session:updated', s)
  })

  // AI
  handle('ai:agents', () => listAgents())
  handle('ai:install-agent', (id) => installAgent(id === 'codex' ? 'codex' : 'claude'))
  handle('ai:key-status', () => ({ hasKey: !!getSecret('anthropic') }))
  handle('ai:set-key', (key) => {
    const k = typeof key === 'string' ? key.trim() : ''
    if (k && !/^sk-ant-[A-Za-z0-9_-]{20,}$/.test(k)) throw new ValidationError('That does not look like an Anthropic API key (it starts with sk-ant-).')
    setSecret('anthropic', k || null)
    if (!k) setSettings({ claudeAuth: 'account' })
    return { hasKey: !!k }
  })
  handle('ai:skills', () => listSkills())
  handle('ai:open-app', async (id) => {
    const app = findApp(id === 'claude' ? 'claudeApp' : id === 'codex' ? 'codexApp' : id === 'burp' ? 'burp' : 'lmstudio')
    if (!app) throw new ValidationError('That app was not found on this Mac.')
    await shell.openPath(app)
  })
  handle('ai:detect', () => detectLlms())
  handle('ai:test', (baseUrl, model) => testLlm(String(baseUrl), String(model)))
  handle('ai:servers', () => listServers())
  handle('ai:save-server', (input) => saveServer(input))
  handle('ai:delete-server', (id) => deleteServer(String(id)))

  // Logs
  handle('logs:list', () => listLogs())
  handle('logs:clear', () => clearLogs())
  logEvents.on('line', (l) => send('logs:line', l))
  jobs.on('changed', (list) => send('jobs:changed', list))
}

app.setName('MacSec')
if (!app.requestSingleInstanceLock()) app.quit()
app.on('second-instance', () => {
  if (mainWindow) {
    if (mainWindow.isMinimized()) mainWindow.restore()
    mainWindow.focus()
  }
})

app.whenReady().then(() => {
  ensureDirs()
  const crypto = { available: () => safeStorage.isEncryptionAvailable(), encrypt: (s: string) => safeStorage.encryptString(s).toString('base64'), decrypt: (s: string) => safeStorage.decryptString(Buffer.from(s, 'base64')) }
  setSecretsCrypto(crypto)
  // Every GitHub API call uses your GitHub sign-in when you added one: 5,000 an hour instead of 60.
  configureGitHub({ userAgent: USER_AGENT, token: () => getSecret('github') })
  setModelCrypto(crypto)
  recoverSessions()
  ensureSkills()
  hardenWebContents()
  registerIpc()
  createWindow()
  log('info', `MacSec ${app.getVersion()} started`)
  // Newer scanner versions are looked for once a day and offered on the Tools page.
  // MacSec's own update: checked at start and every six hours; the window offers it.
  const appUpdate = (): void => void checkForUpdate().then((u) => u && send('app:update', u)).catch(() => undefined)
  setTimeout(appUpdate, 8000)
  setInterval(appUpdate, 6 * 3600_000)
  setTimeout(() => void checkUpdatesDaily().then((names) => names.length && send('tools:updates', names)).catch(() => undefined), 6000)
  app.on('activate', () => {
    if (!mainWindow) createWindow()
  })
})

app.on('window-all-closed', () => {
  if (!isMac) app.quit()
})
