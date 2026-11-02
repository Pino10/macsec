import { app, BrowserWindow, dialog, ipcMain, safeStorage, session, shell, type IpcMainInvokeEvent } from 'electron'
import { existsSync, mkdirSync, writeFileSync } from 'fs'
import { join, normalize, resolve, sep } from 'path'
import { pathToFileURL } from 'url'
import { release } from 'os'
import type { ApiScanRequest, Channels, Events, ReviewRequest, ScanMode, WebScanRequest } from '../shared/types'
import { dirs, ensureDirs } from './paths'
import { getSettings, setSettings } from './settings'
import { setSecretsCrypto } from './secrets'
import { setModelCrypto, detectLlms, testLlm, listServers, saveServer, deleteServer } from './models'
import { jobs } from './jobs'
import { log, logEvents, listLogs, clearLogs } from './logs'
import { checkUpdates, checkUpdatesDaily, installTool, listTools, removeTool, toolDef, updateToolData } from './toolbox'
import { localSites, startWebScan } from './webscan'
import { loadSpec, startApiScan } from './apiscan'
import { cancelOp } from './engine'
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

/** No navigation away, no popups, no webviews, no permissions. */
function hardenWebContents(): void {
  app.on('web-contents-created', (_e, contents) => {
    contents.on('will-navigate', (event, url) => {
      if (!isAppUrl(url)) event.preventDefault()
    })
    contents.on('will-attach-webview', (event) => event.preventDefault())
    contents.setWindowOpenHandler(({ url }) => {
      if (isWebUrl(url)) void shell.openExternal(url)
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
const REVIEWERS = ['none', 'claude', 'codex', 'model'] as const

function validWeb(req: unknown): WebScanRequest {
  const r = (req ?? {}) as Partial<WebScanRequest>
  const t = r.target as WebScanRequest['target'] | undefined
  let target: WebScanRequest['target']
  if (t?.kind === 'local' && typeof t.name === 'string') target = { kind: 'local', name: t.name }
  else if (t?.kind === 'url' && typeof t.url === 'string' && /^https?:\/\/[^\s'"<>]+$/.test(t.url.trim())) target = { kind: 'url', url: new URL(t.url.trim()).href }
  else throw new ValidationError('Enter the address to scan, starting with http:// or https://.')
  return { target, mode: pick<ScanMode>(r.mode, MODES, 'standard'), authorized: r.authorized === true, headers: typeof r.headers === 'string' ? r.headers.slice(0, 4000) : undefined, reviewer: pick(r.reviewer, REVIEWERS, 'none') }
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
  handle('review:start', (req) => startReview(validReview(req)))
  handle('sessions:list', () => listSessions())
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
  handle('web:start', (req) => {
    try {
      return startWebScan(validWeb(req))
    } catch (e) {
      throw new ValidationError((e as Error).message)
    }
  })
  handle('burp:open', () => openBurp())
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
  handle('api:start', (req) => {
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
  setModelCrypto(crypto)
  recoverSessions()
  hardenWebContents()
  registerIpc()
  createWindow()
  log('info', `MacSec ${app.getVersion()} started`)
  // Newer scanner versions are looked for once a day and offered on the Tools page.
  setTimeout(() => void checkUpdatesDaily().then((names) => names.length && send('tools:updates', names)).catch(() => undefined), 6000)
  app.on('activate', () => {
    if (!mainWindow) createWindow()
  })
})

app.on('window-all-closed', () => {
  if (!isMac) app.quit()
})
