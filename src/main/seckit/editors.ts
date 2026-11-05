/**
 * Code editors and IDEs: which ones are on this Mac, and how to open a folder or a file at a line
 * in each. Shared by Laramac and MacSec (keep both copies of src/main/seckit the same).
 *
 * The person picks one; "auto" uses the first one found, in the order below. Any other app can be
 * chosen with "Choose another app", which is opened with macOS's own `open -a`.
 */
import { execFile } from 'child_process'
import { existsSync, readdirSync } from 'fs'
import { homedir } from 'os'
import { basename, join } from 'path'

type Kind = 'vscode' | 'jetbrains' | 'zed' | 'sublime' | 'xcode' | 'plain'

export interface EditorDef {
  id: string
  name: string
  /** App bundle names, without .app. */
  apps: string[]
  kind: Kind
  /** For VS Code and its relatives: the command inside the bundle. */
  cli?: string
}

/** In the order "auto" tries them. */
export const EDITORS: EditorDef[] = [
  { id: 'vscode', name: 'VS Code', apps: ['Visual Studio Code'], kind: 'vscode', cli: 'Contents/Resources/app/bin/code' },
  { id: 'cursor', name: 'Cursor', apps: ['Cursor'], kind: 'vscode', cli: 'Contents/Resources/app/bin/cursor' },
  { id: 'windsurf', name: 'Windsurf', apps: ['Windsurf'], kind: 'vscode', cli: 'Contents/Resources/app/bin/windsurf' },
  { id: 'zed', name: 'Zed', apps: ['Zed', 'Zed Preview'], kind: 'zed' },
  { id: 'phpstorm', name: 'PhpStorm', apps: ['PhpStorm'], kind: 'jetbrains' },
  { id: 'webstorm', name: 'WebStorm', apps: ['WebStorm'], kind: 'jetbrains' },
  { id: 'intellij', name: 'IntelliJ IDEA', apps: ['IntelliJ IDEA', 'IntelliJ IDEA Ultimate', 'IntelliJ IDEA CE', 'IntelliJ IDEA Community Edition'], kind: 'jetbrains' },
  { id: 'pycharm', name: 'PyCharm', apps: ['PyCharm', 'PyCharm Professional Edition', 'PyCharm CE', 'PyCharm Community Edition'], kind: 'jetbrains' },
  { id: 'goland', name: 'GoLand', apps: ['GoLand'], kind: 'jetbrains' },
  { id: 'rustrover', name: 'RustRover', apps: ['RustRover'], kind: 'jetbrains' },
  { id: 'rider', name: 'Rider', apps: ['Rider'], kind: 'jetbrains' },
  { id: 'fleet', name: 'Fleet', apps: ['Fleet'], kind: 'plain' },
  { id: 'sublime', name: 'Sublime Text', apps: ['Sublime Text'], kind: 'sublime' },
  { id: 'vscode-insiders', name: 'VS Code Insiders', apps: ['Visual Studio Code - Insiders'], kind: 'vscode', cli: 'Contents/Resources/app/bin/code-insiders' },
  { id: 'vscodium', name: 'VSCodium', apps: ['VSCodium'], kind: 'vscode', cli: 'Contents/Resources/app/bin/codium' },
  { id: 'kiro', name: 'Kiro', apps: ['Kiro'], kind: 'vscode', cli: 'Contents/Resources/app/bin/kiro' },
  { id: 'antigravity', name: 'Antigravity', apps: ['Antigravity'], kind: 'vscode', cli: 'Contents/Resources/app/bin/antigravity' },
  { id: 'trae', name: 'Trae', apps: ['Trae'], kind: 'vscode', cli: 'Contents/Resources/app/bin/trae' },
  { id: 'void', name: 'Void', apps: ['Void'], kind: 'vscode', cli: 'Contents/Resources/app/bin/void' },
  { id: 'nova', name: 'Nova', apps: ['Nova'], kind: 'plain' },
  { id: 'bbedit', name: 'BBEdit', apps: ['BBEdit'], kind: 'plain' },
  { id: 'textmate', name: 'TextMate', apps: ['TextMate'], kind: 'plain' },
  { id: 'xcode', name: 'Xcode', apps: ['Xcode'], kind: 'xcode' }
]

export interface FoundEditor {
  id: string
  name: string
  /** The .app bundle. */
  app: string
}

/** Where apps live: the Applications folders, and JetBrains Toolbox's own. */
export function appFolders(home = homedir()): string[] {
  const toolbox = join(home, 'Applications', 'JetBrains Toolbox')
  return ['/Applications', join(home, 'Applications'), toolbox, '/Applications/Setapp']
}

/** Every known editor that is installed, found by name in the given folders (and any extra bundle paths, from Spotlight). */
export function findEditors(folders = appFolders(), extra: string[] = [], exists: (p: string) => boolean = existsSync): FoundEditor[] {
  const out: FoundEditor[] = []
  const byName = new Map<string, string>()
  for (const p of extra) if (p.endsWith('.app')) byName.set(basename(p, '.app'), p)
  for (const e of EDITORS) {
    let app: string | undefined
    for (const name of e.apps) {
      app = folders.map((f) => join(f, `${name}.app`)).find((p) => exists(p)) ?? byName.get(name)
      if (app) break
    }
    if (app) out.push({ id: e.id, name: e.name, app })
  }
  return out
}

/** Spotlight's list of every app bundle, for editors installed somewhere unusual. Empty if Spotlight is off. */
export function spotlightApps(): Promise<string[]> {
  return new Promise((resolve) =>
    execFile('/usr/bin/mdfind', ["kMDItemContentType == 'com.apple.application-bundle'"], { timeout: 8000, maxBuffer: 16 * 1024 * 1024 }, (err, out) => resolve(err ? [] : String(out).split('\n').filter(Boolean)))
  )
}

export async function installedEditors(): Promise<FoundEditor[]> {
  const quick = findEditors()
  // Spotlight only when something might be elsewhere; it is the slow part.
  const extra = await spotlightApps()
  const all = findEditors(appFolders(), extra)
  return all.length >= quick.length ? all : quick
}

/** The editor to use: the one chosen when it is still installed, otherwise the first one found. */
export function pickEditor(choice: string | undefined, found: FoundEditor[]): FoundEditor | null {
  return found.find((f) => f.id === choice) ?? found[0] ?? null
}

export interface OpenCommand {
  bin: string
  args: string[]
}

/**
 * How to open a folder, or a file at a line. VS Code and its relatives, Zed and Sublime Text use
 * their own command (which can jump to a line); JetBrains IDEs take --line; Xcode uses xed;
 * everything else is opened with `open -a`.
 */
export function openCommand(def: EditorDef | null, app: string, path: string, line?: number): OpenCommand[] {
  const plain: OpenCommand = { bin: '/usr/bin/open', args: ['-a', app, path] }
  const at = line && line > 0 ? Math.floor(line) : undefined
  switch (def?.kind) {
    case 'vscode': {
      const cli = join(app, def.cli ?? '')
      return [{ bin: cli, args: at ? ['--goto', `${path}:${at}`] : ['--new-window', path] }, plain]
    }
    case 'zed':
      return [{ bin: join(app, 'Contents', 'MacOS', 'cli'), args: [at ? `${path}:${at}` : path] }, plain]
    case 'sublime':
      return [{ bin: join(app, 'Contents', 'SharedSupport', 'bin', 'subl'), args: [at ? `${path}:${at}` : path] }, plain]
    case 'jetbrains':
      return [{ bin: '/usr/bin/open', args: ['-na', app, '--args', ...(at ? ['--line', String(at)] : []), path] }]
    case 'xcode':
      return [{ bin: '/usr/bin/xed', args: [...(at ? ['--line', String(at)] : []), path] }, plain]
    default:
      return [plain]
  }
}

/** Tries each way of opening in turn. */
export function runOpen(cmds: OpenCommand[]): Promise<void> {
  return new Promise((resolve, reject) => {
    const next = (i: number): void => {
      if (i >= cmds.length) return reject(new Error('The editor could not be opened.'))
      const c = cmds[i]
      if (c.bin !== '/usr/bin/open' && c.bin !== '/usr/bin/xed' && !existsSync(c.bin)) return next(i + 1)
      execFile(c.bin, c.args, { timeout: 15000 }, (err) => (err ? next(i + 1) : resolve()))
    }
    next(0)
  })
}

/** Opens `path` (and a line) in the chosen editor, or the custom app, or the first editor found. */
export async function openInEditorOf(o: { choice?: string; customApp?: string | null; path: string; line?: number; found?: FoundEditor[] }): Promise<string> {
  if (o.choice === 'custom' && o.customApp && existsSync(o.customApp)) {
    await runOpen(openCommand(null, o.customApp, o.path, o.line))
    return basename(o.customApp, '.app')
  }
  const found = o.found ?? findEditors()
  const pick = pickEditor(o.choice, found)
  if (!pick) throw new Error('No code editor was found. Install VS Code (or any editor), or choose one in Settings.')
  await runOpen(openCommand(EDITORS.find((e) => e.id === pick.id) ?? null, pick.app, o.path, o.line))
  return pick.name
}

/** For the settings: true for a known editor id, 'auto' or 'custom'. */
export const isEditorChoice = (v: unknown): v is string => typeof v === 'string' && (v === 'auto' || v === 'custom' || EDITORS.some((e) => e.id === v))

/** For tests and the custom picker: an .app bundle path. */
export const isAppBundle = (p: unknown): p is string => typeof p === 'string' && /^\/.+\.app\/?$/.test(p) && !p.includes('..')

/** Lists bundles in a folder, for tests. */
export const listApps = (dir: string): string[] => (existsSync(dir) ? readdirSync(dir).filter((n) => n.endsWith('.app')) : [])
