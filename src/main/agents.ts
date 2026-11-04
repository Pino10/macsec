/**
 * The AI tools MacSec works with: Claude Code and Codex on the command line, LM Studio (or any
 * OpenAI-compatible server) for local models, and Burp Suite and ZAP as apps.
 */
import { execFile } from 'child_process'
import { existsSync, readdirSync } from 'fs'
import { homedir } from 'os'
import { join } from 'path'
import type { AgentInfo } from '../shared/types'
import { getSettings } from './settings'
import { getSecret } from './secrets'

function binDirs(): string[] {
  const h = homedir()
  const out = [join(h, '.local', 'bin'), join(h, '.claude', 'local'), '/opt/homebrew/bin', '/usr/local/bin', join(h, '.npm-global', 'bin'), join(h, '.bun', 'bin'), join(h, '.volta', 'bin'), '/usr/bin']
  for (const base of [join(h, '.nvm', 'versions', 'node'), join(h, '.laramac', 'runtimes', 'node')]) {
    try {
      for (const v of readdirSync(base)) out.push(join(base, v, 'bin'))
    } catch {
      /* not installed */
    }
  }
  return out
}

let shellFound: { at: number; map: Map<string, string> } | null = null

/** Your login shell knows PATH entries no fixed list can; asked at most once a minute. */
export function refreshShellPaths(): Promise<void> {
  if (shellFound && Date.now() - shellFound.at < 60_000) return Promise.resolve()
  const sh = process.env.SHELL && /^\/[\w/.-]+$/.test(process.env.SHELL) ? process.env.SHELL : '/bin/zsh'
  return new Promise((resolve) =>
    execFile(sh, ['-ilc', `for c in claude codex node npm; do p=$(command -v "$c" 2>/dev/null) && printf '%s\\t%s\\n' "$c" "$p"; done`], { timeout: 5000 }, (_e, out) => {
      const map = new Map<string, string>()
      for (const line of String(out ?? '').split('\n')) {
        const [n, p] = line.split('\t')
        if (n && p?.startsWith('/') && existsSync(p)) map.set(n, p)
      }
      shellFound = { at: Date.now(), map }
      resolve()
    })
  )
}

export function findCli(name: string): string | null {
  for (const d of binDirs()) if (existsSync(join(d, name))) return join(d, name)
  return shellFound?.map.get(name) ?? null
}

const APPS = {
  burp: /^Burp Suite( Professional| Community Edition| Enterprise.*)?\.app$/i,
  lmstudio: /^LM Studio\.app$/i,
  claudeApp: /^Claude\.app$/i,
  codexApp: /^Codex\.app$/i
}
const SPOTLIGHT: Record<keyof typeof APPS, string> = {
  burp: "kMDItemFSName == 'Burp Suite*.app'c",
  lmstudio: "kMDItemFSName == 'LM Studio.app'",
  claudeApp: "kMDItemCFBundleIdentifier == 'com.anthropic.claudefordesktop'",
  codexApp: "kMDItemFSName == 'Codex.app'"
}

const found = new Map<string, string | null>()

/** Looks in the Applications folders, then asks Spotlight (apps can live anywhere). */
export function findApp(id: keyof typeof APPS): string | null {
  for (const dir of ['/Applications', join(homedir(), 'Applications'), '/Applications/Utilities']) {
    try {
      const hit = readdirSync(dir).find((n) => APPS[id].test(n))
      if (hit) return join(dir, hit)
    } catch {
      /* folder missing */
    }
  }
  return found.get(id) ?? null
}

export function refreshApps(): Promise<void> {
  return Promise.all(
    (Object.keys(APPS) as (keyof typeof APPS)[]).map(
      (id) =>
        new Promise<void>((resolve) =>
          execFile('mdfind', [SPOTLIGHT[id]], { timeout: 5000 }, (_e, out) => {
            const hit = String(out ?? '')
              .split('\n')
              .find((p) => p.endsWith('.app') && !p.includes('/Trash/') && existsSync(p))
            found.set(id, hit ?? null)
            resolve()
          })
        )
    )
  ).then(() => undefined)
}

/** Opens Burp Suite (or brings it forward). */
export function openBurp(): Promise<void> {
  const app = findApp('burp')
  if (!app) return Promise.reject(new Error('Burp Suite was not found on this Mac.'))
  return new Promise((resolve, reject) => execFile('open', [app], (e) => (e ? reject(e) : resolve())))
}

function version(bin: string): Promise<string | null> {
  return new Promise((resolve) => execFile(bin, ['--version'], { timeout: 8000 }, (_e, out) => resolve(/(\d+\.\d+\.\d+)/.exec(String(out))?.[1] ?? null)))
}

/** PATH for running Claude Code and Codex: they need the real home folder for their sign-in. */
export function agentEnv(): NodeJS.ProcessEnv {
  const extra = binDirs().join(':')
  const env: NodeJS.ProcessEnv = { ...process.env, PATH: `${extra}:${process.env.PATH ?? ''}`, NO_COLOR: '1' }
  // With "API key" chosen, Claude Code uses the key from the Keychain instead of your sign-in.
  if (getSettings().claudeAuth === 'key') {
    const key = getSecret('anthropic')
    if (key) env.ANTHROPIC_API_KEY = key
  } else delete env.ANTHROPIC_API_KEY
  return env
}

export async function listAgents(): Promise<AgentInfo[]> {
  await Promise.all([refreshShellPaths(), refreshApps()])
  const claude = findCli('claude')
  const codex = findCli('codex')
  const claudeApp = findApp('claudeApp')
  const burp = findApp('burp')
  return [
    {
      id: 'claude',
      name: 'Claude Code',
      installed: !!claude,
      path: claude,
      version: claude ? await version(claude) : null,
      app: claudeApp,
      role: claude
        ? 'Reviews your whole project in read-only mode. Sessions continue in Terminal, the Claude app, or on the web.'
        : claudeApp
          ? 'The Claude desktop app is installed. Reviews also need Claude Code’s command line tool: install it once, and it uses the same account.'
          : 'Reviews your whole project in read-only mode.'
    },
    { id: 'codex', name: 'Codex', installed: !!codex, path: codex, version: codex ? await version(codex) : null, app: findApp('codexApp'), role: 'OpenAI’s coding agent, as a second reviewer in a read-only sandbox.' },
    { id: 'gemini', name: 'Gemini CLI', installed: !!findCli('gemini'), path: findCli('gemini'), version: findCli('gemini') ? await version(findCli('gemini')!) : null, app: null, role: 'Google’s coding agent, as another reviewer, in read-only plan mode. Install with npm install -g @google/gemini-cli.' },
    { id: 'lmstudio', name: 'LM Studio', installed: !!findApp('lmstudio'), path: findApp('lmstudio'), version: null, app: findApp('lmstudio'), role: 'Your own models on this Mac. Nothing leaves your computer.' },
    {
      id: 'burp',
      name: burp && /Professional/i.test(burp) ? 'Burp Suite Professional' : 'Burp Suite',
      installed: !!burp,
      path: burp,
      version: null,
      app: burp,
      role: 'For hands-on testing. Open any web or API finding in Burp to look closer.'
    }
  ]
}

const applescript = (s: string): string => s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
export const shellQuote = (s: string): string => `'${s.replace(/'/g, `'\\''`)}'`

/** Opens Terminal in a folder and runs a command there, where you can see and answer it. */
export function openTerminal(cwd: string, command?: string): Promise<void> {
  const line = applescript([`cd ${shellQuote(cwd)}`, ...(command ? [command] : [])].join(' && '))
  return new Promise((resolve, reject) =>
    execFile('osascript', ['-e', `tell application "Terminal"\nactivate\ndo script "${line}"\nend tell`], (err, _o, stderr) => (err ? reject(new Error(String(stderr) || err.message)) : resolve()))
  )
}

/** Installs Claude Code or Codex with their official installers, in Terminal so you see it happen. */
export function installAgent(id: 'claude' | 'codex'): Promise<void> {
  const cmd = id === 'claude' ? 'curl -fsSL https://claude.ai/install.sh | bash && echo && echo "Done. Run: claude   (once, to sign in)"' : 'npm install -g @openai/codex && echo && echo "Done. Run: codex   (once, to sign in)"'
  return openTerminal(homedir(), cmd)
}
