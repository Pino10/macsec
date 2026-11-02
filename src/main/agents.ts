/**
 * The AI tools MacSec works with: Claude Code and Codex on the command line, LM Studio (or any
 * OpenAI-compatible server) for local models, and Burp Suite and ZAP as apps.
 */
import { execFile } from 'child_process'
import { existsSync, readdirSync } from 'fs'
import { homedir } from 'os'
import { join } from 'path'
import type { AgentInfo } from '../shared/types'

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

const APPS: Record<'burp' | 'zap' | 'lmstudio', string[]> = {
  burp: ['Burp Suite Professional.app', 'Burp Suite Community Edition.app'],
  zap: ['ZAP.app', 'OWASP ZAP.app'],
  lmstudio: ['LM Studio.app']
}

export function findApp(id: keyof typeof APPS): string | null {
  for (const dir of ['/Applications', join(homedir(), 'Applications')]) for (const a of APPS[id]) if (existsSync(join(dir, a))) return join(dir, a)
  return null
}

function version(bin: string): Promise<string | null> {
  return new Promise((resolve) => execFile(bin, ['--version'], { timeout: 8000 }, (_e, out) => resolve(/(\d+\.\d+\.\d+)/.exec(String(out))?.[1] ?? null)))
}

/** PATH for running Claude Code and Codex: they need the real home folder for their sign-in. */
export function agentEnv(): NodeJS.ProcessEnv {
  const extra = binDirs().join(':')
  return { ...process.env, PATH: `${extra}:${process.env.PATH ?? ''}`, NO_COLOR: '1' }
}

export async function listAgents(): Promise<AgentInfo[]> {
  await refreshShellPaths()
  const claude = findCli('claude')
  const codex = findCli('codex')
  return [
    { id: 'claude', name: 'Claude Code', installed: !!claude, path: claude, version: claude ? await version(claude) : null, role: 'Reads your whole project in read-only mode and writes the review. Continue any session in Terminal or on the web.' },
    { id: 'codex', name: 'Codex', installed: !!codex, path: codex, version: codex ? await version(codex) : null, role: 'OpenAI’s coding agent, as a second reviewer in a read-only sandbox.' },
    { id: 'lmstudio', name: 'LM Studio', installed: !!findApp('lmstudio'), path: findApp('lmstudio'), version: null, role: 'Your own models on this Mac. Nothing leaves your computer.' },
    { id: 'burp', name: 'Burp Suite', installed: !!findApp('burp'), path: findApp('burp'), version: null, role: 'For hands-on testing: MacSec opens findings and targets in it.' },
    { id: 'zap', name: 'ZAP', installed: !!findApp('zap'), path: findApp('zap'), version: null, role: 'OWASP’s web scanner. Web scan can use it for a full active scan.' }
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
