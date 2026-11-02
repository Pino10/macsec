/**
 * Everything MacSec owns lives in one folder, ~/MacSec, so nothing is scattered over the Mac:
 *
 *   tools/bin        every scanner (Semgrep, Gitleaks, Nuclei...)
 *   tools/home       a private home folder the scanners run with, so their caches, databases
 *                    and templates (which normally go to ~/.config, ~/Library/Caches or
 *                    ~/nuclei-templates) stay in here too
 *   sessions/<id>    one folder per test: its report, findings, logs and, while it exists,
 *                    the private copy of the code
 *   extensions       your own Nuclei templates, Semgrep rules and AI skills
 *   logs             what MacSec did
 */
import { homedir } from 'os'
import { join } from 'path'
import { mkdirSync } from 'fs'

let ROOT = process.env.MACSEC_HOME || join(homedir(), 'MacSec')

/** Tests point MacSec at a temporary folder. */
export function setRoot(path: string): void {
  ROOT = path
}

export const dirs = {
  root: (): string => ROOT,
  tools: (): string => join(ROOT, 'tools'),
  bin: (): string => join(ROOT, 'tools', 'bin'),
  toolHome: (): string => join(ROOT, 'tools', 'home'),
  python: (): string => join(ROOT, 'tools', 'python'),
  downloads: (): string => join(ROOT, 'tools', 'downloads'),
  sessions: (): string => join(ROOT, 'sessions'),
  session: (id: string): string => join(ROOT, 'sessions', id),
  extensions: (): string => join(ROOT, 'extensions'),
  logs: (): string => join(ROOT, 'logs'),
  config: (): string => join(ROOT, 'config')
}

export function ensureDirs(): void {
  for (const d of [dirs.bin(), dirs.toolHome(), dirs.downloads(), dirs.sessions(), dirs.logs(), dirs.config()]) {
    mkdirSync(d, { recursive: true, mode: 0o700 })
  }
  for (const sub of ['nuclei-templates', 'semgrep-rules', 'skills', 'wordlists']) {
    mkdirSync(join(dirs.extensions(), sub), { recursive: true })
  }
}
