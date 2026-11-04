/**
 * Skills for Claude Code. MacSec ships its own security plugin (written into
 * ~/MacSec/tools/claude-plugin) and loads it, plus your own skills from
 * ~/MacSec/extensions/claude, for MacSec's reviews only, with --plugin-dir. Nothing is
 * installed into your normal Claude Code setup.
 */
import { existsSync, mkdirSync, readdirSync, writeFileSync } from 'fs'
import { join } from 'path'
import { dirs } from './paths'
import { writePlugin } from './seckit/skills'
import { packPluginDirs } from './seckit/skillpacks'

export const builtinPluginDir = (): string => join(dirs.tools(), 'claude-plugin')
export const userPluginDir = (): string => join(dirs.extensions(), 'claude')

/** Writes the built-in plugin (refreshed every start) and creates your own skills folder. */
export function ensureSkills(): void {
  // The skills are shared with Laramac (seckit/skills.ts).
  writePlugin(builtinPluginDir(), 'macsec-security', 'MacSec security skills: code review method, secrets, dependencies, recon, JavaScript recon and reports.')
  const mine = userPluginDir()
  if (!existsSync(join(mine, '.claude-plugin', 'plugin.json'))) {
    mkdirSync(join(mine, '.claude-plugin'), { recursive: true })
    mkdirSync(join(mine, 'skills'), { recursive: true })
    writeFileSync(join(mine, '.claude-plugin', 'plugin.json'), JSON.stringify({ name: 'my-security-skills', version: '1.0.0', description: 'Your own skills for MacSec reviews.' }, null, 2))
    writeFileSync(join(mine, 'skills', 'README.md'), 'Put each skill in its own folder here, with a SKILL.md inside (name and description at the top).\nMacSec loads them into every Claude Code review.\n')
  }
}

export function listSkills(): { name: string; mine: boolean }[] {
  const read = (d: string, mine: boolean): { name: string; mine: boolean }[] => {
    try {
      return readdirSync(join(d, 'skills'))
        .filter((n) => existsSync(join(d, 'skills', n, 'SKILL.md')))
        .map((name) => ({ name, mine }))
    } catch {
      return []
    }
  }
  return [...read(builtinPluginDir(), false), ...read(userPluginDir(), true)]
}

export function pluginArgs(): string[] {
  const out: string[] = []
  if (existsSync(join(builtinPluginDir(), '.claude-plugin'))) out.push('--plugin-dir', builtinPluginDir())
  if (listSkills().some((s) => s.mine)) out.push('--plugin-dir', userPluginDir())
  // Skill packs from Trail of Bits and Sentry, when added on the Tools page.
  for (const d of packPluginDirs(join(dirs.tools(), 'skill-packs'))) out.push('--plugin-dir', d)
  return out
}
