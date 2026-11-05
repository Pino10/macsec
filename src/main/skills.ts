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
  // Skill packs from Trail of Bits, Sentry, Cloudflare and Anthropic, when added on the Tools page.
  for (const d of packPluginDirs(join(dirs.tools(), 'skill-packs'))) out.push('--plugin-dir', d)
  return out
}

// ---------------------------------------------------------------- Picking skills per review

import { buildSkillSet, detectStack, recommend, skillCatalog, type SkillItem, type StackTag } from './seckit/skillplan'

const packsRoot = (): string => join(dirs.tools(), 'skill-packs')

/** Every skill a review could load, the project's stack, and the ones that fit it. */
export function skillPlan(root: string | null, files = 0): { items: SkillItem[]; stack: StackTag[]; recommended: string[]; files: number } {
  ensureSkills()
  const items = skillCatalog({ app: 'MacSec', ownDir: builtinPluginDir(), mineDir: userPluginDir(), packsRoot: packsRoot() })
  const stack = root && existsSync(root) ? detectStack(root) : []
  return { items, stack, recommended: recommend(items, stack), files }
}

/** Builds a folder with only the chosen skills for one review; returns the --plugin-dir args. */
export function chosenPluginArgs(chosen: string[], outDir: string, root: string | null): { args: string[]; names: string[] } {
  const plan = skillPlan(root)
  const ids = chosen.filter((c) => plan.items.some((i) => i.id === c))
  const dirsOut = buildSkillSet(plan.items, ids.length ? ids : plan.recommended, outDir)
  const names = plan.items.filter((i) => (ids.length ? ids : plan.recommended).includes(i.id)).map((i) => i.name)
  return { args: dirsOut.flatMap((d) => ['--plugin-dir', d]), names }
}
