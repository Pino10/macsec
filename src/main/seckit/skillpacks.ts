/**
 * Skill packs from the internet, shared by Laramac and MacSec (keep both copies of src/main/seckit
 * the same). A pack is a public GitHub repository of Claude Code skills from a security team or a
 * framework's own authors (Laravel). Only free, openly licensed skills are listed.
 * The app clones it into its own folder (never anywhere else), records the exact commit, and loads
 * the security skills from it into Claude Code reviews with --plugin-dir. Reviews stay read-only:
 * plan mode with only Read, Grep, Glob and Skill, whatever a skill asks for.
 *
 * Only the packs listed here can be installed, so a review never loads instructions from an
 * address someone typed in.
 */
import { execFile } from 'child_process'
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'fs'
import { join } from 'path'

export interface SkillPack {
  id: string
  name: string
  repo: string
  license: string
  about: string
  /**
   * plugins: each folder in plugins/ is a Claude Code plugin. skills: skills/<name>/SKILL.md.
   * commands: .claude/commands/<name>.md, Claude Code slash commands, loaded as a command and as a skill.
   */
  layout: 'plugins' | 'skills' | 'commands'
  /** The security-related plugins or skills that reviews load. */
  pick: string[]
  /** For the skills layout: where a skill is in the repository, when not skills/<name>. */
  paths?: Record<string, string>
}

export const SKILL_PACKS: SkillPack[] = [
  {
    id: 'trailofbits',
    name: 'Trail of Bits',
    repo: 'trailofbits/skills',
    license: 'CC BY-SA 4.0',
    about: 'From the security research firm: audit context building, entry points, differential review, variant analysis, false-positive checks, insecure defaults, sharp edges, supply chain risk, GitHub Actions with AI agents, Firebase apps, and their Application Security Testing Handbook.',
    layout: 'plugins',
    pick: [
      'audit-context-building',
      'entry-point-analyzer',
      'differential-review',
      'variant-analysis',
      'fp-check',
      'insecure-defaults',
      'sharp-edges',
      'supply-chain-risk-auditor',
      'agentic-actions-auditor',
      'firebase-apk-scanner',
      'vulnerability-triage-brocards',
      'static-analysis',
      'testing-handbook-skills',
      'spec-to-code-compliance',
      'second-opinion',
      'review-walkthrough',
      'post-patch-validation',
      'c-review',
      'rust-review',
      'zeroize-audit',
      'constant-time-analysis',
      'building-secure-contracts'
    ]
  },
  {
    id: 'sentry',
    name: 'Sentry',
    repo: 'getsentry/skills',
    license: 'Apache 2.0',
    about: 'From Sentry’s engineering team: security review based on the OWASP Cheat Sheets, bug finding, GitHub Actions security, Django access control, secrets in serialised data and security models.',
    layout: 'skills',
    pick: ['security-review', 'find-bugs', 'code-review', 'gha-security-review', 'django-access-review', 'secret-serialization', 'security-model', 'claude-settings-audit']
  },
  {
    id: 'cloudflare',
    name: 'Cloudflare',
    repo: 'cloudflare/security-audit-skill',
    license: 'MIT',
    about: 'Cloudflare’s security audit: reconnaissance, hunting by attack class (web and auth, client side, cloud and deployment, data isolation, supply chain, AI and LLM apps, desktop and local IPC, protocols, memory safety, resource exhaustion) and checked, evidence-backed findings.',
    layout: 'skills',
    pick: ['security-audit']
  },
  {
    id: 'laravel',
    name: 'Laravel',
    repo: 'laravel/boost',
    license: 'MIT',
    about: 'Laravel’s own agent skills, from Laravel Boost: Laravel best practices with a rule for each topic (security and authorization, Eloquent and N+1 queries, validation, queues, caching, routing, migrations, error handling), Tailwind CSS 4, and feature flags with Pennant. Free; the paid Flux UI Pro and Laravel Cloud skills are left out.',
    layout: 'skills',
    pick: ['laravel-best-practices', 'tailwindcss-development', 'pennant-development'],
    paths: {
      'laravel-best-practices': '.ai/laravel/skill/laravel-best-practices',
      'tailwindcss-development': '.ai/tailwindcss/4/skill/tailwindcss-development',
      'pennant-development': '.ai/pennant/skill/pennant-development'
    }
  },
  {
    id: 'anthropic',
    name: 'Anthropic',
    repo: 'anthropics/claude-code-security-review',
    license: 'MIT',
    about: 'Anthropic’s /security-review: a senior security engineer’s review of your changes that only reports high-confidence problems and filters out the usual false positives. Use it as /security-review in Claude Code too.',
    layout: 'commands',
    pick: ['security-review']
  }
]

export interface PackState {
  id: string
  installed: boolean
  commit: string | null
  at: string | null
  /** The plugins or skills found and loaded. */
  loaded: string[]
}

const packDir = (root: string, id: string): string => join(root, id)
const repoDir = (root: string, id: string): string => join(packDir(root, id), 'repo')
const stateFile = (root: string, id: string): string => join(packDir(root, id), 'state.json')
/** A skill's folder inside a pack's repository. */
const skillPath = (pack: SkillPack, repo: string, n: string): string => join(repo, pack.paths?.[n] ?? join('skills', n))
const known = (id: string): SkillPack => {
  const p = SKILL_PACKS.find((x) => x.id === id)
  if (!p) throw new Error('That skill pack is not on the list.')
  return p
}

/** What a pack provides once cloned: plugin folders, by name. */
export function packContents(pack: SkillPack, repo: string): string[] {
  if (pack.layout === 'plugins') return pack.pick.filter((n) => existsSync(join(repo, 'plugins', n, '.claude-plugin', 'plugin.json')) || existsSync(join(repo, 'plugins', n, 'skills')))
  if (pack.layout === 'commands') return pack.pick.filter((n) => existsSync(join(repo, '.claude', 'commands', `${n}.md`)))
  return pack.pick.filter((n) => existsSync(join(skillPath(pack, repo, n), 'SKILL.md')))
}

/**
 * Turns a Claude Code slash command into a skill. Commands run shell lines written as !`...`
 * before the model sees them; a skill cannot, so those become plain instructions to read the
 * same information with the tools a read-only review has. The command's own allowed-tools line
 * is dropped: the review decides what the agent may use.
 */
export function commandToSkill(md: string, name: string, pack: string): string {
  const fm = /^---\n([\s\S]*?)\n---\n?/.exec(md)
  const description = (fm && /^description:\s*(.+)$/m.exec(fm[1])?.[1].trim()) || `The ${name} command`
  let body = fm ? md.slice(fm[0].length) : md
  body = body.replace(/```\s*\n!`([^`]+)`\s*\n```/g, (_m, cmd: string) => `(Find this yourself: the output of \`${cmd.trim()}\`. If you cannot run commands, read the files involved and any diff or change list you were given.)`)
  body = body.replace(/!`([^`]+)`/g, (_m, cmd: string) => `the output of \`${cmd.trim()}\``)
  return `---\nname: ${name}\ndescription: ${description.replace(/\n/g, ' ')} (from ${pack}). When no branch or diff is given, review the files you were asked to review.\n---\n\n${body.trim()}\n`
}

export function packState(root: string, id: string): PackState {
  try {
    const s = JSON.parse(readFileSync(stateFile(root, id), 'utf8')) as PackState
    return { ...s, installed: existsSync(repoDir(root, id)) }
  } catch {
    return { id, installed: false, commit: null, at: null, loaded: [] }
  }
}

function git(args: string[], cwd: string): Promise<string> {
  return new Promise((resolve, reject) =>
    execFile('git', args, { cwd, timeout: 180_000, maxBuffer: 8 * 1024 * 1024, env: { ...process.env, GIT_TERMINAL_PROMPT: '0' } }, (err, out, errOut) => (err ? reject(new Error(String(errOut || err.message).trim().split('\n').pop())) : resolve(String(out).trim())))
  )
}

/** Wraps a skills/ or commands layout as one Claude Code plugin, with only the chosen skills. */
function wrapSkills(pack: SkillPack, root: string, names: string[]): void {
  const plugin = join(packDir(root, pack.id), 'plugin')
  rmSync(plugin, { recursive: true, force: true })
  mkdirSync(join(plugin, '.claude-plugin'), { recursive: true })
  writeFileSync(join(plugin, '.claude-plugin', 'plugin.json'), JSON.stringify({ name: `${pack.id}-security`, description: `${pack.name} security skills (${pack.license}), from github.com/${pack.repo}`, version: '1.0.0' }, null, 2))
  for (const n of names) {
    if (pack.layout === 'commands') {
      const md = readFileSync(join(repoDir(root, pack.id), '.claude', 'commands', `${n}.md`), 'utf8')
      mkdirSync(join(plugin, 'commands'), { recursive: true })
      writeFileSync(join(plugin, 'commands', `${n}.md`), md)
      // Sentry has a security-review skill too, so the skill carries the pack's name.
      const skill = `${pack.id}-${n}`
      mkdirSync(join(plugin, 'skills', skill), { recursive: true })
      writeFileSync(join(plugin, 'skills', skill, 'SKILL.md'), commandToSkill(md, skill, `${pack.name}, ${pack.license}`))
    } else cpSync(skillPath(pack, repoDir(root, pack.id), n), join(plugin, 'skills', n), { recursive: true })
  }
}

/** Clones (or refreshes) a pack into the app's folder and records the commit. */
export async function installPack(root: string, id: string): Promise<PackState> {
  const pack = known(id)
  const dir = packDir(root, id)
  mkdirSync(dir, { recursive: true })
  const staging = join(dir, 'repo.new')
  rmSync(staging, { recursive: true, force: true })
  await git(['clone', '--depth', '1', '--single-branch', `https://github.com/${pack.repo}.git`, staging], dir)
  const commit = await git(['rev-parse', 'HEAD'], staging)
  // Git's own files are not needed to load skills.
  rmSync(join(staging, '.git'), { recursive: true, force: true })
  rmSync(repoDir(root, id), { recursive: true, force: true })
  cpSync(staging, repoDir(root, id), { recursive: true })
  rmSync(staging, { recursive: true, force: true })
  const loaded = packContents(pack, repoDir(root, id))
  if (pack.layout !== 'plugins') wrapSkills(pack, root, loaded)
  const state: PackState = { id, installed: true, commit, at: new Date().toISOString(), loaded }
  writeFileSync(stateFile(root, id), JSON.stringify(state, null, 2))
  return state
}

export function removePack(root: string, id: string): void {
  known(id)
  rmSync(packDir(root, id), { recursive: true, force: true })
}

/** Every plugin folder from installed packs, for Claude Code's --plugin-dir. */
export function packPluginDirs(root: string): string[] {
  const out: string[] = []
  for (const pack of SKILL_PACKS) {
    const st = packState(root, pack.id)
    if (!st.installed) continue
    if (pack.layout === 'plugins') for (const n of st.loaded) out.push(join(repoDir(root, pack.id), 'plugins', n))
    else if (existsSync(join(packDir(root, pack.id), 'plugin'))) out.push(join(packDir(root, pack.id), 'plugin'))
  }
  return out
}

/** The skill folders (each with a SKILL.md) inside installed packs, for copying into ~/.claude/skills. */
export function packSkillFolders(root: string): { name: string; dir: string }[] {
  const out: { name: string; dir: string }[] = []
  for (const dir of packPluginDirs(root)) {
    const skills = join(dir, 'skills')
    if (!existsSync(skills)) continue
    for (const n of readdirSync(skills)) if (existsSync(join(skills, n, 'SKILL.md'))) out.push({ name: n, dir: join(skills, n) })
  }
  // Two packs can use the same name (Sentry's and Anthropic's security-review): the first one keeps it.
  return out.filter((f, i) => out.findIndex((g) => g.name === f.name) === i)
}
