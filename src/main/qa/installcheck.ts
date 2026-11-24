/**
 * The install harness: every tool MacSec can install is checked for the things that rot quietly.
 * The static half runs in normal CI; the live half asks GitHub for the latest release of each repo,
 * so a renamed repository or a release with no assets fails the harness before a user hits it.
 */
import type { ToolDef } from '../toolbox'
import { CATALOG } from '../toolbox'

export interface InstallIssue {
  id: string
  problem: string
}

const SLUG = /^[a-z0-9][a-z0-9-]*$/
const REPO = /^[\w.-]+\/[\w.-]+$/
const PKG = /^[a-z0-9][a-z0-9._-]*$/i
const FORMULA = /^[\w.-]+(\/[\w.-]+)*$/

/** Rules that catch a catalogue entry before it can teach a bad install. */
export function checkCatalog(list: ToolDef[] = CATALOG): InstallIssue[] {
  const out: InstallIssue[] = []
  const seen = new Set<string>()
  for (const t of list) {
    const bad = (problem: string): void => void out.push({ id: t.id, problem })
    if (!SLUG.test(t.id)) bad('the id is not a slug')
    if (seen.has(t.id)) bad('the id is used twice')
    seen.add(t.id)
    if (!t.name.trim()) bad('no name')
    if (!/^https:\/\//.test(t.homepage)) bad('the homepage is not https')
    if (t.purpose.trim().length < 20) bad('the purpose is too short to explain the tool')
    if (t.method === 'release') {
      if (!REPO.test(t.repo)) bad('the repository is not owner/name')
      if (!t.binaries.length) bad('no binary is listed')
      for (const b of t.binaries) if (!/^[\w.-]+$/.test(b)) bad(`the binary "${b}" is not a plain name`)
    } else if (t.method === 'python') {
      if (!PKG.test(t.pkg)) bad('the Python package name is not valid')
      if (!t.binaries.length) bad('no binary is listed')
    } else {
      if (!t.apps.length || t.apps.some((a) => !a.startsWith('/'))) bad('an app tool needs absolute paths')
      if (t.formula && !FORMULA.test(t.formula.name)) bad('the Homebrew formula is not a plain name')
    }
  }
  return out
}

interface Release {
  tag_name?: string
  assets?: { name: string }[]
}

/** The live half: one request per downloaded tool, with a short timeout. */
export async function checkLatestReleases(fetchImpl: typeof fetch = fetch, ids?: string[]): Promise<InstallIssue[]> {
  const tools = CATALOG.filter((t) => t.method === 'release' && (!ids || ids.includes(t.id)))
  const out: InstallIssue[] = []
  for (const t of tools) {
    if (t.method !== 'release') continue
    try {
      const res = await fetchImpl(`https://api.github.com/repos/${t.repo}/releases/latest`, {
        headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'MacSec-install-harness' },
        signal: AbortSignal.timeout(15_000)
      })
      if (!res.ok) {
        out.push({ id: t.id, problem: `GitHub answered ${res.status} for ${t.repo}` })
        continue
      }
      const r = (await res.json()) as Release
      if (!r.tag_name) out.push({ id: t.id, problem: 'the latest release has no tag' })
      if (!r.assets?.length) out.push({ id: t.id, problem: 'the latest release has no assets' })
    } catch (e) {
      out.push({ id: t.id, problem: `could not read ${t.repo}: ${(e as Error).message}` })
    }
  }
  return out
}
