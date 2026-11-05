import { mkdirSync, mkdtempSync, rmSync, writeFileSync, existsSync, readdirSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { afterAll, describe, expect, it } from 'vitest'
import { afterRevoking, leakGuide } from '../src/shared/leaked'
import { fixDiff, unfence, unifiedDiff } from '../src/shared/fixdiff'
import { due, EVERY, findingKey, newSerious, readWatch, setWatch, watchedProjects } from '../src/main/watch'
import { setRoot } from '../src/main/paths'
import { buildSkillSet, detectStack, estimateMinutes, recommend, skillCatalog } from '../src/main/seckit/skillplan'
import type { Finding, SessionInfo } from '../src/shared/types'

const tmp = mkdtempSync(join(tmpdir(), 'macsec-v010-'))
afterAll(() => rmSync(tmp, { recursive: true, force: true }))

describe('I leaked a key', () => {
  it('picks the provider from what Gitleaks and TruffleHog call the key', () => {
    expect(leakGuide({ title: 'AWS Access Key in code' }).id).toBe('aws')
    expect(leakGuide({ title: 'GitHub Personal Access Token in code' }).id).toBe('github')
    expect(leakGuide({ title: 'Stripe key (confirmed live)' }).id).toBe('stripe')
    expect(leakGuide({ title: 'GCP API key in code' }).id).toBe('google')
    expect(leakGuide({ title: 'Slack token in code' }).id).toBe('slack')
    expect(leakGuide({ title: 'Anthropic API Key in code' }).id).toBe('anthropic')
    expect(leakGuide({ title: 'Private Key in code' }).id).toBe('private-key')
    expect(leakGuide({ title: 'Postgres key' }).id).toBe('database')
    expect(leakGuide({ title: 'Generic API Key in code' }).id).toBe('generic')
  })
  it('only links to https pages, and never needs the key', () => {
    for (const t of ['AWS', 'GitHub', 'Stripe', 'GCP', 'Slack', 'OpenAI', 'Anthropic', 'Twilio', 'SendGrid', 'Azure', 'GitLab']) {
      const g = leakGuide({ title: `${t} key` })
      expect(`${t}:${g.id}:${g.revokeUrl}`).toMatch(/:https:\/\//)
      expect(g.steps.length).toBeGreaterThan(0)
    }
  })
  it('explains cleaning the Git history only when the key is in it', () => {
    expect(afterRevoking(true).join(' ')).toMatch(/filter-repo/)
    expect(afterRevoking(false).join(' ')).not.toMatch(/filter-repo/)
    expect([...afterRevoking(true), ...afterRevoking(false)].join(' ')).not.toMatch(/—/)
  })
})

describe('Suggested fix as a diff', () => {
  const context = { start: 40, at: 42, lines: ['function find($id) {', '  global $db;', '  return $db->query("SELECT * FROM users WHERE id = $id");', '}', ''] }
  it('shows the flagged line replaced and keeps the lines around it', () => {
    const fix = '```php\nglobal $db;\n$stmt = $db->prepare("SELECT * FROM users WHERE id = ?");\n$stmt->execute([$id]);\nreturn $stmt->fetch();\n```'
    const d = fixDiff(context, fix)
    expect(d.filter((l) => l.kind === 'del').map((l) => l.n)).toEqual([42])
    expect(d.filter((l) => l.kind === 'add').length).toBe(3)
    // The opening and closing lines the fix left out are kept, not removed.
    expect(d.find((l) => l.n === 40)?.kind).toBe('same')
    expect(d.find((l) => l.n === 43)?.kind).toBe('same')
    // The new lines take the flagged line's place, before the closing brace.
    const kinds = d.map((l) => l.kind).join(',')
    expect(kinds).toBe('same,same,del,add,add,add,same,same')
  })
  it('shows an unrelated snippet as added lines only', () => {
    const d = fixDiff(context, 'use PDO;')
    expect(d).toEqual([{ kind: 'add', text: 'use PDO;' }])
  })
  it('strips code fences and makes a patch', () => {
    expect(unfence('```js\na()\n```')).toBe('a()')
    const p = unifiedDiff('app/User.php', fixDiff(context, 'global $db;\nreturn $db->find($id);'))
    expect(p).toMatch(/^--- a\/app\/User\.php\n\+\+\+ b\/app\/User\.php\n@@ -40,/)
    expect(p).toMatch(/\n-  return \$db->query/)
    expect(p).toMatch(/\n\+return \$db->find/)
  })
})

describe('Keeping watch', () => {
  const f = (o: Partial<Finding>): Finding => ({ id: Math.random().toString(36), tool: 'OSV-Scanner', category: 'dependency', severity: 'high', title: 'lodash 4.17.20: Prototype pollution', file: 'package-lock.json', advisory: 'CVE-2021-23337', ...o })
  it('reports only serious problems that are new, and not ones you dealt with', () => {
    const prev = [f({})]
    const next = [f({}), f({ advisory: 'CVE-2024-1', title: 'axios: SSRF' }), f({ advisory: 'CVE-2024-2', severity: 'low' }), f({ advisory: 'CVE-2024-3', triage: 'accepted' }), f({ advisory: 'CVE-2024-4', verdict: 'false-positive' })]
    expect(newSerious(prev, next).map((x) => x.advisory)).toEqual(['CVE-2024-1'])
    expect(findingKey(prev[0])).toBe('OSV-Scanner|CVE-2021-23337|package-lock.json')
  })
  it('knows when a check is due', () => {
    const now = Date.parse('2026-11-05T12:00:00Z')
    expect(due(undefined, EVERY.packages, now)).toBe(true)
    expect(due('2026-11-05T00:00:00Z', EVERY.packages, now)).toBe(false)
    expect(due('2026-11-04T11:00:00Z', EVERY.packages, now)).toBe(true)
    expect(due('2026-11-01T12:00:00Z', EVERY.retest, now)).toBe(false)
  })
  it('watches each reviewed project on this Mac once, from its newest review', () => {
    const a = join(tmp, 'shop')
    mkdirSync(a, { recursive: true })
    const s = (id: string, createdAt: string, o: Partial<SessionInfo> = {}): SessionInfo => ({ id, kind: 'code-review', title: 'shop', target: a, createdAt, status: 'done', counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, steps: [], codePath: a, ...o }) as SessionInfo
    const list = [s('old', '2026-10-01T00:00:00Z'), s('new', '2026-11-01T00:00:00Z'), s('gone', '2026-11-02T00:00:00Z', { codePath: join(tmp, 'deleted') }), s('web', '2026-11-03T00:00:00Z', { kind: 'web-scan' }), s('failed', '2026-11-04T00:00:00Z', { status: 'failed' })]
    expect(watchedProjects(list)).toEqual([{ path: a, title: 'shop', session: 'new' }])
  })
  it('keeps its switches in MacSec’s config folder: packages on, re-test off by default', () => {
    setRoot(join(tmp, 'home'))
    expect(readWatch()).toMatchObject({ packages: true, retest: false })
    setWatch({ retest: true })
    expect(readWatch()).toMatchObject({ packages: true, retest: true })
    expect(existsSync(join(tmp, 'home', 'config', 'watch.json'))).toBe(true)
  })
})

describe('Picking skills per review (shared with Laramac)', () => {
  const own = join(tmp, 'own')
  const packs = join(tmp, 'packs')
  for (const n of ['security-code-review', 'injection-catalog', 'electron-review', 'recon-methodology']) {
    mkdirSync(join(own, 'skills', n), { recursive: true })
    writeFileSync(join(own, 'skills', n, 'SKILL.md'), `---\nname: ${n}\ndescription: Reviews ${n}. More text.\n---\nBody`)
  }
  mkdirSync(join(own, '.claude-plugin'), { recursive: true })
  writeFileSync(join(own, '.claude-plugin', 'plugin.json'), '{"name":"macsec-security"}')
  it('lists the skills a review can use, without the recon ones', () => {
    const items = skillCatalog({ app: 'MacSec', ownDir: own, packsRoot: packs })
    expect(items.map((i) => i.id)).toContain('own:security-code-review')
    expect(items.map((i) => i.id)).not.toContain('own:recon-methodology')
    expect(items.find((i) => i.id === 'own:security-code-review')?.source).toBe('MacSec')
  })
  it('detects a Laravel and Electron stack and recommends what fits', () => {
    const root = join(tmp, 'app')
    mkdirSync(root, { recursive: true })
    writeFileSync(join(root, 'composer.json'), JSON.stringify({ require: { 'laravel/framework': '^11.0' } }))
    writeFileSync(join(root, 'artisan'), '')
    writeFileSync(join(root, 'package.json'), JSON.stringify({ devDependencies: { electron: '45.0.0' } }))
    const stack = detectStack(root)
    expect(stack).toEqual(expect.arrayContaining(['php', 'laravel', 'electron']))
    const items = skillCatalog({ app: 'MacSec', ownDir: own, packsRoot: packs })
    const rec = recommend(items, stack)
    expect(rec).toContain('own:electron-review')
    const out = join(tmp, 'set')
    const dirs = buildSkillSet(items, rec, out)
    expect(dirs.length).toBeGreaterThan(0)
    // Only the chosen skills are copied (here, the ones with a folder on disk).
    const copied = readdirSync(join(dirs[0], 'skills')).sort()
    expect(copied).toContain('electron-review')
    expect(copied).not.toContain('recon-methodology')
    expect(copied.every((n) => rec.includes(`own:${n}`))).toBe(true)
    // Not chosen: not copied.
    const none = buildSkillSet(items, ['own:injection-catalog'], join(tmp, 'set2'))
    expect(readdirSync(join(none[0], 'skills'))).toEqual(['injection-catalog'])
  })
  it('estimates more time for more skills and slower reviewers', () => {
    const [a] = estimateMinutes({ files: 300, skills: 4, reviewer: 'claude' })
    const [b] = estimateMinutes({ files: 300, skills: 20, reviewer: 'claude' })
    const [c] = estimateMinutes({ files: 300, skills: 4, reviewer: 'claude-local' })
    expect(b).toBeGreaterThan(a)
    expect(c).toBeGreaterThan(a)
  })
})
