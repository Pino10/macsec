import { spawnSync } from 'child_process'
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
import { changedFiles, checkCitations, deepClaudeArgs, deepFindingsFromJson, deepHandoffPrompt, deepMarkdown, deepPlan, deepPrompt, engineList, readDeepResults, treeSignature, validateFindings } from '../src/main/seckit/deepaudit'

const fx = join(__dirname, 'fixtures', 'v12', 'cloudflare')
const schemaPath = join(fx, 'report-schema.json')
const schema = JSON.parse(readFileSync(schemaPath, 'utf8'))
const rec = (n: string): Record<string, any> => JSON.parse(readFileSync(join(fx, `${n}.json`), 'utf8'))
const tmp = (p: string): string => mkdtempSync(join(tmpdir(), p))

/** Cloudflare's own validator, run as they ship it: the app's check must agree with it. */
const theirs = (doc: unknown): boolean => {
  const f = join(tmp('cf-doc-'), 'findings.json')
  writeFileSync(f, JSON.stringify(doc))
  return spawnSync(process.execPath, [join(fx, 'validate-findings.cjs'), f], { encoding: 'utf8' }).status === 0
}

describe('the findings check agrees with Cloudflare’s own validator', () => {
  const good = (): unknown[] => [rec('confirmed'), rec('needs_validation'), rec('rejected')]
  it('accepts their example records', () => {
    expect(theirs(good())).toBe(true)
    expect(validateFindings(good(), schema)).toEqual([])
  })
  const mutations: [string, (d: any[]) => void][] = [
    ['a missing required field', (d) => delete d[0].root_cause],
    ['an empty title', (d) => (d[0].title = '')],
    ['an unknown verdict', (d) => (d[1].verdict = 'maybe')],
    ['a bad severity word', (d) => (d[0].severity.overall_severity = 'urgent')],
    ['a trace with no steps', (d) => (d[0].trace = [])],
    ['an extra field', (d) => (d[2].surprise = true)],
    ['a line of zero', (d) => (d[0].evidence[0].line = 0)],
    ['an absolute path', (d) => (d[0].trace[0].file = '/etc/passwd')],
    ['a path that climbs out', (d) => (d[0].evidence[0].file = '../secrets.txt')],
    ['not a list', (d) => d.splice(0, d.length, ...[])] // empty list is valid: handled below
  ]
  for (const [name, change] of mutations.slice(0, -1)) {
    it(`rejects ${name}, as theirs does`, () => {
      const d = JSON.parse(JSON.stringify(good())) as any[]
      change(d)
      expect(theirs(d)).toBe(false)
      expect(validateFindings(d, schema).length).toBeGreaterThan(0)
    })
  }
  it('rejects a document that is not a list', () => {
    expect(validateFindings({ findings: [] }, schema).length).toBeGreaterThan(0)
  })
})

describe('reading a deep audit', () => {
  const project = (): string => {
    const root = tmp('deep-root-')
    mkdirSync(join(root, 'src'), { recursive: true })
    for (const f of ['handler.c', 'model.c', 'store.c']) writeFileSync(join(root, 'src', f), Array.from({ length: 60 }, (_, i) => `line ${i + 1}`).join('\n'))
    return root
  }
  const audit = (records: unknown[], extra: Record<string, string> = {}): string => {
    const out = tmp('deep-out-')
    mkdirSync(join(out, 'run-1'), { recursive: true })
    writeFileSync(join(out, 'run-1', 'findings.json'), JSON.stringify(records))
    for (const [n, t] of Object.entries(extra)) writeFileSync(join(out, 'run-1', n), t)
    return out
  }

  it('counts confirmed, leads and disproved candidates, and keeps the report', () => {
    const root = project()
    const out = audit([rec('confirmed'), rec('needs_validation'), rec('rejected')], { 'REPORT.md': '# Report\nAll good.', 'NEEDS-VALIDATION.md': 'One lead.' })
    const r = readDeepResults(out, root, schemaPath)
    expect(r.counts).toEqual({ confirmed: 1, needsChecking: 1, rejected: 1 })
    expect(r.problems).toEqual([])
    expect(r.report).toContain('All good.')
    const c = r.findings.find((f) => f.state === 'confirmed')!
    expect(c.severity).toBe('medium')
    expect(c.file).toBe('src/store.c')
    expect(c.line).toBe(30)
    expect(c.fix).toContain('ownership')
    expect(r.findings.find((f) => f.state === 'needs-checking')!.severity).toBe('info')
  })

  it('does not believe a finding whose file or line is not in the project', () => {
    const root = project()
    const bad = rec('confirmed')
    bad.trace[2].line = 5000
    const missing = rec('confirmed')
    missing.fingerprint = 'other'
    missing.evidence[0].file = 'src/nowhere.c'
    const r = readDeepResults(audit([bad, missing]), root, schemaPath)
    expect(r.counts.confirmed).toBe(0)
    expect(r.counts.needsChecking).toBe(2)
    expect(r.problems.join(' ')).toContain('has no line 5000')
    expect(r.problems.join(' ')).toContain('src/nowhere.c is not in the project')
    expect(r.findings.every((f) => f.state === 'needs-checking' && f.severity === 'info')).toBe(true)
  })

  it('shows nothing as confirmed when the file breaks the report format', () => {
    const root = project()
    const broken = rec('confirmed')
    delete broken.root_cause
    const r = readDeepResults(audit([broken]), root, schemaPath)
    expect(r.counts.confirmed).toBe(0)
    expect(r.problems[0]).toContain('does not follow Cloudflare’s report format')
    expect(r.findings[0].state).toBe('needs-checking')
  })

  it('says so when it cannot check the format, and when there is no file at all', () => {
    const root = project()
    expect(readDeepResults(audit([rec('confirmed')]), root, null).counts.confirmed).toBe(0)
    expect(readDeepResults(tmp('empty-'), root, schemaPath)).toMatchObject({ fromFiles: false, findings: [] })
  })

  it('writes the report in the format both apps read', () => {
    const root = project()
    const md = deepMarkdown(readDeepResults(audit([rec('confirmed'), rec('needs_validation')]), root, schemaPath), 'shop', ['Cloudflare security audit'])
    expect(md).toMatch(/### \[MEDIUM\] Missing ownership check/)
    expect(md).toContain('`src/store.c:30`')
    expect(md).toContain('## Needs checking')
    expect(md).toMatch(/### \[LEAD\] Unchecked parsed size/)
    expect(md.match(/^#{2,4}\s*\[(CRITICAL|HIGH|MEDIUM|LOW)\]/gim)).toHaveLength(1)
    expect(md).toContain('1 confirmed finding, 1 lead')
  })

  it('reads the json block the Anthropic pass writes, and checks its citations', () => {
    const root = project()
    const text = 'Report.\n```json\n{"findings":[{"severity":"high","title":"SQL injection","file":"src/handler.c","line":12,"description":"d"},{"severity":"high","title":"Ghost","file":"src/ghost.c","line":3,"description":"d"}]}\n```'
    const list = deepFindingsFromJson(text)
    expect(list).toHaveLength(2)
    const c = checkCitations(root, list)
    expect(c.findings[0].state).toBe('confirmed')
    expect(c.findings[1]).toMatchObject({ state: 'needs-checking', severity: 'info' })
    expect(c.problems[0]).toContain('ghost.c')
    expect(deepFindingsFromJson('no json here')).toEqual([])
  })
})

describe('keeping the project untouched', () => {
  it('notices a changed, added or removed file', () => {
    const root = tmp('deep-sig-')
    mkdirSync(join(root, 'node_modules', 'x'), { recursive: true })
    writeFileSync(join(root, 'a.txt'), 'one')
    writeFileSync(join(root, 'b.txt'), 'two')
    writeFileSync(join(root, 'node_modules', 'x', 'skip.js'), 'ignored')
    const before = treeSignature(root)
    expect([...before.keys()].sort()).toEqual(['a.txt', 'b.txt'])
    expect(changedFiles(before, treeSignature(root))).toEqual([])
    writeFileSync(join(root, 'a.txt'), 'one more')
    writeFileSync(join(root, 'c.txt'), 'new')
    writeFileSync(join(root, 'node_modules', 'x', 'skip.js'), 'changed but skipped')
    expect(changedFiles(before, treeSignature(root))).toEqual(['a.txt', 'c.txt'])
  })
})

describe('the Claude Code command for a deep audit', () => {
  const o = { prompt: 'Audit it', outDir: '/Users/me/MacSec/sessions/s1/deep-audit', root: '/Users/me/www/shop', plugins: ['/Users/me/MacSec/tools/skill-packs/cloudflare/plugin'], session: { id: 'abc', name: 'Deep audit: shop' } }
  it('lets it write only its own notes, and never run commands or use the web', () => {
    const r = deepClaudeArgs(o)
    const allowed = r.args[r.args.indexOf('--allowedTools') + 1].split(',')
    const denied = r.args[r.args.indexOf('--disallowedTools') + 1].split(',')
    expect(r.cwd).toBe(o.outDir)
    expect(allowed).toContain('Edit(//Users/me/MacSec/sessions/s1/deep-audit/**)')
    expect(allowed).toContain('Agent')
    expect(allowed.some((a) => a.startsWith('Bash'))).toBe(false)
    expect(denied).toEqual(expect.arrayContaining(['Bash', 'WebFetch', 'WebSearch', 'Edit(//Users/me/www/shop/**)', 'Write(//Users/me/www/shop/**)']))
    expect(r.args).toEqual(expect.arrayContaining(['--add-dir', o.root, '--plugin-dir', o.plugins[0], '--session-id', 'abc']))
    expect(r.args).not.toContain('--dangerously-skip-permissions')
    expect(r.args).not.toContain('--permission-mode')
  })
  it('passes a local model through, and refuses folder names it cannot make safe rules for', () => {
    expect(deepClaudeArgs({ ...o, model: 'qwen3', localEnv: { ANTHROPIC_BASE_URL: 'http://127.0.0.1:1234' } })).toMatchObject({ env: { ANTHROPIC_BASE_URL: 'http://127.0.0.1:1234' } })
    expect(() => deepClaudeArgs({ ...o, root: '/Users/me/www/shop, v2' })).toThrow(/plainer folder name/)
    expect(() => deepClaudeArgs({ ...o, root: '/Users/me/www/shop (copy)' })).toThrow(/plainer folder name/)
  })
  it('tells the AI the rules of the environment', () => {
    const p = deepPrompt({ engine: 'cloudflare', name: 'shop', root: o.root, outDir: o.outDir })
    expect(p).toContain('security-audit skill')
    expect(p).toContain(o.outDir)
    expect(p).toContain('cannot run commands')
    expect(p).toContain('needs_validation')
    expect(deepPrompt({ engine: 'anthropic', name: 'shop', root: o.root, outDir: o.outDir })).toContain('anthropic-security-review')
    expect(engineList('both')).toEqual(['anthropic', 'cloudflare'])
    expect(deepHandoffPrompt({ engine: 'both', name: 'shop', root: o.root })).toContain('Do not change any project file')
  })
})

describe('what will run, in plain words', () => {
  const packs = [{ id: 'cloudflare', name: 'Cloudflare', commit: 'c1c8a8c1471069fb0e188eeaff69b8e8db6564a8' }, { id: 'anthropic', name: 'Anthropic', commit: '0c6a49f1fa56a1d472575da86a94dbc1edb78eda' }]
  it('names the AI, where the code goes, the skill version and what it may touch', () => {
    const lines = deepPlan({ engine: 'both', reviewer: 'claude-free', model: 'auto', packs, app: 'MacSec', outFolder: '~/MacSec/sessions/s1' })
    const text = lines.map((l) => `${l.label}: ${l.text}`).join('\n')
    expect(text).toContain('Claude Code on Free LLM API')
    expect(text).toContain('free provider')
    expect(text).toContain('version c1c8a8c')
    expect(text).toContain('version 0c6a49f')
    expect(text).toContain('Anthropic security-review, version 0c6a49f, then Cloudflare')
    expect(text).toContain('measures your project before and after')
    expect(text).toContain('Run commands')
  })
  it('is honest that Claude Desktop is a hand-off', () => {
    const lines = deepPlan({ engine: 'cloudflare', reviewer: 'claude-desktop', packs, app: 'Laramac', outFolder: 'x' })
    expect(lines.map((l) => l.label)).not.toContain('Writes')
    expect(lines.find((l) => l.label === 'Method')!.text).toContain('You run it in the Claude app')
    expect(lines.find((l) => l.label === 'AI')!.text).toContain('You paste the request')
  })
})

describe('skill updates', () => {
  const sh = (cwd: string, ...args: string[]): string => {
    const r = spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@t', '-c', 'commit.gpgsign=false', ...args], { cwd, encoding: 'utf8' })
    if (r.status !== 0) throw new Error(r.stderr)
    return r.stdout.trim()
  }
  it('notices a newer version upstream, links what changed, and updates to it', async () => {
    const { installPack, checkPackUpdates, packUpdates, packState, packFile, packPluginDir } = await import('../src/main/seckit/skillpacks')
    const base = tmp('upstream-')
    const work = join(base, 'cloudflare', 'security-audit-skill')
    mkdirSync(join(work, 'skills', 'security-audit'), { recursive: true })
    writeFileSync(join(work, 'skills', 'security-audit', 'SKILL.md'), '---\nname: security-audit\ndescription: Test\n---\nv1\n')
    writeFileSync(join(work, 'skills', 'security-audit', 'report-schema.json'), '{}')
    sh(work, 'init', '-q', '-b', 'main')
    sh(work, 'add', '-A')
    sh(work, 'commit', '-q', '-m', 'one')
    sh(base, 'clone', '-q', '--bare', work, join(base, 'cloudflare', 'security-audit-skill.git'))
    const root = tmp('packs-')
    const first = await installPack(root, 'cloudflare', `file://${base}/`)
    expect(first.loaded).toEqual(['security-audit'])
    expect(packPluginDir(root, 'cloudflare')).toBeTruthy()
    expect(packFile(root, 'cloudflare', 'skills', 'security-audit', 'report-schema.json')).toBeTruthy()
    // Nothing new yet.
    let u = (await checkPackUpdates(root, `file://${base}/`))[0]
    expect(u).toMatchObject({ id: 'cloudflare', available: false, current: first.commit })
    // Upstream moves on.
    writeFileSync(join(work, 'skills', 'security-audit', 'SKILL.md'), '---\nname: security-audit\ndescription: Test\n---\nv2\n')
    sh(work, 'commit', '-q', '-am', 'two')
    sh(work, 'push', '-q', join(base, 'cloudflare', 'security-audit-skill.git'), 'HEAD:main')
    u = (await checkPackUpdates(root, `file://${base}/`))[0]
    expect(u.available).toBe(true)
    expect(u.latest).not.toBe(first.commit)
    expect(u.changes).toBe(`https://github.com/cloudflare/security-audit-skill/compare/${first.commit!.slice(0, 12)}...${u.latest!.slice(0, 12)}`)
    // The answer is remembered without the network.
    expect(packUpdates(root)[0].available).toBe(true)
    const second = await installPack(root, 'cloudflare', `file://${base}/`)
    expect(second.commit).toBe(u.latest)
    expect(readFileSync(join(root, 'cloudflare', 'repo', 'skills', 'security-audit', 'SKILL.md'), 'utf8')).toContain('v2')
    expect(packUpdates(root)[0].available).toBe(false)
    expect(packState(root, 'cloudflare').installed).toBe(true)
  })

  it('keeps the installed version when the update cannot be fetched', async () => {
    const { installPack, checkPackUpdates, packUpdates, packState } = await import('../src/main/seckit/skillpacks')
    const base = tmp('upstream2-')
    const work = join(base, 'cloudflare', 'security-audit-skill')
    mkdirSync(join(work, 'skills', 'security-audit'), { recursive: true })
    writeFileSync(join(work, 'skills', 'security-audit', 'SKILL.md'), '---\nname: security-audit\ndescription: T\n---\n')
    sh(work, 'init', '-q', '-b', 'main')
    sh(work, 'add', '-A')
    sh(work, 'commit', '-q', '-m', 'one')
    sh(base, 'clone', '-q', '--bare', work, join(base, 'cloudflare', 'security-audit-skill.git'))
    const root = tmp('packs2-')
    const first = await installPack(root, 'cloudflare', `file://${base}/`)
    await expect(installPack(root, 'cloudflare', `file://${base}/missing/`)).rejects.toThrow()
    expect(packState(root, 'cloudflare')).toMatchObject({ installed: true, commit: first.commit })
    const u = (await checkPackUpdates(root, `file://${base}/missing/`))[0]
    expect(u.error).toBeTruthy()
    expect(packUpdates(root)[0].available).toBe(false)
  })
})
