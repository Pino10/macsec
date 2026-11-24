/**
 * The accuracy gate: known-bad and known-good samples for the checks that carry the most weight,
 * scored with precision and recall. No network, no tools, so it runs in CI on every commit.
 */
import type { Finding } from '../shared/types'
import { score, type Expected, type Score } from './benchmark'
import { fileShows } from './seckit/confirm'
import { isPlaceholderKey } from './decoys'
import { assessWebDeception } from './wafdeception'
import { chainsOf } from './chains'

export interface BenchRow extends Score {
  name: string
}

const f = (title: string, extra: Partial<Finding> = {}): Finding => ({ id: title, tool: 'Bench', category: 'web', severity: 'high', title, ...extra })

/** .env, .git and a dump are real exposures; an HTML "not found" page is not. */
function exposedFiles(): BenchRow {
  const good = [
    { path: '.env', body: 'DB_HOST=db.internal\nDB_PASSWORD=Zx8!kP2qLm4RtV\nAPP_KEY=base64:9f8a7b6c5d4e3f2a1b0c\n' },
    { path: '.git/config', body: '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://github.com/acme/shop.git\n' },
    { path: 'db.sql', body: 'CREATE TABLE users (id int);\nINSERT INTO users VALUES (1);\n' }
  ]
  const html = '<!doctype html><html><head><title>Not found</title></head><body><h1>404</h1></body></html>'
  const wrong = [
    { path: '.env', body: html },
    { path: '.git/config', body: '<html>Welcome to our shop</html>' },
    { path: 'db.sql', body: '{"error":"not found"}' }
  ]
  const found: Finding[] = []
  for (const s of good) if (fileShows(s.path, s.body)) found.push(f(`Public file: ${s.path}`))
  for (const s of wrong) if (fileShows(s.path, s.body)) found.push(f(`Public file: ${s.path}`))
  const expected: Expected[] = good.map((s) => ({ name: s.path, title: new RegExp(s.path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')) }))
  return { name: 'exposed files', ...score(expected, found) }
}

/** A real-looking key is a finding; an example or placeholder is not. */
function keyValues(): BenchRow {
  const real = ['Zx8!kP2qLm4RtV9w', 'AKIAZ7XK2LMN4PQ8RSTU', 'bXlfc2VjcmV0X2tleV92YWx1ZV8xMjM0']
  const placeholders = ['your-api-key-here', 'xxxxxxxxxxxxxxxxxxxx', '<insert-key>', 'changeme-changeme-1', '${API_KEY}', 'aaaaaaaaaaaaaaaaaaaa']
  const found: Finding[] = []
  for (const v of [...real, ...placeholders]) if (!isPlaceholderKey(v)) found.push(f(`Key found in public JavaScript (${v.slice(0, 4)}…)`))
  const expected: Expected[] = real.map((v) => ({ name: v.slice(0, 6), title: /^Key found/ }))
  return { name: 'key values', ...score(expected, found) }
}

/** A site that answers fake paths with the home page is deception; an honest 404 is not. */
function deception(): BenchRow {
  const home = '<html><body><h1>Shop</h1><p>Welcome to our shop. Browse the products and contact us.</p></body></html>'
  const page = (b: string, status: number): { url: string; status: number; length: number; body: string } => ({ url: 'http://x.test/p', status, length: b.length, body: b })
  const spoofed = assessWebDeception({ home: page(home, 200), random: Array.from({ length: 6 }, () => page(home, 200)) })
  const honest = assessWebDeception({ home: page(home, 200), random: Array.from({ length: 6 }, () => page('Not found', 404)) })
  const found: Finding[] = []
  if (spoofed.deceptive) found.push(f('WAF honeypot or decoy behaviour'))
  if (honest.deceptive) found.push(f('WAF honeypot or decoy behaviour'))
  const expected: Expected[] = [{ name: 'spoofed site', title: /WAF honeypot/ }]
  return { name: 'deception', ...score(expected, found) }
}

/** Paths that add up are found; a single finding is not a path. */
function chains(): BenchRow {
  const pairs: Finding[][] = [
    [f('Public file: /.git/config'), f('GitHub token in public JavaScript')],
    [f('Input comes back in the page without escaping: /search'), f('Cookie "session" is missing the HttpOnly flag', { severity: 'medium' })],
    [f('Records are numbered in the address: /invoice/1'), f('Another account can open /invoice/2')]
  ]
  const singles: Finding[][] = [[f('Missing security header: X-Frame-Options', { severity: 'low' })], [f('Source map public: 12 files')]]
  const found: Finding[] = []
  for (const p of [...pairs, ...singles]) for (const c of chainsOf(p)) found.push(f(c.name))
  const names = ['Exposed files lead to stolen keys', 'Script injection can steal sessions', 'Numbered records and open access to them']
  const expected: Expected[] = names.map((n) => ({ name: n, title: new RegExp(n) }))
  return { name: 'attack paths', ...score(expected, found) }
}

export function runBenchmarks(): BenchRow[] {
  return [exposedFiles(), keyValues(), deception(), chains()]
}
