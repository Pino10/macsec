/**
 * Evidence: the exact lines behind every finding, read while the code is still here (a private
 * copy is deleted when the review ends, the evidence stays in the report). Secrets are masked:
 * the first four characters stay so you can recognise which key it is.
 */
import { readFileSync, statSync } from 'fs'
import { isAbsolute, join, normalize, sep } from 'path'
import type { Finding } from '../shared/types'

/** Hides the secret part of a line: long token-like values after =, : or inside quotes. */
const secretish = (v: string): boolean => v.length >= 28 || (v.length >= 12 && /\d/.test(v) && /[A-Za-z]/.test(v) && !/^[a-z_]+\d?$/.test(v))
const hide = (v: string): string => `${v.slice(0, 4)}${'•'.repeat(8)}`

export function maskSecrets(line: string): string {
  return line
    .replace(/(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]*/, '$1 ••••')
    .replace(/(["'`])([A-Za-z0-9+/_\-.~=]{12,})\1/g, (m, q: string, v: string) => (secretish(v) ? `${q}${hide(v)}${q}` : m))
    .replace(/([=:]\s*)([A-Za-z0-9+/_\-.~]{12,})(?=\s*($|[,;#]))/g, (m, pre: string, v: string) => (secretish(v) ? `${pre}${hide(v)}` : m))
    .replace(/\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, '$1••••••••')
    .replace(/\b(sk|pk|rk)_(live|test)_[A-Za-z0-9]{8,}/g, '$1_$2_••••••••')
    .replace(/\b(gh[pousr]_|github_pat_|xox[baprs]-|AIza|eyJ)[A-Za-z0-9_\-.]{8,}/g, '$1••••••••')
}

const cache = new Map<string, string[] | null>()
function fileLines(root: string, rel: string): string[] | null {
  const p = normalize(isAbsolute(rel) ? rel : join(root, rel))
  if (!p.startsWith(normalize(root) + sep)) return null
  if (cache.has(p)) return cache.get(p)!
  let lines: string[] | null = null
  try {
    if (statSync(p).size < 5_000_000) {
      const text = readFileSync(p, 'utf8')
      if (!/\0/.test(text.slice(0, 2000))) lines = text.split('\n')
    }
  } catch {
    lines = null
  }
  cache.set(p, lines)
  return lines
}

/** Adds the surrounding lines to each finding that points at a file in the code. */
export function addEvidence(root: string, findings: Finding[], around = 4): Finding[] {
  cache.clear()
  return findings.map((f) => {
    if (f.context || !f.file || /^https?:\/\//.test(f.file)) return f
    const lines = fileLines(root, f.file)
    if (!lines) return f
    let at = f.line ?? 0
    // Package findings point at a lock file: find the package's own line.
    if (!at && f.category === 'dependency') {
      const pkg = f.title.split(':')[0].split(' ')[0]
      const i = lines.findIndex((l) => l.includes(`"${pkg}"`) || l.includes(`${pkg}==`) || l.includes(`name = "${pkg}"`) || l.startsWith(`${pkg}@`) || l.includes(` ${pkg} `))
      at = i >= 0 ? i + 1 : 0
    }
    if (!at || at > lines.length) return f
    const start = Math.max(1, at - around)
    const end = Math.min(lines.length, at + around)
    const mask = f.category === 'secret' || /secret|key|token|password|credential/i.test(f.title)
    const slice = lines.slice(start - 1, end).map((l) => (l.length > 400 ? `${l.slice(0, 400)} …` : l))
    return { ...f, line: f.line ?? at, context: { start, at, lines: mask ? slice.map(maskSecrets) : slice } }
  })
}
