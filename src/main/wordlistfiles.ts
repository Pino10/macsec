/**
 * The word lists discovery uses: MacSec's own paths, plus any .txt list you drop into
 * ~/MacSec/extensions/wordlists. One list, written once per run, so ffuf has a file to read.
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'fs'
import { join } from 'path'
import { dirs } from './paths'
import { CONTENT_WORDS } from './wordlists'

const WORD = /^[A-Za-z0-9._~!$-][A-Za-z0-9._~!$/-]{0,140}$/

/** Your own lists, one path per line. Comments and blanks are skipped, and every line is a plain path. */
export function customWords(): string[] {
  const dir = join(dirs.extensions(), 'wordlists')
  if (!existsSync(dir)) return []
  const out: string[] = []
  for (const f of readdirSync(dir).filter((n) => /\.txt$/i.test(n)).slice(0, 20)) {
    try {
      for (const line of readFileSync(join(dir, f), 'utf8').split('\n')) {
        const w = line.trim().replace(/^\/+/, '')
        if (w && !w.startsWith('#') && WORD.test(w) && !w.includes('..')) out.push(w)
      }
    } catch {
      // A list that cannot be read is skipped.
    }
  }
  return out
}

/** The words a run may use: your lists first, then MacSec's, without duplicates. */
export function discoveryWords(cap = 2000): string[] {
  return [...new Set([...customWords(), ...CONTENT_WORDS])].slice(0, cap)
}

/** Writes the words where ffuf can read them and returns the path. */
export function writeWordlist(words: string[], path: string): string {
  mkdirSync(join(path, '..'), { recursive: true, mode: 0o700 })
  writeFileSync(path, `${words.join('\n')}\n`, { mode: 0o600 })
  return path
}
