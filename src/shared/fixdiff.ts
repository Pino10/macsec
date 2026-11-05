/**
 * The AI's suggested fix, as a diff against the lines around the finding. MacSec only shows it:
 * you copy it and apply it yourself (AI agents run read-only).
 */

export interface DiffLine {
  kind: 'same' | 'del' | 'add'
  text: string
  /** The line number in the file, for kept and removed lines. */
  n?: number
}

const norm = (s: string): string => s.replace(/\s+$/, '')

/** Strips a Markdown code fence the AI may have wrapped the fix in. */
export function unfence(code: string): string {
  const m = /^\s*```[\w-]*\n([\s\S]*?)\n?```\s*$/.exec(code)
  return m ? m[1] : code
}

/**
 * A line diff (longest common subsequence). The fix is usually only the changed part, while the
 * context has a few lines either side, so context lines outside the part the fix overlaps are
 * kept as they are, except the flagged line itself (context.at), which the fix replaces.
 */
export function fixDiff(context: { start: number; lines: string[]; at?: number }, fixCode: string): DiffLine[] {
  const a = context.lines.map(norm)
  const b = unfence(fixCode).split('\n').map(norm)
  while (b.length && !b[b.length - 1].trim()) b.pop()
  while (b.length && !b[0].trim()) b.shift()
  if (!b.length || a.length > 400 || b.length > 400) return []
  const n = a.length
  const m = b.length
  const eq = (i: number, j: number): boolean => a[i].trim() === b[j].trim()
  const L: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0))
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) L[i][j] = eq(i, j) ? L[i + 1][j + 1] + 1 : Math.max(L[i + 1][j], L[i][j + 1])
  if (!L[0][0]) return b.map((text) => ({ kind: 'add', text }))
  const ops: (DiffLine & { i?: number })[] = []
  let i = 0
  let j = 0
  while (i < n || j < m) {
    if (i < n && j < m && eq(i, j)) {
      ops.push({ kind: 'same', text: a[i], n: context.start + i, i })
      i++
      j++
    } else if (j >= m || (i < n && (L[i + 1][j] > L[i][j + 1] || (L[i + 1][j] === L[i][j + 1] && context.start + i === context.at)))) {
      // On a tie, the flagged line goes first (it is what the fix replaces); other lines wait,
      // so the new code sits where the old line was, not after the lines around it.
      ops.push({ kind: 'del', text: a[i], n: context.start + i, i })
      i++
    } else ops.push({ kind: 'add', text: b[j++] })
  }
  const sameIdx = ops.flatMap((o, k) => (o.kind === 'same' ? [k] : []))
  const first = sameIdx[0]
  const last = sameIdx[sameIdx.length - 1]
  const flagged = context.at
  return ops.map((o, k) => {
    const outside = k < first || k > last
    const isFlagged = flagged !== undefined && o.n === flagged
    const line: DiffLine = o.kind === 'del' && outside && !isFlagged ? { kind: 'same', text: o.text, n: o.n } : { kind: o.kind, text: o.text, n: o.n }
    if (line.n === undefined) delete line.n
    return line
  })
}

/** A unified diff, to copy into a patch or a pull request. */
export function unifiedDiff(file: string, lines: DiffLine[]): string {
  const first = lines.find((l) => l.n)?.n ?? 1
  const oldCount = lines.filter((l) => l.kind !== 'add').length
  const newCount = lines.filter((l) => l.kind !== 'del').length
  return [`--- a/${file}`, `+++ b/${file}`, `@@ -${first},${oldCount} +${first},${newCount} @@`, ...lines.map((l) => `${l.kind === 'same' ? ' ' : l.kind === 'del' ? '-' : '+'}${l.text}`)].join('\n') + '\n'
}
