/**
 * The AI reviewer's knowledge base: short notes on how real vulnerabilities are found and proven
 * (authorization, authentication, business logic, payments, APIs, mobile and more), written in our
 * own words. The AI only reads the prompt, so the notes that fit a scan are picked here and put in it.
 * Built by scripts/build-knowledge.py. The raw report corpus is not included.
 */
import kb from './data/kb.json'

interface KbFile {
  id: string
  title: string
  trigger: string
  text: string
}

const FILES = (kb as { files: KbFile[] }).files

const STOP = new Set(['the', 'and', 'for', 'with', 'that', 'this', 'from', 'any', 'are', 'not', 'can', 'all', 'has', 'was', 'its', 'you', 'use', 'when', 'into', 'than', 'only', 'which', 'where', 'what', 'have', 'been', 'such', 'each', 'other', 'also', 'but', 'via', 'per', 'out'])

export const words = (s: string): string[] => (s.toLowerCase().match(/[a-z][a-z0-9]{2,}/g) ?? []).filter((w) => !STOP.has(w))

export interface Picked {
  id: string
  title: string
  score: number
}

/** The notes that best match a description of what was found, best first. */
export function pickKnowledge(query: string, o: { max?: number; prefer?: string[] } = {}): Picked[] {
  const q = new Set(words(query))
  const out: Picked[] = []
  for (const f of FILES) {
    const head = new Set(words(`${f.id.replace(/[/-]/g, ' ')} ${f.title}`))
    const trig = new Set(words(f.trigger))
    let score = 0
    for (const w of q) {
      if (head.has(w)) score += 3
      if (trig.has(w)) score += 2
    }
    if (score === 0) continue
    // Body words count a little, so a note about the same thing in other words can still surface.
    const body = f.text.toLowerCase()
    for (const w of q) if (body.includes(w)) score += 0.15
    if (o.prefer?.some((p) => f.id.startsWith(p))) score += 1.5
    out.push({ id: f.id, title: f.title, score })
  }
  return out.sort((a, b) => b.score - a.score).slice(0, o.max ?? 5)
}

const cut = (text: string, max: number): string => {
  if (text.length <= max) return text
  const at = text.lastIndexOf('\n', max)
  return `${text.slice(0, at > max / 2 ? at : max)}\n[shortened]`
}

/** A block for an AI prompt: the best-matching notes, each cut to a few thousand characters. */
export function knowledgeBlock(query: string, o: { max?: number; maxChars?: number; prefer?: string[] } = {}): string {
  const picked = pickKnowledge(query, o)
  if (!picked.length) return ''
  const each = Math.floor((o.maxChars ?? 14000) / picked.length)
  const parts = picked.map((p) => `### ${p.title} (${p.id})\n${cut(FILES.find((f) => f.id === p.id)!.text.replace(/^Status:.*\n/m, ''), each)}`)
  return `Notes from past real-world cases. Use them to judge what is real, how it is proven and how it is rated. They are guidance, not findings about this target:\n\n${parts.join('\n\n')}`
}

export const knowledgeCount = (): number => FILES.length
