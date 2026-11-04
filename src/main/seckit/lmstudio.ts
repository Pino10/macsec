/**
 * LM Studio for Claude Code, shared by Laramac and MacSec (keep both copies of src/main/seckit
 * the same).
 *
 * Claude Code sends a long system prompt and tool list with every request, so a model loaded
 * with LM Studio's default context (often 4,096 tokens) fails with "context too small". Before a
 * review or a claudelm session, this asks LM Studio which context the model was loaded with and,
 * when it is too small, loads it again with enough (capped at what the model supports).
 *
 * It only talks to LM Studio's own REST API on this Mac: GET /api/v1/models,
 * POST /api/v1/models/unload and POST /api/v1/models/load.
 */

/** Below this Claude Code cannot work at all. */
export const CLAUDE_CODE_MIN_CONTEXT = 32768
/** Room for Claude Code's prompt, the skills and a few files. */
export const CLAUDE_CODE_GOOD_CONTEXT = 65536

export interface LmModelEntry {
  key: string
  type?: string
  max_context_length?: number
  loaded_instances?: { id: string; config?: { context_length?: number } }[]
}

export interface LmContextResult {
  model: string
  /** Context the model was loaded with before, or null when it was not loaded. */
  before: number | null
  /** Context it has now. */
  after: number | null
  max: number | null
  reloaded: boolean
  /** What happened, in words; empty when all was already fine. */
  note: string
  ok: boolean
}

/** LM Studio's root address from an OpenAI-style one: http://127.0.0.1:1234/v1 → http://127.0.0.1:1234 */
export const lmRoot = (baseUrl: string): string => baseUrl.trim().replace(/\/+$/, '').replace(/\/v1$/, '').replace('://localhost', '://127.0.0.1')

/** The context to load with: the good amount, never more than the model allows. */
export function targetContext(max: number | null | undefined, want = CLAUDE_CODE_GOOD_CONTEXT): number {
  if (!max || max <= 0) return want
  return Math.min(max, want)
}

/** Finds a model in LM Studio's list by its key or the id of a loaded copy. */
export function findModel(list: LmModelEntry[], model: string): LmModelEntry | null {
  const m = model.trim()
  return list.find((x) => x.key === m) ?? list.find((x) => x.loaded_instances?.some((i) => i.id === m)) ?? list.find((x) => x.key.endsWith(`/${m}`) || m.endsWith(`/${x.key}`)) ?? null
}

/** What to do for one model, without doing it. */
export function plan(entry: LmModelEntry, want = CLAUDE_CODE_GOOD_CONTEXT): { action: 'none' | 'load' | 'reload' | 'too-small'; target: number; current: number | null } {
  const max = entry.max_context_length ?? null
  const target = targetContext(max, want)
  const current = entry.loaded_instances?.length ? Math.max(...entry.loaded_instances.map((i) => i.config?.context_length ?? 0)) : null
  if (max !== null && max < CLAUDE_CODE_MIN_CONTEXT) return { action: 'too-small', target, current }
  if (current === null) return { action: 'load', target, current }
  // A context you chose that already works is kept; reloading takes time.
  if (current >= target || current >= CLAUDE_CODE_MIN_CONTEXT) return { action: 'none', target, current }
  return { action: 'reload', target, current }
}

type Fetch = typeof fetch

async function call<T>(f: Fetch, url: string, token: string | undefined, body?: unknown, timeoutMs = 15000): Promise<T> {
  const res = await f(url, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs)
  })
  if (!res.ok) throw new Error(`LM Studio answered ${res.status}: ${(await res.text()).slice(0, 200)}`)
  return (await res.json().catch(() => ({}))) as T
}

/**
 * Makes sure an LM Studio model is loaded with enough context for Claude Code.
 * Servers that are not LM Studio (no /api/v1/models) are left alone.
 */
export async function ensureLmContext(baseUrl: string, model: string, token?: string, want = CLAUDE_CODE_GOOD_CONTEXT, f: Fetch = fetch): Promise<LmContextResult> {
  const root = lmRoot(baseUrl)
  const none = (note: string, ok = true): LmContextResult => ({ model, before: null, after: null, max: null, reloaded: false, note, ok })
  let list: LmModelEntry[]
  try {
    list = (await call<{ models?: LmModelEntry[]; data?: LmModelEntry[] }>(f, `${root}/api/v1/models`, token)).models ?? []
  } catch {
    return none('')
  }
  const entry = findModel(list, model)
  if (!entry) return none(`LM Studio does not have ${model}. Download it in LM Studio, or choose another model.`, false)
  const p = plan(entry, want)
  const max = entry.max_context_length ?? null
  if (p.action === 'too-small') return { model, before: p.current, after: p.current, max, reloaded: false, ok: false, note: `${entry.key} holds at most ${max?.toLocaleString('en')} tokens, and Claude Code needs at least ${CLAUDE_CODE_MIN_CONTEXT.toLocaleString('en')}. Choose a model with a longer context (most recent Qwen, Gemma and gpt-oss models have 128k or more).` }
  if (p.action === 'none') return { model, before: p.current, after: p.current, max, reloaded: false, ok: true, note: '' }
  for (const i of entry.loaded_instances ?? []) await call(f, `${root}/api/v1/models/unload`, token, { instance_id: i.id }).catch(() => undefined)
  try {
    const r = await call<{ load_config?: { context_length?: number } }>(f, `${root}/api/v1/models/load`, token, { model: entry.key, context_length: p.target, echo_load_config: true }, 10 * 60_000)
    const after = r.load_config?.context_length ?? p.target
    return { model, before: p.current, after, max, reloaded: true, ok: after >= CLAUDE_CODE_MIN_CONTEXT, note: `Loaded ${entry.key} with ${after.toLocaleString('en')} tokens of context${p.current ? ` (it had ${p.current.toLocaleString('en')})` : ''}.` }
  } catch (e) {
    return { model, before: p.current, after: null, max, reloaded: false, ok: false, note: `LM Studio could not load ${entry.key} with ${p.target.toLocaleString('en')} tokens: ${(e as Error).message}. Try a smaller model, or load it in LM Studio with a context length of ${CLAUDE_CODE_MIN_CONTEXT.toLocaleString('en')} or more.` }
  }
}
