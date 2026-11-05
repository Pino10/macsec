/**
 * Free LLM API, shared by Laramac and MacSec (keep both copies of src/main/seckit the same).
 *
 * Free LLM API is an app you run yourself: it holds your free keys for Google AI Studio, Groq,
 * Cerebras, NVIDIA, OpenRouter and the rest, and answers on one address with one key. It speaks
 * OpenAI's format (/v1/chat/completions) and Anthropic's (/v1/messages), so Claude Code can run
 * on it, like it runs on LM Studio.
 *
 *   auto        the routing chain you set up in Free LLM API
 *   auto:fast   the fastest of the models you turned on
 *
 * The unified key goes only to the Free LLM API address, which must be on this Mac or use HTTPS.
 */
import { localModelEnv } from './reviewers'

export const FREELLM_DEFAULT_URL = 'http://127.0.0.1:31415/v1'
export const FREELLM_MODELS = ['auto', 'auto:fast'] as const

export interface FreeLlmConfig {
  baseUrl: string
  model: string
}

export interface FreeLlmCheck {
  ok: boolean
  /** Models it offers, auto first. */
  models: string[]
  note: string
}

type Fetch = (url: string, init?: { headers?: Record<string, string>; signal?: AbortSignal; method?: string; body?: string }) => Promise<{ ok: boolean; status: number; json: () => Promise<unknown>; text: () => Promise<string> }>

/** The address with /v1, localhost written as 127.0.0.1. Throws for anything that would send the key across the internet in the clear. */
export function freeLlmUrl(input: string): string {
  let u = String(input ?? '').trim().replace(/\/+$/, '')
  if (!u) return FREELLM_DEFAULT_URL
  if (!/^https?:\/\//i.test(u)) u = `http://${u}`
  let parsed: URL
  try {
    parsed = new URL(u)
  } catch {
    throw new Error('That is not a web address.')
  }
  if (parsed.username || parsed.password) throw new Error('Put the key in the key box, not in the address.')
  const host = parsed.hostname.replace(/^\[|\]$/g, '')
  const local = host === '127.0.0.1' || host === 'localhost' || host === '::1'
  if (!local && parsed.protocol !== 'https:') throw new Error('Free LLM API must be on this Mac (127.0.0.1) or use https://, so your key is never sent in the clear.')
  u = u.replace(/^(https?:\/\/)localhost(?=[:/]|$)/i, '$1127.0.0.1')
  return /\/v1$/.test(u) ? u : `${u.replace(/\/v1\/.*$/, '')}/v1`
}

/** Unified keys look like freellmapi-… ; anything with spaces or quotes is a paste mistake. */
export function checkFreeLlmKey(key: string): string {
  const k = String(key ?? '').trim()
  if (!/^[A-Za-z0-9._:-]{16,256}$/.test(k)) throw new Error('That does not look like a Free LLM API key. Copy the unified key from its Keys page.')
  return k
}

export function freeLlmModel(m: string): string {
  const v = String(m ?? '').trim() || 'auto'
  if (!/^[A-Za-z0-9._:/@-]{1,160}$/.test(v)) throw new Error('That model name has characters model names do not use.')
  return v
}

/** Models from /v1/models, with auto and auto:fast first. */
export function freeLlmModels(data: unknown): string[] {
  const list = (data as { data?: { id?: unknown }[] })?.data
  const ids = Array.isArray(list) ? list.map((m) => (typeof m?.id === 'string' ? m.id : '')).filter(Boolean) : []
  return [...FREELLM_MODELS, ...ids.filter((x) => !(FREELLM_MODELS as readonly string[]).includes(x)).sort()]
}

/** Asks Free LLM API for its models with the key: tells you if it is running and the key is right. */
export async function checkFreeLlm(baseUrl: string, key: string, f: Fetch = fetch as unknown as Fetch): Promise<FreeLlmCheck> {
  const url = freeLlmUrl(baseUrl)
  try {
    const r = await f(`${url}/models`, { headers: { Authorization: `Bearer ${key}` }, signal: AbortSignal.timeout(6000) })
    if (r.status === 401 || r.status === 403) return { ok: false, models: [], note: 'Free LLM API is running, but it did not accept the key. Copy the unified key again from its Keys page.' }
    if (!r.ok) return { ok: false, models: [], note: `Free LLM API answered with an error (${r.status}).` }
    const models = freeLlmModels(await r.json().catch(() => null))
    return { ok: true, models, note: `Connected: ${models.length - FREELLM_MODELS.length} models behind one key.` }
  } catch {
    return { ok: false, models: [], note: `Free LLM API is not answering at ${url}. Open it and make sure the server is running.` }
  }
}

/** Environment that points Claude Code at Free LLM API's Anthropic-compatible /v1/messages. */
export function freeLlmEnv(c: FreeLlmConfig, key: string): Record<string, string> {
  const env = localModelEnv({ baseUrl: freeLlmUrl(c.baseUrl), model: freeLlmModel(c.model), token: key })
  // Free tiers have smaller output limits than Anthropic; Claude Code copes with 8,192.
  env.CLAUDE_CODE_MAX_OUTPUT_TOKENS = '8192'
  return env
}
