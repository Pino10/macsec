/**
 * Model servers: the ones MacSec finds by itself (LM Studio, Ollama, vMLX, oMLX, Jan, llama.cpp)
 * and the ones you add (any address, OpenAI or Anthropic format, with an optional key).
 * Keys are encrypted with the macOS Keychain and never go to the window.
 */
import { execFile } from 'child_process'
import { existsSync, readFileSync, writeFileSync } from 'fs'
import { randomBytes } from 'crypto'
import { join } from 'path'
import type { ChatMessage, LlmTest, LocalLlm, ModelApi, ModelServer, ModelServerInput } from '../shared/types'
import { dirs } from './paths'
import { getSettings } from './settings'

interface Stored {
  id: string
  name: string
  baseUrl: string
  api: ModelApi
  key?: string
}

interface Crypto {
  available: () => boolean
  encrypt: (s: string) => string
  decrypt: (s: string) => string
}
let crypto: Crypto | null = null
/** The app passes the Keychain in at startup; tests pass their own. */
export function setModelCrypto(c: Crypto | null): void {
  crypto = c
}

const file = (): string => join(dirs.config(), 'model-servers.json')
function load(): Stored[] {
  try {
    return existsSync(file()) ? (JSON.parse(readFileSync(file(), 'utf8')) as Stored[]) : []
  } catch {
    return []
  }
}
function save(list: Stored[]): void {
  writeFileSync(file(), JSON.stringify(list, null, 2), { mode: 0o600 })
}

/** Anthropic's format is addressed by its root; OpenAI's includes /v1. */
export function normalizeBase(url: string, api: ModelApi): string {
  let u = url.trim().replace(/\/+$/, '')
  if (!/^https?:\/\//i.test(u)) u = `http://${u}`
  u = u.replace(/^(https?:\/\/)localhost(?=[:/]|$)/i, '$1127.0.0.1')
  if (api === 'anthropic') return u.replace(/\/v1$/, '')
  // OpenAI-format servers answer under /v1; an address with just the host and port gets it added.
  if (/^https?:\/\/[^/]+$/.test(u)) return `${u}/v1`
  return u
}

const isLocal = (url: string): boolean => /^https?:\/\/(127\.0\.0\.1|localhost|\[::1\])(:|\/|$)/i.test(url)

export function listServers(): ModelServer[] {
  return load().map((s) => ({ id: s.id, name: s.name, baseUrl: s.baseUrl, api: s.api, hasKey: !!s.key }))
}

export function saveServer(input: ModelServerInput): ModelServer[] {
  const name = String(input.name ?? '').trim().slice(0, 60)
  if (!name) throw new Error('Give the server a name.')
  const api: ModelApi = input.api === 'anthropic' ? 'anthropic' : 'openai'
  const raw = String(input.baseUrl ?? '')
  if (!/^(https?:\/\/)?[\w.-]+(:\d+)?(\/[\w./-]*)?$/i.test(raw.trim())) throw new Error('That address does not look like http://host:port/v1.')
  const baseUrl = normalizeBase(raw, api)
  if (!isLocal(baseUrl) && !baseUrl.startsWith('https://') && !/^http:\/\/(10|192\.168|172\.(1[6-9]|2\d|3[01]))\./.test(baseUrl)) {
    throw new Error('Servers outside this Mac and your network must use https, so your prompts and key are not sent in the clear.')
  }
  const list = load()
  const existing = input.id ? list.find((s) => s.id === input.id) : undefined
  let key = existing?.key
  if (input.key === null) key = undefined
  else if (typeof input.key === 'string' && input.key.trim()) {
    if (!crypto?.available()) throw new Error('The Keychain is not available, so the key cannot be stored safely.')
    key = crypto.encrypt(input.key.trim())
  }
  const entry: Stored = { id: existing?.id ?? randomBytes(6).toString('hex'), name, baseUrl, api, ...(key ? { key } : {}) }
  save(existing ? list.map((s) => (s.id === existing.id ? entry : s)) : [...list, entry])
  return listServers()
}

export function deleteServer(id: string): ModelServer[] {
  save(load().filter((s) => s.id !== id))
  return listServers()
}

/** The saved server behind an address, so its key and format are used. */
function lookup(baseUrl: string): { api: ModelApi; key: string | null; name: string } | null {
  const want = baseUrl.replace(/\/+$/, '')
  const list = load()
  const s = list.find((x) => x.baseUrl === want) ?? list.find((x) => x.baseUrl === normalizeBase(want, 'openai'))
  if (!s) return null
  let key: string | null = null
  try {
    key = s.key && crypto ? crypto.decrypt(s.key) : null
  } catch {
    key = null
  }
  return { api: s.api, key, name: s.name }
}

function headers(api: ModelApi, key: string | null): Record<string, string> {
  const h: Record<string, string> = { 'Content-Type': 'application/json' }
  if (api === 'anthropic') {
    h['anthropic-version'] = '2023-06-01'
    if (key) h['x-api-key'] = key
  } else if (key) h.Authorization = `Bearer ${key}`
  return h
}

async function getJson<T>(url: string, timeoutMs = 1500, h: Record<string, string> = {}): Promise<T | null> {
  try {
    const res = await fetch(url, { headers: h, signal: AbortSignal.timeout(timeoutMs) })
    return res.ok ? ((await res.json()) as T) : null
  } catch {
    return null
  }
}

interface ListedModel {
  id: string
  type?: string
  state?: string
}

/** Embedding models are listed beside chat models but cannot chat. */
export const isChatModel = (id: string, type?: string): boolean =>
  type ? type === 'llm' || type === 'vlm' : !/embed|embedding|rerank|whisper|bge-|e5-|nomic-embed/i.test(id)

/** Loaded models first, then the rest, in the server's order. */
export function orderModels(models: string[], loaded: string[]): string[] {
  return [...models.filter((m) => loaded.includes(m)), ...models.filter((m) => !loaded.includes(m))]
}

/** Which model apps are open, to name what answers on a shared port like 8000. */
function runningApps(): Promise<string> {
  return new Promise((resolve) => execFile('ps', ['-axo', 'comm='], { timeout: 2000 }, (_e, out) => resolve(String(out ?? ''))))
}

/** Ports model apps use by default, besides LM Studio (1234) and Ollama (11434). */
export const SCAN_PORTS = [8000, 8001, 8080, 10240, 1337, 4891]

export function nameForPort(port: number, apps: string): { provider: string; toolId?: LocalLlm['toolId'] } {
  const vmlx = /vMLX(\.app)?\b|MLX Studio/i.test(apps)
  const omlx = /\boMLX(\.app)?\b/.test(apps)
  if (port === 1337) return { provider: 'Jan' }
  if (port === 4891) return { provider: 'GPT4All' }
  if (vmlx && !omlx) return { provider: `vMLX (:${port})`, toolId: 'vmlx' }
  if (omlx && !vmlx) return { provider: `oMLX (:${port})`, toolId: 'omlx' }
  if (vmlx && omlx) return { provider: `vMLX or oMLX (:${port})`, toolId: 'vmlx' }
  if (/llama-server/.test(apps)) return { provider: `llama.cpp (:${port})` }
  return { provider: `Server on :${port}` }
}

/** Which app card a saved server belongs to, from its name or address. */
export function guessTool(name: string, baseUrl: string): LocalLlm['toolId'] {
  if (/\bvmlx\b|mlx studio/i.test(name)) return 'vmlx'
  if (/\bomlx\b/i.test(name)) return 'omlx'
  if (/lm ?studio/i.test(name) || /:1234\b/.test(baseUrl)) return 'lmstudio'
  if (/ollama/i.test(name) || /:11434\b/.test(baseUrl)) return 'ollama'
  return undefined
}

/** Every model server that answers right now, found or saved. */
export async function detectLlms(): Promise<LocalLlm[]> {
  const found: LocalLlm[] = []
  const apps = await runningApps()
  const tasks: Promise<void>[] = []
  const local = (provider: string, baseUrl: string, models: string[], loaded: string[], toolId?: LocalLlm['toolId']): LocalLlm => ({
    provider,
    toolId,
    baseUrl,
    api: 'openai',
    models,
    loaded,
    remote: false,
    saved: false
  })

  tasks.push(
    (async () => {
      const tags = await getJson<{ models: { name: string }[] }>('http://127.0.0.1:11434/api/tags')
      if (!tags) return
      const ps = await getJson<{ models: { name: string }[] }>('http://127.0.0.1:11434/api/ps')
      const loaded = (ps?.models ?? []).map((m) => m.name)
      const models = tags.models.map((m) => m.name).filter((m) => isChatModel(m))
      found.push(local('Ollama', 'http://127.0.0.1:11434/v1', orderModels(models, loaded), loaded, 'ollama'))
    })()
  )
  tasks.push(
    (async () => {
      const rich = await getJson<{ data: ListedModel[] }>('http://127.0.0.1:1234/api/v0/models')
      const list = (rich ?? (await getJson<{ data: ListedModel[] }>('http://127.0.0.1:1234/v1/models')))?.data
      if (!list) return
      const chat = list.filter((m) => isChatModel(m.id, m.type))
      const loaded = chat.filter((m) => m.state === 'loaded').map((m) => m.id)
      found.push(local('LM Studio', 'http://127.0.0.1:1234/v1', orderModels(chat.map((m) => m.id), loaded), loaded, 'lmstudio'))
    })()
  )
  for (const port of SCAN_PORTS) {
    tasks.push(
      (async () => {
        const data = await getJson<{ data: ListedModel[] }>(`http://127.0.0.1:${port}/v1/models`)
        if (!Array.isArray(data?.data)) return
        const models = data!.data.map((m) => m.id).filter((m) => isChatModel(m))
        const { provider, toolId } = nameForPort(port, apps)
        found.push(local(provider, `http://127.0.0.1:${port}/v1`, models, models, toolId))
      })()
    )
  }
  // Saved servers, with their own names, formats and keys.
  for (const s of load()) {
    tasks.push(
      (async () => {
        const l = lookup(s.baseUrl)
        const modelsUrl = s.api === 'anthropic' ? `${s.baseUrl}/v1/models?limit=100` : `${s.baseUrl}/models`
        const data = await getJson<{ data: ListedModel[] }>(modelsUrl, isLocal(s.baseUrl) ? 1500 : 6000, headers(s.api, l?.key ?? null))
        const models = (data?.data ?? []).map((m) => m.id).filter((m) => isChatModel(m))
        found.push({ id: s.id, provider: s.name, toolId: guessTool(s.name, s.baseUrl), baseUrl: s.baseUrl, api: s.api, models, loaded: isLocal(s.baseUrl) ? models : [], remote: !isLocal(s.baseUrl), saved: true, online: !!data })
      })()
    )
  }
  await Promise.all(tasks)

  // A saved server replaces the one found at the same address and format.
  const out = found.filter((f) => f.saved || !found.some((g) => g.saved && g.api === f.api && g.baseUrl === f.baseUrl))
  const rank = (f: LocalLlm): number => (f.saved ? 0 : f.provider === 'LM Studio' ? 1 : f.provider === 'Ollama' ? 2 : 3)
  return out.sort((a, b) => rank(a) - rank(b) || a.provider.localeCompare(b.provider))
}

/** Turns a model server's error into something a person can act on. */
export function explainLlmError(status: number, body: string, model: string): string {
  let detail = body
  try {
    const j = JSON.parse(body) as { error?: string | { message?: string } }
    detail = typeof j.error === 'string' ? j.error : (j.error?.message ?? body)
  } catch {
    /* plain text */
  }
  detail = detail.trim().slice(0, 300)
  const d = detail.toLowerCase()
  let hint = ''
  if (/embed/.test(d) || /embed/i.test(model)) hint = `${model} is an embedding model and cannot chat. Pick a chat model instead.`
  else if (status === 401 || status === 403 || /api key|x-api-key|unauthori[sz]ed|authentication/.test(d)) hint = 'The key was refused. Check it in Tools › Model servers.'
  else if (/credit|billing|quota|insufficient/.test(d)) hint = 'The account behind this key has no credit left.'
  else if (/context|n_ctx|too long|token/.test(d)) hint = 'The conversation is longer than the model can hold. Load the model with a larger context length, or start a new chat.'
  else if (/not (found|loaded)|no model|unknown model|does not exist/.test(d)) hint = `${model} is not loaded. Load it in your model app, or pick a loaded one.`
  return [hint, detail ? `The server said: ${detail}` : `The model server answered ${status}.`].filter(Boolean).join(' ')
}

/** One request in either format, returning the text. */
async function complete(baseUrl: string, model: string, messages: ChatMessage[], maxTokens: number | null, timeoutMs: number): Promise<{ ok: true; text: string } | { ok: false; error: string }> {
  const saved = lookup(baseUrl)
  const api = saved?.api ?? 'openai'
  const key = saved?.key ?? null
  const base = baseUrl.replace(/\/+$/, '')
  let res: Response
  try {
    if (api === 'anthropic') {
      const system = messages.filter((m) => m.role === 'system').map((m) => m.content).join('\n\n')
      res = await fetch(`${base}/v1/messages`, {
        method: 'POST',
        headers: headers(api, key),
        body: JSON.stringify({ model, max_tokens: maxTokens ?? 4096, ...(system ? { system } : {}), messages: messages.filter((m) => m.role !== 'system') }),
        signal: AbortSignal.timeout(timeoutMs)
      })
    } else {
      res = await fetch(`${base}/chat/completions`, {
        method: 'POST',
        headers: headers(api, key),
        body: JSON.stringify({ model, messages, stream: false, ...(maxTokens ? { max_tokens: maxTokens, temperature: 0 } : {}) }),
        signal: AbortSignal.timeout(timeoutMs)
      })
    }
  } catch (err) {
    return { ok: false, error: (err as Error).name === 'TimeoutError' ? 'No answer in time. The model may still be loading.' : `Could not reach ${base}. Is the server on?` }
  }
  const text = await res.text().catch(() => '')
  if (!res.ok) return { ok: false, error: explainLlmError(res.status, text, model) }
  try {
    if (api === 'anthropic') {
      const data = JSON.parse(text) as { content?: { type: string; text?: string }[] }
      return { ok: true, text: (data.content ?? []).filter((c) => c.type === 'text').map((c) => c.text).join('') }
    }
    const data = JSON.parse(text) as { choices?: { message?: { content?: string; reasoning_content?: string } }[] }
    const msg = data.choices?.[0]?.message
    return { ok: true, text: msg?.content || msg?.reasoning_content || '' }
  } catch {
    return { ok: false, error: 'The server answered with something that is not a chat reply.' }
  }
}

/** Sends one short message to check that a server and model really answer. */
export async function testLlm(baseUrl: string, model: string): Promise<LlmTest> {
  const started = Date.now()
  const r = await complete(baseUrl, model, [{ role: 'user', content: 'Reply with the single word: ready' }], 16, 120000)
  const ms = Date.now() - started
  return r.ok ? { ok: true, ms, reply: r.text.trim().slice(0, 120) } : { ok: false, ms, error: r.error }
}

/** Sends a chat to the model chosen in the Assistant. */
export async function chatWithLlm(messages: ChatMessage[], timeoutMs = 180000): Promise<string> {
  const { baseUrl, model } = getSettings().llm
  if (!model) throw new Error('Choose a model on the Tools page first.')
  const r = await complete(baseUrl, model, messages, null, timeoutMs)
  if (!r.ok) throw new Error(r.error)
  return r.text
}

/** Whether the chosen model sends text off this Mac, so screens can say so. */
export const chosenIsRemote = (): boolean => !isLocal(getSettings().llm.baseUrl)
