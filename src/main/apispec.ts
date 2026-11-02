/**
 * Reads API descriptions: Postman collections (v2), OpenAPI 3, Swagger 2 and HAR files, into
 * one list of endpoints, plus what the file itself says about sign-in.
 */
import { parse as parseYaml } from 'yaml'

export interface Endpoint {
  method: string
  /** Path as written, e.g. /orders/{id} */
  path: string
  /** Full address with path values filled in. */
  url: string
  name?: string
  params: { name: string; in: string }[]
  /** Sign-in the file asks for: true, false (explicitly none), or null (not said). */
  secured: boolean | null
  /** Example values and saved data, checked for real keys. */
  examples: string[]
}

export interface ParsedSpec {
  format: 'postman' | 'openapi' | 'swagger' | 'har'
  name: string
  baseUrl: string
  endpoints: Endpoint[]
  /** The file defines a way to sign in at all. */
  hasAuthScheme: boolean
  /** Values saved in the file itself (Postman auth, variables). */
  saved: { where: string; value: string }[]
}

const METHODS = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options']

function fill(path: string, examples: Record<string, unknown> = {}): string {
  return path.replace(/\{([^}]+)\}|:([A-Za-z_]\w*)/g, (_m, a: string | undefined, b: string | undefined) => {
    const k = (a ?? b) as string
    const v = examples[k]
    return encodeURIComponent(v === undefined || v === null ? '1' : String(v))
  })
}

const join = (base: string, path: string): string => `${base.replace(/\/+$/, '')}/${path.replace(/^\/+/, '')}`

export function parseSpec(text: string, fileName = 'api'): ParsedSpec {
  let doc: Record<string, unknown>
  try {
    doc = JSON.parse(text) as Record<string, unknown>
  } catch {
    doc = parseYaml(text) as Record<string, unknown>
  }
  if (!doc || typeof doc !== 'object') throw new Error('That file is not JSON or YAML.')
  if ((doc as { log?: unknown }).log) return parseHar(doc)
  if ((doc as { info?: { schema?: string } }).info?.schema?.includes('postman') || (Array.isArray((doc as { item?: unknown }).item) && (doc as { info?: unknown }).info)) return parsePostman(doc)
  if (typeof doc.openapi === 'string' || doc.swagger) return parseOpenApi(doc)
  throw new Error(`${fileName} is not a Postman collection, OpenAPI or Swagger file, or HAR file.`)
}

function parseOpenApi(doc: Record<string, unknown>): ParsedSpec {
  type Op = { operationId?: string; summary?: string; parameters?: P[]; security?: unknown[]; requestBody?: unknown; responses?: unknown }
  type P = { name: string; in: string; example?: unknown; schema?: { example?: unknown; default?: unknown }; $ref?: string }
  const swagger = !!doc.swagger
  const d = doc as { servers?: { url: string }[]; host?: string; basePath?: string; schemes?: string[]; paths?: Record<string, Record<string, Op | P[]>>; security?: unknown[]; components?: { securitySchemes?: object }; securityDefinitions?: object; info?: { title?: string } }
  const baseUrl = swagger ? `${d.schemes?.includes('https') ? 'https' : (d.schemes?.[0] ?? 'https')}://${d.host ?? 'localhost'}${d.basePath ?? ''}` : (d.servers?.[0]?.url ?? '/')
  const schemes = swagger ? d.securityDefinitions : d.components?.securitySchemes
  const hasAuthScheme = !!schemes && Object.keys(schemes).length > 0
  const globalSecured = Array.isArray(d.security) && d.security.some((s) => s && Object.keys(s as object).length > 0)
  const endpoints: Endpoint[] = []
  for (const [path, item] of Object.entries(d.paths ?? {})) {
    const shared = (Array.isArray(item.parameters) ? item.parameters : []) as P[]
    for (const method of METHODS) {
      const op = item[method] as Op | undefined
      if (!op) continue
      const params = [...shared, ...(op.parameters ?? [])].filter((p) => p && p.name)
      const ex: Record<string, unknown> = {}
      for (const p of params) ex[p.name] = p.example ?? p.schema?.example ?? p.schema?.default
      const secured = Array.isArray(op.security) ? op.security.some((s) => s && Object.keys(s as object).length > 0) : globalSecured ? true : hasAuthScheme ? null : false
      const query = params.filter((p) => p.in === 'query' && ex[p.name] !== undefined).map((p) => `${encodeURIComponent(p.name)}=${encodeURIComponent(String(ex[p.name]))}`)
      endpoints.push({
        method: method.toUpperCase(),
        path,
        url: join(baseUrl, fill(path, ex)) + (query.length ? `?${query.join('&')}` : ''),
        name: op.summary ?? op.operationId,
        params: params.map((p) => ({ name: p.name, in: p.in })),
        secured,
        examples: [JSON.stringify(op.requestBody ?? ''), JSON.stringify(op.responses ?? ''), JSON.stringify(ex)].filter((x) => x.length > 4)
      })
    }
  }
  return { format: swagger ? 'swagger' : 'openapi', name: d.info?.title ?? 'API', baseUrl, endpoints, hasAuthScheme, saved: [] }
}

function parsePostman(doc: Record<string, unknown>): ParsedSpec {
  type Url = string | { raw?: string; host?: string[]; path?: string[]; query?: { key: string; value?: string }[]; protocol?: string }
  type Auth = { type?: string; bearer?: { key: string; value: string }[]; apikey?: { key: string; value: string }[]; basic?: { key: string; value: string }[] }
  type Item = { name?: string; item?: Item[]; request?: { method?: string; url?: Url; auth?: Auth; header?: { key: string; value: string }[]; body?: { raw?: string } }; auth?: Auth }
  const d = doc as { info?: { name?: string }; item?: Item[]; variable?: { key: string; value?: unknown }[]; auth?: Auth }
  const vars = new Map((d.variable ?? []).map((v) => [v.key, String(v.value ?? '')]))
  const sub = (s: string): string => s.replace(/\{\{([^}]+)\}\}/g, (m, k: string) => vars.get(k.trim()) || m)
  const saved: { where: string; value: string }[] = []
  const authSaved = (a: Auth | undefined, where: string): void => {
    for (const kv of [...(a?.bearer ?? []), ...(a?.apikey ?? []), ...(a?.basic ?? [])]) if (kv.key !== 'key' && kv.key !== 'in' && kv.key !== 'username' && kv.value && !/^\{\{.*\}\}$/.test(kv.value)) saved.push({ where, value: kv.value })
  }
  authSaved(d.auth, 'Collection sign-in')
  for (const v of d.variable ?? []) if (/token|key|secret|password|auth/i.test(v.key) && v.value && !/^\{\{/.test(String(v.value))) saved.push({ where: `Variable ${v.key}`, value: String(v.value) })
  const endpoints: Endpoint[] = []
  const walk = (items: Item[], inheritedAuth: boolean): void => {
    for (const it of items) {
      const auth = it.request?.auth ?? it.auth
      const has = auth ? auth.type !== 'noauth' : inheritedAuth
      if (it.item) {
        walk(it.item, has)
        continue
      }
      if (!it.request) continue
      authSaved(it.request.auth, `Request "${it.name ?? ''}"`)
      for (const h of it.request.header ?? []) if (/^(authorization|x-api-key|api-key|cookie)$/i.test(h.key) && h.value && !/\{\{/.test(h.value)) saved.push({ where: `Header ${h.key} in "${it.name ?? ''}"`, value: h.value })
      const u = it.request.url
      const raw = typeof u === 'string' ? u : (u?.raw ?? `${u?.protocol ?? 'https'}://${(u?.host ?? []).join('.')}/${(u?.path ?? []).join('/')}`)
      const url = sub(raw)
      let path = url
      try {
        path = new URL(url.replace(/\{\{[^}]+\}\}/g, 'x')).pathname
      } catch {
        // Unresolved variables: keep the raw text.
      }
      endpoints.push({ method: (it.request.method ?? 'GET').toUpperCase(), path, url: url.replace(/:([A-Za-z_]\w*)/g, '1'), name: it.name, params: [], secured: auth?.type === 'noauth' ? false : has ? true : null, examples: [it.request.body?.raw ?? ''].filter(Boolean) })
    }
  }
  walk(d.item ?? [], !!d.auth && d.auth.type !== 'noauth')
  let baseUrl = vars.get('baseUrl') ?? vars.get('base_url') ?? vars.get('url') ?? ''
  if (!baseUrl) {
    try {
      baseUrl = new URL(endpoints.find((e) => /^https?:\/\//.test(e.url))?.url ?? '').origin
    } catch {
      baseUrl = ''
    }
  }
  return { format: 'postman', name: d.info?.name ?? 'Collection', baseUrl, endpoints, hasAuthScheme: !!d.auth || endpoints.some((e) => e.secured), saved }
}

function parseHar(doc: Record<string, unknown>): ParsedSpec {
  type E = { request: { method: string; url: string; headers?: { name: string; value: string }[] } }
  const entries = ((doc as { log: { entries?: E[] } }).log.entries ?? []).filter((e) => /^https?:/.test(e.request?.url ?? ''))
  const seen = new Set<string>()
  const endpoints: Endpoint[] = []
  for (const e of entries) {
    const key = `${e.request.method} ${e.request.url.split('?')[0]}`
    if (seen.has(key)) continue
    seen.add(key)
    const u = new URL(e.request.url)
    endpoints.push({ method: e.request.method.toUpperCase(), path: u.pathname, url: e.request.url, params: [...u.searchParams.keys()].map((n) => ({ name: n, in: 'query' })), secured: (e.request.headers ?? []).some((h) => /^(authorization|cookie|x-api-key)$/i.test(h.name)), examples: [] })
  }
  return { format: 'har', name: 'Recorded traffic', baseUrl: endpoints[0] ? new URL(endpoints[0].url).origin : '', endpoints, hasAuthScheme: endpoints.some((e) => e.secured), saved: [] }
}
