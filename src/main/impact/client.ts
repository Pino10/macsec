/**
 * The one client that can send a real request during a controlled-exploitation run.
 *
 * It is deliberately stricter than ConfirmClient, because a step here may change data:
 *   - the host must be covered by the engagement, and every step must talk to the target's own
 *     origin (a verification GET may look at a covered subdomain, with no credentials);
 *   - a private or local address is only allowed when the engagement says it is a staging server;
 *     a cloud metadata address is never allowed;
 *   - a request that can change data counts against the write cap, and needs integrity allowed;
 *   - redirects are never followed (a proof that needs a redirect says so), there is a delay
 *     between requests, and the client stops when the server struggles;
 *   - the audit log keeps the method, the masked address, the status and a hash, never a secret.
 */
import { createHash } from 'crypto'
import { lookup } from 'dns/promises'
import { isIP } from 'net'
import type { Engagement, ImpactAuditEntry } from '../../shared/impact'
import { classify, NetGuard } from '../netguard'
import { maskSecrets } from '../evidence'
import { hostCovers, ValidationError } from '../validate'

export class ImpactRefused extends Error {}

export interface ImpactClientOptions {
  engagement: Engagement
  /** Requests and writes still allowed under the engagement. */
  budget: { requests: number; writes: number }
  /** The target's origin. Everything a step does happens here. */
  origin: string
  /** Whether this engagement allows requests that change data. */
  allowWrites: boolean
  fetchImpl?: typeof fetch
  guard?: NetGuard | false
  delayMs?: number
  cancelled?: () => boolean
  paused?: () => boolean
  now?: () => number
  /** How much of an answer is read, in bytes. */
  bodyCap?: number
}

export interface ImpactReply {
  status: number
  headers: Headers
  body: string
  url: string
  method: string
  ms: number
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))

const SECRET_HEADER = /^(authorization|cookie|set-cookie|x-api-key|proxy-authorization)$/i
const FORBIDDEN_HEADER = /^(host|content-length|connection|transfer-encoding|upgrade|expect)$/i

let stopRequested = false
/** The kill switch: one flag, checked before every request and between actions. */
export function requestStop(): void {
  stopRequested = true
}
export function clearStop(): void {
  stopRequested = false
}
export const isStopped = (): boolean => stopRequested

/** Keeps the names of the parameters, hides the values that look secret. */
export function maskUrl(raw: string): string {
  try {
    const u = new URL(raw)
    const secret = /token|key|secret|pass|auth|session|code|sig|otp/i
    for (const k of [...u.searchParams.keys()]) if (secret.test(k)) u.searchParams.set(k, '[hidden]')
    return u.href
  } catch {
    return raw
  }
}

export function safeHeaders(input: unknown): Record<string, string> {
  const out: Record<string, string> = {}
  const o = (input ?? {}) as Record<string, unknown>
  for (const [k, v] of Object.entries(o).slice(0, 24)) {
    if (!/^[A-Za-z0-9-]{2,64}$/.test(k) || FORBIDDEN_HEADER.test(k)) continue
    if (typeof v !== 'string' || /[\r\n\0]/.test(v) || v.length > 4000) continue
    out[k] = v
  }
  return out
}

export class ImpactClient {
  requests = 0
  writes = 0
  readonly audit: ImpactAuditEntry[] = []
  stopped: string | null = null
  private bad = 0

  constructor(private o: ImpactClientOptions) {}

  left(): { requests: number; writes: number } {
    return { requests: this.o.budget.requests - this.requests, writes: this.o.budget.writes - this.writes }
  }

  /** Every reason this request may not go, checked before it is built. */
  async assertTarget(method: string, url: URL): Promise<void> {
    if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new ImpactRefused('Only http and https are tested.')
    if (url.username || url.password) throw new ImpactRefused('Take the user name and password out of the address.')
    const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '')
    if (!hostCovers(this.o.engagement.hosts, host)) throw new ImpactRefused(`${host} is not covered by this engagement.`)
    const crossOrigin = url.origin !== this.o.origin
    if (crossOrigin && method !== 'GET') throw new ImpactRefused('A step may only change data on the target site itself, not on another host.')
    const literal = isIP(host)
    if (literal) {
      const c = classify(host)
      if (c === 'metadata') throw new ImpactRefused('That address is a cloud metadata service. MacSec never touches it.')
      if (c !== 'public' && !this.o.engagement.allowPrivate) throw new ImpactRefused(`${host} is a ${c} address. Mark the engagement as a staging server if that is right.`)
      return
    }
    if (!this.o.guard) return
    await this.o.guard.check(host)
    if (this.o.engagement.allowPrivate) return
    const ips = await lookup(host, { all: true }).then((r) => r.map((x) => x.address)).catch(() => [] as string[])
    const inside = ips.filter((ip) => classify(ip) !== 'public')
    if (inside.length) throw new ImpactRefused(`${host} resolves to ${inside[0]}, which is not a public address. Mark the engagement as a staging server if that is right.`)
  }

  /** A plain read. Anything with a body goes through send() with a write flag. */
  get(url: string, o: { headers?: Record<string, string>; note?: string; allowCrossOrigin?: boolean } = {}): Promise<ImpactReply> {
    return this.send('GET', url, o)
  }

  async send(
    method: string,
    raw: string,
    o: { headers?: Record<string, string>; body?: string; form?: FormData; contentType?: string; note?: string; allowCrossOrigin?: boolean } = {}
  ): Promise<ImpactReply> {
    for (;;) {
      if (this.stopped) throw new ImpactRefused(this.stopped)
      if (stopRequested || this.o.cancelled?.()) throw new ImpactRefused('Stopped by you.')
      if (!this.o.paused?.()) break
      await sleep(300)
    }
    let url: URL
    try {
      url = new URL(raw)
    } catch {
      throw new ImpactRefused('That is not a full address.')
    }
    if (!o.allowCrossOrigin && url.origin !== this.o.origin) throw new ImpactRefused('A step may only talk to the target site itself.')
    await this.assertTarget(method, url)
    const write = method !== 'GET'
    if (write && !this.o.allowWrites) throw new ImpactRefused('This engagement does not allow requests that change data.')
    const left = this.left()
    if (left.requests < 1) throw new ImpactRefused('The request cap for this engagement is used up.')
    if (write && left.writes < 1) throw new ImpactRefused('The write cap for this engagement is used up.')

    const headers: Record<string, string> = { 'User-Agent': 'MacSec controlled proof', 'Cache-Control': 'no-cache', ...safeHeaders(o.headers) }
    let body: string | FormData | undefined = o.body
    if (o.form) body = o.form
    else if (body !== undefined && !headers['Content-Type']) headers['Content-Type'] = o.contentType ?? 'text/plain; charset=utf-8'
    const requestBytes = Buffer.byteLength(typeof body === 'string' ? body : o.form ? 'multipart' : '')

    this.requests++
    if (write) this.writes++
    if (this.o.delayMs) await sleep(this.o.delayMs)

    const t = this.o.now?.() ?? Date.now()
    let reply: Response
    try {
      reply = await (this.o.fetchImpl ?? fetch)(url.href, {
        method,
        headers,
        body: body as BodyInit | undefined,
        redirect: 'manual',
        signal: AbortSignal.timeout(20000)
      })
    } catch (e) {
      this.bad++
      if (this.bad >= 3) this.stopped = 'The server stopped answering three times in a row, so the run stopped to avoid harming it.'
      this.audit.push({ at: new Date().toISOString(), method, url: maskUrl(url.href), requestBytes, status: 0, responseBytes: 0, responseSha: '', note: 'no answer' })
      throw new ImpactRefused(`The request did not complete: ${(e as Error).message}. Nothing was retried.`)
    }
    const text = reply.status >= 300 && reply.status < 400 ? '' : (await reply.text()).slice(0, this.o.bodyCap ?? 300_000)
    this.bad = reply.status >= 500 ? this.bad + 1 : 0
    if (this.bad >= 3) this.stopped = 'The server answered with errors three times in a row, so the run stopped to avoid harming it.'
    const at = new Date().toISOString()
    this.audit.push({
      at,
      method,
      url: maskUrl(url.href),
      requestBytes,
      status: reply.status,
      responseBytes: Buffer.byteLength(text),
      responseSha: createHash('sha256').update(text).digest('hex'),
      ...(o.note ? { note: o.note } : {})
    })
    return { status: reply.status, headers: reply.headers, body: text, url: url.href, method, ms: (this.o.now?.() ?? Date.now()) - t }
  }
}

/** What the audit log shows for a header set: names, and whether a secret was sent. */
export function headerNote(headers: Record<string, string> | undefined): string {
  const names = Object.keys(safeHeaders(headers))
  if (!names.length) return 'no extra headers'
  return `${names.length} header${names.length === 1 ? '' : 's'}${names.some((n) => SECRET_HEADER.test(n)) ? ' (with a credential, hidden from this record)' : ''}`
}

/** A body as it may appear in a record: masked, and short. */
export function bodyNote(body: string | undefined, max = 240): string {
  if (!body) return ''
  return maskSecrets(body).slice(0, max)
}

/** The validation gate every step goes through before the client is even built. */
export function assertStepShaped(step: unknown): void {
  const s = step as Record<string, unknown>
  if (!s || typeof s !== 'object' || Array.isArray(s)) throw new ValidationError('That step is not shaped like a step.')
  if (typeof s.id !== 'string' || !/^[\w-]{1,64}$/.test(s.id)) throw new ValidationError('That step has no usable id.')
  if (typeof s.url !== 'string') throw new ValidationError('That step has no address.')
}
