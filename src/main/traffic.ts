/**
 * Reads what an app said on the network, from a HAR file (mitmproxy writes one, and so do Burp, Charles
 * and browsers). It only reads the file: it never sends a request and never touches the phone.
 *
 * What it reports, and how it stays honest:
 *   - Plain http to a server: the request line (without the values after ?) is the proof.
 *   - A sensitive name (token, password, api key...) in the web address, in the headers of a plain http
 *     request, or in a form or JSON body sent over plain http. Only the NAME and the kind are saved, never the value.
 *   - A cookie set over https without the Secure flag (cookie name only).
 *   - The servers the app talked to (a note, not a problem).
 * Nothing is "possible": every finding here was seen in a real request. An empty capture is a note that
 * says why it may be empty (the app may use certificate pinning, which is good).
 */
import { createHash } from 'crypto'
import type { Finding, Severity } from '../shared/types'
import { fid } from './scanners/parse'
import type { Proof } from './seckit/confirm'

interface Pair {
  name?: string
  value?: string
}
interface Entry {
  request?: { method?: string; url?: string; headers?: Pair[]; queryString?: Pair[]; postData?: { mimeType?: string; text?: string; params?: Pair[] } }
  response?: { status?: number; headers?: Pair[]; cookies?: { name?: string; secure?: boolean }[] }
}

export interface TrafficResult {
  findings: Finding[]
  hosts: string[]
  requests: number
}

/** Names that carry a secret. Matched on the whole name, so "tokenizer" or "pinned" never match by accident. */
const SECRET_NAME = /^(pass(word|wd|phrase)?|pwd|secret|client[_-]?secret|(access|refresh|id|auth|session|csrf|xsrf|bearer)[_-]?token|token|api[_-]?key|apikey|api[_-]?secret|auth|authorization|sessionid|session[_-]?id|sid|otp|pin|cvv|cvc|card[_-]?(number|no)|pan|iban)$/i
const SECRET_HEADER = /^(authorization|proxy-authorization|x-api-key|x-auth-token|x-access-token)$/i

/** Hosts that are meant to be plain http: the phone talking to itself, and mitmproxy's own certificate page. */
const SKIP_HTTP = /^(localhost|127\.\d+\.\d+\.\d+|\[?::1\]?|mitm\.it)$/i

const sha = (s: string): string => createHash('sha256').update(s).digest('hex')

function parse(url: string): URL | null {
  try {
    return new URL(url)
  } catch {
    return null
  }
}

/** The request line with the values after ? removed, so a secret in the address is never copied into a report. */
const safeLine = (method: string, u: URL): string => `${method} ${u.protocol}//${u.host}${u.pathname}${u.search ? '?…' : ''}`

function proof(method: string, u: URL, status: number, n: number, shows: string[]): Proof {
  const line = safeLine(method, u)
  return {
    request: line,
    reproduce: `Open the capture file and look at request number ${n}: ${line}`,
    status,
    bytes: 0,
    sha256: sha(line),
    at: new Date().toISOString(),
    shows
  }
}

const f = (severity: Severity, title: string, host: string, key: string, description: string, fix: string, p: Proof, cwe?: string): Finding => ({
  id: fid('traffic', title, host, key),
  tool: 'MacSec traffic check',
  category: 'mobile',
  severity,
  confidence: 'confirmed',
  title,
  file: host,
  url: host,
  cwe,
  description,
  fix,
  proof: p
})

export function analyzeHar(text: string): TrafficResult {
  let entries: Entry[] = []
  try {
    const j = JSON.parse(text) as { log?: { entries?: Entry[] } }
    entries = Array.isArray(j?.log?.entries) ? j.log!.entries! : []
  } catch {
    throw new Error('That file is not a HAR capture. Save the traffic as a HAR file (mitmproxy, Burp, Charles and browsers can).')
  }
  const findings = new Map<string, Finding>()
  const hosts = new Set<string>()
  const put = (x: Finding): void => {
    if (!findings.has(x.id)) findings.set(x.id, x)
  }

  entries.forEach((e, i) => {
    const method = String(e.request?.method ?? 'GET').toUpperCase().replace(/[^A-Z]/g, '').slice(0, 10) || 'GET'
    const u = parse(String(e.request?.url ?? ''))
    if (!u || !/^https?:$/.test(u.protocol)) return
    const host = u.host.toLowerCase()
    hosts.add(host)
    const status = Number(e.response?.status ?? 0)
    const plain = u.protocol === 'http:' && !SKIP_HTTP.test(u.hostname)
    const n = i + 1

    // 1. Secrets named in the web address.
    const names = [...new Set([...(e.request?.queryString ?? []).map((q) => String(q.name ?? '')), ...[...u.searchParams.keys()]])].filter((k) => SECRET_NAME.test(k))
    for (const k of names)
      put(f(plain ? 'high' : 'medium', `A ${k.toLowerCase()} is sent in the web address to ${host}`, host, `url-${k.toLowerCase()}`, `The app puts a value named "${k}" after the ? in the address. Web addresses end up in server logs, proxies and browser history, so secrets should travel in a header or the body instead.${plain ? ' It also went over plain http, so anyone on the network could read it.' : ''}`, 'Send secrets in a header or in the request body over https, never in the address.', proof(method, u, status, n, [`the address has a parameter named ${k}`, plain ? 'the request used plain http' : 'the request used https']), 'CWE-598'))

    if (plain) {
      // 2. Plain http.
      put(f('medium', `The app talks to ${host} unencrypted (plain http)`, host, 'http', 'Anything the app sends to this server can be read or changed by anyone on the same network (café wifi, a hotel, a hacked router).', 'Use https for every server. On Android set cleartextTrafficPermitted to false; on iOS keep App Transport Security on.', proof(method, u, status, n, ['the request used plain http, not https']), 'CWE-319'))
      // 3. Sign-in details in headers of a plain http request.
      for (const h of e.request?.headers ?? []) {
        const hn = String(h.name ?? '')
        if (SECRET_HEADER.test(hn) || /^cookie$/i.test(hn))
          put(f('high', `A ${hn.toLowerCase()} header is sent unencrypted to ${host}`, host, `hdr-${hn.toLowerCase()}`, `The ${hn} header carries sign-in details and it went over plain http, so anyone on the network could copy it and act as the user.`, 'Use https for this server and make the app refuse plain http.', proof(method, u, status, n, [`the request had a ${hn} header`, 'the request used plain http']), 'CWE-319'))
      }
      // 4. Secrets in a form or JSON body.
      const post = e.request?.postData
      const bodyNames = new Set<string>((post?.params ?? []).map((p) => String(p.name ?? '')))
      if (post?.text && /json/i.test(post.mimeType ?? '')) {
        try {
          const walk = (v: unknown, depth: number): void => {
            if (depth > 4 || !v || typeof v !== 'object') return
            for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
              bodyNames.add(k)
              walk(x, depth + 1)
            }
          }
          walk(JSON.parse(post.text), 0)
        } catch {
          /* not JSON after all */
        }
      }
      for (const k of [...bodyNames].filter((x) => SECRET_NAME.test(x)))
        put(f('high', `A ${k.toLowerCase()} is sent unencrypted to ${host}`, host, `body-${k.toLowerCase()}`, `The app sends a field named "${k}" over plain http. Anyone on the network could read it.`, 'Use https for this server and make the app refuse plain http.', proof(method, u, status, n, [`the request body has a field named ${k}`, 'the request used plain http']), 'CWE-319'))
    }

    // 5. Cookies set over https without Secure.
    if (u.protocol === 'https:')
      for (const c of e.response?.cookies ?? []) {
        const cn = String(c.name ?? '')
        if (cn && c.secure === false) put(f('low', `The cookie ${cn} from ${host} has no Secure flag`, host, `cookie-${cn}`, 'Without the Secure flag the cookie can also be sent over plain http, where it can be read.', 'Add the Secure flag when the server sets the cookie.', proof(method, u, status, n, [`the answer sets a cookie named ${cn}`, 'the cookie has no Secure flag']), 'CWE-614'))
      }
  })

  const list = [...hosts].sort()
  const out = [...findings.values()]
  if (!entries.length)
    out.push({ id: fid('traffic', 'empty'), tool: 'MacSec traffic check', category: 'mobile', severity: 'info', confidence: 'possible', title: 'No traffic was captured', description: 'Nothing passed through the capture. The app may not use the proxy, or it may use certificate pinning and refuse the capture certificate (which is a good sign for MASVS-NETWORK-2, but pinning is not proven by an empty capture).' })
  else if (list.length)
    out.push({ id: fid('traffic', 'hosts'), tool: 'MacSec traffic check', category: 'mobile', severity: 'info', confidence: 'confirmed', title: `The app talked to ${list.length} server${list.length === 1 ? '' : 's'}`, file: list[0], description: `${list.slice(0, 60).join(', ')}. Check that each one belongs to you or to a service you chose.` })
  return { findings: out, hosts: list, requests: entries.length }
}
