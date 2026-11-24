/**
 * A small request function whose DNS answer can be pinned.
 *
 * Plain `fetch` re-resolves the name for every request, so a server that changes its answer between
 * the guard's lookup and the connection (DNS rebinding) still gets the request. This client takes
 * the address the guard approved and connects to exactly that address, with the original name in
 * the Host header and in TLS SNI. It never follows a redirect and it verifies the certificate.
 */
import http, { type IncomingHttpHeaders } from 'http'
import https from 'https'

export interface PinnedResponse {
  status: number
  headers: Headers
  body: string
  url: string
}

export interface PinnedOptions {
  method?: string
  headers?: Record<string, string>
  body?: string
  timeoutMs?: number
  /** The address the guard approved for this host. When set, DNS is never consulted. */
  address?: string | null
  maxBytes?: number
}

const toHeaders = (raw: IncomingHttpHeaders): Headers => {
  const h = new Headers()
  for (const [k, v] of Object.entries(raw)) {
    if (v === undefined) continue
    if (Array.isArray(v)) for (const one of v) h.append(k, one)
    else h.append(k, String(v))
  }
  return h
}

export function pinnedRequest(url: string, o: PinnedOptions = {}): Promise<PinnedResponse> {
  return new Promise((resolve, reject) => {
    let u: URL
    try {
      u = new URL(url)
    } catch {
      reject(new Error('That is not a full address.'))
      return
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      reject(new Error('Only http and https are requested.'))
      return
    }
    const mod = u.protocol === 'https:' ? https : http
    const headers: Record<string, string> = { ...(o.headers ?? {}) }
    if (o.body !== undefined && !Object.keys(headers).some((k) => k.toLowerCase() === 'content-length')) headers['Content-Length'] = String(Buffer.byteLength(o.body))
    const address = o.address ?? null
    const req = mod.request(
      {
        protocol: u.protocol,
        hostname: u.hostname,
        port: u.port || undefined,
        path: `${u.pathname}${u.search}`,
        method: o.method ?? 'GET',
        headers,
        timeout: o.timeoutMs ?? 20000,
        // The name stays the name; only its resolution is replaced. TLS SNI keeps the name too.
        ...(u.protocol === 'https:' ? { servername: u.hostname } : {}),
        ...(address
          ? {
              // Node asks with { all: true } on modern versions, so both shapes are answered.
              lookup: ((_h: string, opts: { all?: boolean } | undefined, cb: (...args: unknown[]) => void): void => {
                const family = address.includes(':') ? 6 : 4
                if (opts?.all) cb(null, [{ address, family }])
                else cb(null, address, family)
              }) as never
            }
          : {}),
        rejectUnauthorized: true
      },
      (res) => {
        const chunks: Buffer[] = []
        let bytes = 0
        const cap = o.maxBytes ?? 400_000
        res.on('data', (c: Buffer) => {
          bytes += c.length
          if (bytes <= cap) chunks.push(c)
        })
        res.on('end', () => {
          resolve({ status: res.statusCode ?? 0, headers: toHeaders(res.headers), body: Buffer.concat(chunks).toString('utf8'), url })
        })
        res.on('error', reject)
      }
    )
    req.on('timeout', () => req.destroy(new Error('The request took too long.')))
    req.on('error', reject)
    if (o.body !== undefined) req.write(o.body)
    req.end()
  })
}
