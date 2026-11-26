/**
 * A drop-in `fetch` for the checks that read a site directly (its scripts, headers, pages, API answers).
 * It asks the network guard first and then connects to the address the guard approved (`netclient.ts`),
 * so the answer cannot change between the check and the connection. Redirects are only followed when the
 * caller did not say "manual", only on the same host, at most three times, and every hop is guarded.
 * It sends nothing the caller did not ask for.
 */
import { NetGuard, sharedGuard } from './netguard'
import { pinnedRequest } from './netclient'

const NO_BODY = new Set([101, 204, 205, 304])

export function guardedFetch(guard: NetGuard = sharedGuard, request: typeof pinnedRequest = pinnedRequest): typeof fetch {
  return (async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
    let url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const method = (init?.method ?? 'GET').toUpperCase()
    const headers = Object.fromEntries(new Headers(init?.headers as HeadersInit | undefined).entries())
    const follow = init?.redirect !== 'manual' && init?.redirect !== 'error'
    const first = new URL(url)
    for (let hop = 0; ; hop++) {
      const host = new URL(url).hostname
      await guard.check(host)
      const r = await request(url, { method, headers, address: guard.addressFor(host), timeoutMs: 15000 })
      const loc = r.headers.get('location')
      if (follow && hop < 3 && r.status >= 300 && r.status < 400 && loc) {
        const next = new URL(loc, url)
        if (next.host === first.host) {
          url = next.href
          continue
        }
      }
      const res = new Response(NO_BODY.has(r.status) || method === 'HEAD' ? null : r.body, { status: r.status, headers: r.headers })
      Object.defineProperty(res, 'url', { value: url })
      return res
    }
  }) as typeof fetch
}
