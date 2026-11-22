/**
 * Sign-in with OAuth and OpenID Connect (Google, Microsoft, Okta, Auth0, Keycloak, your own server).
 * Everything here only reads, and every claim is tied to something that was seen:
 *
 *   From the sign-in links the site sends (read from its pages and redirects, no request to the provider):
 *     no "state" value        a login can be forced on a visitor (login CSRF)
 *     a fixed "state" value   the site sends the same state every time, so it protects nothing
 *     the implicit flow       tokens come back in the address (response_type=token)
 *     no PKCE                 a "code" flow without a code challenge: a lead only, it depends on the client type
 *     a plain http callback   the code or token travels without encryption
 *     tokens in addresses     access_token, id_token or refresh_token in a page address
 *   From the provider's own settings page (only when it is on the site being tested):
 *     weak settings           "none" signatures, "plain" PKCE, implicit and password grants, open client registration
 *   From the site's own authorization endpoint (only when it is on the site being tested):
 *     redirect_uri checks     made-up callback addresses with GET: if the server sends the visitor to one of them, it does not validate the callback
 *
 * Nothing is signed in, nothing is submitted, no provider that is not yours is contacted, and the
 * made-up callback addresses end in .invalid, which cannot exist. Every live hit is repeated once.
 */
import type { Finding } from '../shared/types'
import { ConfirmClient, Stop, type Reply } from './confirmtests'
import { fid } from './scanners/parse'
import { proofOf } from './seckit/confirm'

export interface AuthRequest {
  /** The full authorization address as the site sends it. */
  url: string
  params: Record<string, string>
  /** The answer that contained it: a page, or a redirect. */
  via: Reply
  /** A same-site address whose redirect leads here, when there is one. */
  starter?: string
}

const AUTH_URL = /https?:\/\/[^\s"'<>\\)]+?[?&](?:[^\s"'<>\\)]*&)?client_id=[^\s"'<>\\)]+/gi
const clean = (s: string): string => s.replace(/&amp;/g, '&').replace(/\\u0026/g, '&').replace(/\\\//g, '/').replace(/&#38;/g, '&')

const parse = (u: string): URL | null => {
  try {
    return new URL(u)
  } catch {
    return null
  }
}

/** The authorization requests in answers: in a page, or in the Location of a redirect. */
export function authRequestsFrom(replies: Reply[]): AuthRequest[] {
  const out = new Map<string, AuthRequest>()
  const add = (raw: string, via: Reply, starter?: string): void => {
    const u = parse(clean(raw).replace(/[.,;]+$/, ''))
    if (!u || !u.searchParams.has('client_id') || !u.searchParams.has('response_type')) return
    const key = `${u.origin}${u.pathname}|${u.searchParams.get('client_id')}`
    if (!out.has(key)) out.set(key, { url: u.href, params: Object.fromEntries(u.searchParams), via, starter })
  }
  for (const r of replies) {
    const loc = r.headers.get('location')
    if (loc) {
      let abs = loc
      try {
        abs = new URL(loc, r.url).href
      } catch {
        /* keep as is */
      }
      add(abs, r, r.url)
    }
    for (const m of r.body.matchAll(AUTH_URL)) add(m[0], r)
  }
  return [...out.values()]
}

const seen = (a: AuthRequest, shows: string[]) => proofOf({ url: a.via.url, status: a.via.status, headers: a.via.headers, body: a.via.body.slice(0, 300000), shows })
const hostOf = (u: string): string => parse(u)?.host ?? u
const mask = (u: string): string => u.replace(/([?&#](?:client_secret|code|access_token|id_token|refresh_token|token)=)[^&#]+/gi, '$1…')

/** What the sign-in links alone show. Nothing is sent. */
export function oauthPassive(reqs: AuthRequest[]): Finding[] {
  const out: Finding[] = []
  for (const a of reqs) {
    const p = a.params
    const where = hostOf(a.url)
    const base = { tool: 'MacSec', category: 'web' as const, url: mask(a.via.url), file: mask(a.via.url), confidence: 'confirmed' as const }
    const types = (p.response_type ?? '').split(/[\s+]+/)
    if (!p.state)
      out.push({ id: fid('oauth-nostate', a.via.url, where), ...base, severity: 'medium', title: `Sign-in with ${where} is started without a state value`, cwe: 'CWE-352', description: `The sign-in link the site sends to ${where} has no "state" parameter. Without it, an attacker can start a sign-in with their own account and trick a visitor into finishing it, which logs the visitor into the attacker's account (login CSRF). Link seen: ${mask(a.url).slice(0, 300)}`, fix: 'Create a random state value for each sign-in, keep it in the visitor’s session, send it with the request and refuse the answer if it does not come back unchanged. Most OAuth libraries do this when it is switched on.', proof: seen(a, ['the sign-in link has client_id and response_type but no state', `link: ${mask(a.url).slice(0, 160)}`]) })
    if (types.includes('token') || (types.includes('id_token') && !types.includes('code')))
      out.push({ id: fid('oauth-implicit', a.via.url, where), ...base, severity: 'medium', title: `Sign-in with ${where} uses the implicit flow (tokens in the address)`, cwe: 'CWE-598', description: `The sign-in link asks for response_type=${p.response_type}, so the token comes back in the address of the page. Addresses end up in browser history, logs and the Referer header. Current guidance (OAuth 2.0 Security Best Current Practice) says not to use this flow.`, fix: 'Use the authorization code flow with PKCE (response_type=code) and exchange the code on the server or with a code verifier.', proof: seen(a, [`response_type=${p.response_type}`, 'the token is returned in the address, not sent privately']) })
    if (types.includes('code') && !p.code_challenge)
      out.push({ id: fid('oauth-nopkce', a.via.url, where), ...base, confidence: 'possible', proof: undefined, severity: 'low', title: `Sign-in with ${where} sends no PKCE code challenge`, cwe: 'CWE-345', description: `The code-flow link has no code_challenge. PKCE stops a stolen code from being used. It matters most for apps that cannot keep a secret (single-page apps, mobile apps); a server-side app with a client secret is less exposed. This is a lead, not proof: check which kind of client this is.`, fix: 'Add PKCE (code_challenge with method S256) to every authorization request, and make the provider require it for this client.' })
    const cb = p.redirect_uri
    if (cb && /^http:\/\//i.test(cb) && !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])([:/]|$)/i.test(cb))
      out.push({ id: fid('oauth-httpcb', a.via.url, cb), ...base, severity: 'medium', title: `The sign-in callback uses plain http: ${hostOf(cb)}`, cwe: 'CWE-319', description: `The redirect_uri is ${cb.slice(0, 200)}. The code or token is sent back over an unencrypted connection, where anyone on the network can read it.`, fix: 'Register and use only https callback addresses.', proof: seen(a, [`redirect_uri=${cb.slice(0, 120)}`, 'the scheme is http, not https']) })
  }
  return out
}

/** Tokens that sit in the address of a page the site served or redirected to. Values are never kept. */
export function tokensInAddresses(replies: Reply[]): Finding[] {
  const out: Finding[] = []
  const seenKeys = new Set<string>()
  for (const r of replies) {
    const places: [string, string][] = [['the page address', r.url]]
    const loc = r.headers.get('location')
    if (loc) places.push(['a redirect', loc])
    for (const [what, addr] of places) {
      const m = /[?&#](access_token|id_token|refresh_token)=[^&#\s]{12,}/i.exec(addr)
      if (!m) continue
      const key = `${r.url}|${m[1]}`
      if (seenKeys.has(key)) continue
      seenKeys.add(key)
      const name = m[1].toLowerCase()
      out.push({ id: fid('oauth-tokenurl', key), tool: 'MacSec', category: 'web', url: mask(r.url), file: mask(r.url), confidence: 'confirmed', severity: name === 'refresh_token' ? 'high' : 'medium', title: `A ${name.replace('_', ' ')} travels in ${what === 'a redirect' ? 'a redirect address' : 'a page address'}: ${new URL(r.url).pathname}`, cwe: 'CWE-598', description: `${what[0].toUpperCase()}${what.slice(1)} contains ${name}=… (the value is not kept here). Addresses are saved in browser history, proxy and server logs and sent in the Referer header, so a token in one can be read by others.`, fix: 'Send tokens in a header or a cookie, or in the fragment only for the short moment of a redirect, and exchange them at once. Never put them in a query string.', proof: proofOf({ url: r.url.replace(/(access_token|id_token|refresh_token)=[^&#]+/gi, '$1=…'), status: r.status, headers: r.headers, body: r.body.slice(0, 100000), shows: [`${name} is in ${what}`, 'the value is hidden in this report'] }) })
    }
  }
  return out
}

// ---------------------------------------------------------------- The provider's settings page (same site only)

export const DISCOVERY = ['/.well-known/openid-configuration', '/.well-known/oauth-authorization-server']

export interface Discovery {
  reply: Reply
  doc: Record<string, unknown>
}

export async function readDiscovery(c: ConfirmClient): Promise<Discovery[]> {
  const out: Discovery[] = []
  for (const p of DISCOVERY) {
    const r = await c.get(p, { headers: 'none' }).catch((e) => {
      if (e instanceof Stop) throw e
      return null
    })
    if (!r || r.status !== 200 || !/json/i.test(r.headers.get('content-type') ?? '')) continue
    try {
      const doc = JSON.parse(r.body) as Record<string, unknown>
      if (typeof doc.issuer === 'string' && (doc.authorization_endpoint || doc.token_endpoint || doc.jwks_uri)) out.push({ reply: r, doc })
    } catch {
      /* not JSON */
    }
  }
  return out
}

const list = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [])

/** Weak settings stated in the provider's own settings document. */
export function discoveryChecks(d: Discovery): Finding[] {
  const out: Finding[] = []
  const { doc, reply } = d
  const path = new URL(reply.url).pathname
  const base = { tool: 'MacSec', category: 'web' as const, url: reply.url, file: reply.url, confidence: 'confirmed' as const }
  const proof = (shows: string[]) => proofOf({ url: reply.url, status: reply.status, headers: reply.headers, body: reply.body, shows })
  const idAlgs = list(doc.id_token_signing_alg_values_supported)
  if (idAlgs.map((a) => a.toLowerCase()).includes('none'))
    out.push({ id: fid('oidc-algnone', reply.url), ...base, severity: 'high', title: `The sign-in provider allows unsigned ID tokens ("none"): ${path}`, cwe: 'CWE-347', description: 'The settings list "none" among the signing methods for ID tokens. A token with no signature proves nothing, and an app that accepts it can be logged in as anyone.', fix: 'Remove "none" from id_token_signing_alg_values_supported and make every app require RS256, ES256 or another real signature.', proof: proof(['id_token_signing_alg_values_supported contains "none"']) })
  const pk = list(doc.code_challenge_methods_supported)
  if (pk.length && !pk.includes('S256'))
    out.push({ id: fid('oidc-plain', reply.url), ...base, severity: 'medium', title: `The sign-in provider supports only weak PKCE ("plain"): ${path}`, cwe: 'CWE-326', description: `code_challenge_methods_supported is ${pk.join(', ')}. With "plain" the challenge is the secret itself, so anyone who sees the request can use the code.`, fix: 'Support and require S256.', proof: proof([`code_challenge_methods_supported: ${pk.join(', ')}`, 'S256 is not listed']) })
  const rt = list(doc.response_types_supported)
  const implicit = rt.filter((t) => /(^|\s)token(\s|$)/.test(t) || t === 'id_token')
  if (implicit.length)
    out.push({ id: fid('oidc-implicit', reply.url), ...base, severity: 'low', title: `The sign-in provider still offers the implicit flow: ${path}`, cwe: 'CWE-598', description: `response_types_supported includes ${implicit.join(', ')}. The implicit flow returns tokens in the address. It is switched on here, not necessarily used.`, fix: 'Turn the implicit flow off for every client that does not need it.', proof: proof([`response_types_supported: ${implicit.join(', ')}`]) })
  if (list(doc.grant_types_supported).includes('password'))
    out.push({ id: fid('oidc-password', reply.url), ...base, severity: 'low', title: `The sign-in provider offers the password grant: ${path}`, cwe: 'CWE-522', description: 'The password grant lets an app collect the person’s username and password itself, which defeats single sign-on and cannot use multi-factor sign-in. Current guidance removes it.', fix: 'Turn the password grant off.', proof: proof(['grant_types_supported contains "password"']) })
  if (typeof doc.registration_endpoint === 'string')
    out.push({ id: fid('oidc-register', reply.url), ...base, confidence: 'possible', proof: proof([`registration_endpoint is ${String(doc.registration_endpoint).slice(0, 120)}`]), severity: 'low', title: `Clients can be registered by address: ${path}`, cwe: 'CWE-284', description: 'The settings advertise a registration endpoint. If it accepts anyone without a token, anybody can create an OAuth client for your provider. MacSec did not try it (that would create a record): test it by hand.', fix: 'Require an initial access token for dynamic client registration, or turn it off.' })
  const http = ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri'].filter((k) => typeof doc[k] === 'string' && /^http:\/\//i.test(String(doc[k])) && !/^http:\/\/(localhost|127\.)/.test(String(doc[k])))
  if (http.length)
    out.push({ id: fid('oidc-http', reply.url), ...base, severity: 'medium', title: `The sign-in provider publishes plain http addresses: ${path}`, cwe: 'CWE-319', description: `These addresses in the settings use http: ${http.join(', ')}.`, fix: 'Publish https addresses only, and set the public URL of the provider correctly behind a proxy.', proof: proof(http.map((k) => `${k} starts with http://`)) })
  const origin = new URL(reply.url).origin
  if (typeof doc.issuer === 'string' && doc.issuer.replace(/\/+$/, '') !== origin && parse(doc.issuer)?.host === new URL(origin).host)
    out.push({ id: fid('oidc-issuer', reply.url), ...base, severity: 'low', title: `The provider's issuer differs from the address it is served on: ${path}`, cwe: 'CWE-345', description: `The issuer is ${doc.issuer} but the settings were read at ${origin}. A wrong issuer breaks the check apps make on tokens (and can enable mix-up attacks).`, fix: 'Set the issuer to the exact public address, with the right scheme and no extra path.', proof: proof([`issuer ${doc.issuer}`, `served at ${origin}`]) })
  return out
}

// ---------------------------------------------------------------- Live checks on the site's own sign-in start and authorization endpoint

const rnd = (): string => Math.random().toString(36).slice(2, 8)

/** Whether the "state" value is the same on two fresh sign-in starts. */
export async function stateChecks(c: ConfirmClient, reqs: AuthRequest[]): Promise<Finding[]> {
  const out: Finding[] = []
  for (const a of reqs) {
    if (!a.starter || parse(a.starter)?.origin !== c.origin || !a.params.state) continue
    const get = async (): Promise<Reply | null> => c.get(a.starter!, { headers: 'none' }).catch((e) => (e instanceof Stop ? Promise.reject(e) : null))
    const r1 = await get()
    const r2 = await get()
    const s = (r: Reply | null): string | null => {
      const l = r?.headers.get('location')
      if (!l) return null
      try {
        return new URL(l, r!.url).searchParams.get('state')
      } catch {
        return null
      }
    }
    const a1 = s(r1)
    const a2 = s(r2)
    if (r2 && a1 && a1 === a2 && a1.length >= 1)
      out.push({ id: fid('oauth-staticstate', a.starter), tool: 'MacSec', category: 'web', url: a.starter, file: a.starter, confidence: 'confirmed', severity: 'medium', title: `The sign-in state value never changes: ${new URL(a.starter).pathname}`, cwe: 'CWE-330', description: 'Two fresh visits to the sign-in start sent the same state value. A state that is the same every time (or the same for everyone) cannot protect a login from being forced by an attacker.', fix: 'Generate a new random state for each sign-in and check it when the visitor comes back.', proof: proofOf({ url: a.starter, status: r2.status, headers: r2.headers, body: '', shows: [`first visit: state is ${a1.length > 8 ? `${a1.slice(0, 4)}… (${a1.length} characters)` : a1}`, 'second visit: the same state', 'a fresh, signed-out visit each time'] }) })
  }
  return out
}

/** Callback variants that must be refused. The hosts end in .invalid, which cannot exist. */
export function callbackVariants(registered: string): { label: string; value: string }[] {
  const u = parse(registered)
  const bad = `https://macsec-${rnd()}.invalid`
  const out = [{ label: 'a completely different address', value: `${bad}/callback` }]
  if (u && /^https?:$/.test(u.protocol)) {
    out.push({ label: 'the registered host with another domain added at the end', value: `${u.protocol}//${u.host}.macsec-${rnd()}.invalid${u.pathname}` })
    out.push({ label: 'the registered address followed by "@" and another host', value: `${u.protocol}//${u.host}@macsec-${rnd()}.invalid${u.pathname}` })
  }
  return out
}

/** Whether a redirect leads to the made-up host, and what it carries. */
export function leadsTo(r: Reply, marker: string): { carries: string[] } | null {
  const loc = r.headers.get('location')
  if (!loc || r.status < 300 || r.status >= 400) return null
  const u = parse(new URL(loc, r.url).href)
  if (!u || !u.hostname.endsWith('.invalid') || !u.hostname.includes(marker)) return null
  const q = new URLSearchParams(u.search + (u.hash ? `&${u.hash.slice(1)}` : ''))
  return { carries: ['code', 'access_token', 'id_token', 'error'].filter((k) => q.has(k)) }
}

/** Sends made-up callback addresses to the site's own authorization endpoint. */
export async function redirectUriChecks(c: ConfirmClient, reqs: AuthRequest[], note: (t: string) => void = () => undefined): Promise<Finding[]> {
  const out: Finding[] = []
  for (const a of reqs) {
    const au = parse(a.url)
    if (!au || au.origin !== c.origin || !a.params.redirect_uri) continue
    for (const v of callbackVariants(a.params.redirect_uri)) {
      const marker = /macsec-([a-z0-9]+)\.invalid/.exec(v.value)![0].replace(/\.invalid$/, '')
      const ask = (): Promise<Reply> => {
        const q = new URLSearchParams(au.search)
        q.set('redirect_uri', v.value)
        return c.get(`${au.origin}${au.pathname}?${q.toString()}`, { headers: 'none' })
      }
      note(`redirect_uri: ${v.label}`)
      const r = await ask().catch((e) => (e instanceof Stop ? Promise.reject(e) : null))
      const hit = r && leadsTo(r, marker)
      if (!r || !hit) continue
      const again = await ask().catch(() => null)
      if (!again || !leadsTo(again, marker)) continue
      const takes = hit.carries.filter((k) => k !== 'error').length > 0
      out.push({ id: fid('oauth-redirecturi', au.pathname, v.label), tool: 'MacSec', category: 'web', url: r.url, file: r.url, confidence: 'confirmed', severity: takes ? 'critical' : 'high', title: `The authorization endpoint accepts a callback it was never given: ${au.pathname}`, cwe: 'CWE-601', description: `Asked to send the visitor back to ${v.label} (${v.value.slice(0, 120)}), the server answered with a redirect to that address${takes ? ` and put ${hit.carries.filter((k) => k !== 'error').join(' and ')} in it` : hit.carries.length ? ` with ${hit.carries.join(', ')} in it` : ''}. The address ends in .invalid, which cannot exist, so nothing was sent anywhere. If an attacker can pick the callback, they receive the visitor's code or token.`, fix: 'Compare the redirect_uri to the registered one as an exact string (no prefixes, no wildcards, no extra hosts), and refuse the request with an error page, never a redirect, when it does not match.', proof: proofOf({ url: r.url, status: r.status, headers: r.headers, body: '', shows: [`redirect_uri was ${v.label}`, `the server redirected to ${new URL(r.headers.get('location')!, r.url).origin}`, 'the same on a second try', 'the made-up host ends in .invalid and cannot receive anything'] }) })
      break
    }
  }
  return out
}

export const START_PATHS = ['/login/google', '/auth/google', '/login/github', '/auth/github', '/login/microsoft', '/auth/microsoft', '/oauth/login', '/oauth2/authorization/google', '/sso', '/sso/login', '/auth/login', '/login/oauth', '/connect/google', '/signin/google', '/api/auth/signin/google']

/** Same-site addresses that look like the start of a sign-in with a provider, from the crawl and the usual names. */
export function startCandidates(urls: string[], origin: string): string[] {
  const own = urls.filter((u) => {
    const p = parse(u)
    return p && p.origin === origin && /(oauth|sso|\/auth\/|login\/|signin\/|connect\/|authorize)/i.test(p.pathname) && !/\.(js|css|png|jpe?g|svg|map|woff2?)$/i.test(p.pathname)
  })
  return [...new Set([...own, ...START_PATHS.map((p) => `${origin}${p}`)])].slice(0, 20)
}

/** Everything above, in order. Returns the findings and the authorization requests that were found. */
export async function oauthChecks(c: ConfirmClient, o: { pages: Reply[]; urls: string[] }, note: (t: string) => void = () => undefined): Promise<Finding[]> {
  const out: Finding[] = []
  const replies = [...o.pages]
  try {
    note('Looking for sign-in starts')
    for (const u of startCandidates(o.urls, c.origin)) {
      const r = await c.get(u, { headers: 'none' }).catch((e) => (e instanceof Stop ? Promise.reject(e) : null))
      if (r && r.status >= 300 && r.status < 400) replies.push(r)
    }
    const reqs = authRequestsFrom(replies)
    note(`${reqs.length} sign-in ${reqs.length === 1 ? 'request' : 'requests'} found`)
    out.push(...oauthPassive(reqs), ...tokensInAddresses(replies))
    for (const d of await readDiscovery(c)) out.push(...discoveryChecks(d))
    out.push(...(await stateChecks(c, reqs)))
    out.push(...(await redirectUriChecks(c, reqs, note)))
  } catch (e) {
    if (e instanceof Stop) note(e.message)
    else throw e
  }
  const seenIds = new Set<string>()
  return out.filter((f) => (seenIds.has(f.id) ? false : (seenIds.add(f.id), true)))
}
