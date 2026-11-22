/**
 * JSON Web Tokens (JWT), from the person's own sign-in. MacSec reads the tokens it is given or sees,
 * and never makes up a login:
 *
 *   What the token says     no signature ("none"), no expiry or a very long one, secrets or other
 *                           sensitive claims, a key address (jku, x5u) or a path-like key id (kid)
 *   A weak signing secret   the signature is checked offline against a short list of the usual weak
 *                           secrets. The secret itself is never written down: only that it was on the list
 *   Where the token lives   in a cookie without HttpOnly, in a page address, or in a public page
 *   Does the server check?  the same token with its signature removed, or with "alg":"none", is sent
 *                           to a page that treats signed-in and signed-out visitors differently. If the
 *                           server answers as it does for the real token, it does not check signatures.
 *                           The claims are never changed: this is the person's own identity, not a
 *                           forged one, and it is only a GET.
 *
 * Token values are never put in a finding, a log or a proof: only the algorithm, claim names and
 * lifetimes, and a fingerprint of the token.
 */
import { createHash, createHmac } from 'crypto'
import type { Finding } from '../shared/types'
import { ConfirmClient, similar, Stop, type Reply } from './confirmtests'
import { fid } from './scanners/parse'
import { proofOf } from './seckit/confirm'

export interface Jwt {
  token: string
  header: Record<string, unknown>
  payload: Record<string, unknown>
  signature: string
}

export interface Found extends Jwt {
  /** Where it was seen, in words, for example "the cookie session". */
  where: string
  /** How to put a changed token back where it came from. */
  put?: (headers: Record<string, string>, token: string) => Record<string, string>
}

const b64 = (s: string): Buffer => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
const b64u = (b: Buffer | string): string => Buffer.from(b).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_')
const TOKEN = /eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/g

export function decodeJwt(token: string): Jwt | null {
  const p = token.split('.')
  if (p.length !== 3) return null
  try {
    const header = JSON.parse(b64(p[0]).toString('utf8')) as unknown
    const payload = JSON.parse(b64(p[1]).toString('utf8')) as unknown
    if (!header || typeof header !== 'object' || Array.isArray(header) || !payload || typeof payload !== 'object' || Array.isArray(payload)) return null
    if (typeof (header as Record<string, unknown>).alg !== 'string') return null
    return { token, header: header as Record<string, unknown>, payload: payload as Record<string, unknown>, signature: p[2] }
  } catch {
    return null
  }
}

/** The tokens in the headers the person gave (cookie, Authorization), with a way to replace each one. */
export function tokensInHeaders(headers: Record<string, string>): Found[] {
  const out: Found[] = []
  for (const [name, value] of Object.entries(headers)) {
    for (const m of value.matchAll(TOKEN)) {
      const j = decodeJwt(m[0])
      if (!j) continue
      const lower = name.toLowerCase()
      let where = `the ${name} header`
      if (lower === 'cookie') {
        const cn = new RegExp(`([A-Za-z0-9_.-]+)=${m[0].replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`).exec(value)
        where = `the cookie ${cn?.[1] ?? '(unnamed)'}`
      } else if (lower === 'authorization') where = 'the Authorization header'
      out.push({ ...j, where, put: (h, t) => ({ ...h, [name]: h[name].split(m[0]).join(t) }) })
    }
  }
  return out
}

/** Tokens that a response sets as a cookie, with whether the cookie is HttpOnly. */
export function tokenCookies(replies: Reply[]): { name: string; jwt: Jwt; httpOnly: boolean; secure: boolean; url: string; reply: Reply }[] {
  const out: { name: string; jwt: Jwt; httpOnly: boolean; secure: boolean; url: string; reply: Reply }[] = []
  for (const r of replies) {
    const cookies = (r.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie?.() ?? (r.headers.get('set-cookie') ? [r.headers.get('set-cookie')!] : [])
    for (const c of cookies) {
      const m = /^([^=;\s]+)=([^;]*)/.exec(c)
      if (!m) continue
      const j = decodeJwt(m[2])
      if (j) out.push({ name: m[1], jwt: j, httpOnly: /;\s*httponly/i.test(c), secure: /;\s*secure/i.test(c), url: r.url, reply: r })
    }
  }
  return out
}

/** Tokens in the address or the redirect of an answer. */
export function tokensInUrls(replies: Reply[]): { jwt: Jwt; url: string; reply: Reply; where: string }[] {
  const out: { jwt: Jwt; url: string; reply: Reply; where: string }[] = []
  for (const r of replies) {
    for (const [where, addr] of [['the page address', r.url], ['a redirect', r.headers.get('location') ?? '']] as const) {
      const m = addr.match(TOKEN)
      const j = m && decodeJwt(m[0])
      if (j) out.push({ jwt: j, url: r.url, reply: r, where })
    }
  }
  return out
}

/** Tokens embedded in the text of public pages (not in the person's own headers). */
export function tokensInPages(replies: Reply[]): { jwt: Jwt; reply: Reply }[] {
  const out: { jwt: Jwt; reply: Reply }[] = []
  for (const r of replies) {
    if (r.status !== 200) continue
    const m = r.body.match(TOKEN)
    for (const t of new Set(m ?? [])) {
      const j = decodeJwt(t)
      if (j) out.push({ jwt: j, reply: r })
    }
  }
  return out
}

export const WEAK_SECRETS = ['secret', 'password', 'changeme', 'change-me', 'changeit', 'admin', '123456', '12345678', 'qwerty', 'test', 'testing', 'jwt', 'jwtsecret', 'jwt_secret', 'jwt-secret', 'mysecret', 'my_secret', 'mysecretkey', 'secretkey', 'secret_key', 'supersecret', 'super-secret', 'your-256-bit-secret', 'your-secret', 'your_secret_key', 'key', 'private', 'default', 'letmein', 'token', 'app_secret', 'appsecret', 'hs256', 'hs256-secret', 'dev', 'development', 'production', 'laravel', 'django', 'flask', 'express', 'node', 'example', 's3cr3t', 'p@ssw0rd', 'abc123', 'password123', 'qwerty123', 'secret123', '']

/** The signature check done offline for HS256, HS384 and HS512. Returns the length of the secret if it is on the list. */
export function weakSecret(j: Jwt, list: string[] = WEAK_SECRETS): number | null {
  const algs: Record<string, string> = { HS256: 'sha256', HS384: 'sha384', HS512: 'sha512' }
  const alg = algs[String(j.header.alg).toUpperCase()]
  if (!alg) return null
  const [h, p] = j.token.split('.')
  const want = Buffer.from(j.signature.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
  if (!want.length) return null
  for (const s of list) {
    const got = createHmac(alg, s).update(`${h}.${p}`).digest()
    if (got.length === want.length && got.equals(want)) return s.length
  }
  return null
}

const fingerprint = (t: string): string => createHash('sha256').update(t).digest('hex')
const SENSITIVE = /^(password|passwd|pwd|secret|client_secret|api_?key|apikey|private_?key|ssn|credit_?card|card_?number|cvv|pin)$/i

const proofFor = (j: Jwt, where: string, shows: string[], reproduce: string) => ({
  request: `read the token in ${where} (its value is not kept)`,
  reproduce,
  status: 0,
  bytes: j.token.length,
  sha256: fingerprint(j.token),
  at: new Date().toISOString(),
  shows: shows.slice(0, 12)
})

const seconds = (s: number): string => (s >= 86400 * 365 ? `${Math.round(s / 86400 / 365)} years` : s >= 86400 ? `${Math.round(s / 86400)} days` : s >= 3600 ? `${Math.round(s / 3600)} hours` : `${Math.round(s / 60)} minutes`)

/** What a token says about itself, and what an offline check shows. No request is sent. */
export function tokenChecks(f: Found): Finding[] {
  const out: Finding[] = []
  const { header: h, payload: p } = f
  const alg = String(h.alg)
  const base = { tool: 'MacSec', category: 'web' as const, url: undefined as string | undefined }
  const key = `${f.where}|${alg}|${Object.keys(p).sort().join(',')}`
  const claimNames = Object.keys(p).slice(0, 12).join(', ')
  if (alg.toLowerCase() === 'none' || !f.signature)
    out.push({ id: fid('jwt-nosig', key), ...base, confidence: 'confirmed', severity: 'critical', title: `A token in ${f.where} has no signature`, cwe: 'CWE-347', description: `The token uses "${alg}" with ${f.signature ? 'a signature' : 'an empty signature'}. Anyone can write such a token with any claims, including another user's id or an admin role. Claims in it: ${claimNames}.`, fix: 'Sign every token with a strong algorithm (RS256, ES256 or HS256 with a long random secret) and make the server reject tokens whose algorithm is not the one it expects.', proof: proofFor(f, f.where, [`header alg is "${alg}"`, f.signature ? 'the signature part is present' : 'the signature part is empty', `claims: ${claimNames}`], 'echo <token> | cut -d. -f1 | base64 -d') })
  const weak = weakSecret(f)
  if (weak !== null)
    out.push({ id: fid('jwt-weak', key), ...base, confidence: 'confirmed', severity: 'critical', title: `A token in ${f.where} is signed with a weak secret`, cwe: 'CWE-1391', description: `The signature matches a secret from a short list of common weak secrets (${weak} characters long; the secret is not written here). With the secret, anyone can create tokens for any user. Claims in it: ${claimNames}.`, fix: 'Change the signing secret to a random value of at least 32 bytes, then sign out every user (old tokens stay valid until the secret changes). Better: use an asymmetric key pair.', proof: proofFor(f, f.where, [`HMAC (${alg}) over the token matches a secret on MacSec's list of ${WEAK_SECRETS.length} weak secrets`, `the secret is ${weak} characters long`, 'the secret itself is not stored'], `jwt_tool <your token> -C -d <a wordlist with the common secrets>`) })
  const exp = typeof p.exp === 'number' ? p.exp : null
  const iat = typeof p.iat === 'number' ? p.iat : typeof p.nbf === 'number' ? p.nbf : null
  if (exp === null)
    out.push({ id: fid('jwt-noexp', key), ...base, confidence: 'confirmed', severity: 'low', title: `A token in ${f.where} never expires`, cwe: 'CWE-613', description: `The token has no "exp" claim, so a copy stays valid until the secret is changed. Claims in it: ${claimNames}.`, fix: 'Give access tokens a short life (minutes to an hour) and use refresh tokens that can be revoked.', proof: proofFor(f, f.where, ['no "exp" claim', `claims: ${claimNames}`], 'echo <token> | cut -d. -f2 | base64 -d') })
  else if (iat !== null && exp - iat > 86400 * 30)
    out.push({ id: fid('jwt-longexp', key), ...base, confidence: 'confirmed', severity: 'low', title: `A token in ${f.where} lives for ${seconds(exp - iat)}`, cwe: 'CWE-613', description: `The token is valid for ${seconds(exp - iat)} (exp minus iat). A stolen copy works for that long.`, fix: 'Shorten the life of access tokens and use revocable refresh tokens.', proof: proofFor(f, f.where, [`exp - iat = ${exp - iat} seconds (${seconds(exp - iat)})`], 'echo <token> | cut -d. -f2 | base64 -d') })
  const names = Object.keys(p).filter((k) => SENSITIVE.test(k))
  if (names.length)
    out.push({ id: fid('jwt-claims', key), ...base, confidence: 'confirmed', severity: 'medium', title: `A token in ${f.where} carries sensitive data (${names.join(', ')})`, cwe: 'CWE-200', description: `A token is signed, not encrypted: anyone who holds it can read it. It has claims named ${names.join(', ')}.`, fix: 'Keep secrets and personal data out of tokens. Put an id in the token and look the rest up on the server.', proof: proofFor(f, f.where, [`claim names: ${names.join(', ')}`, 'the values are not shown'], 'echo <token> | cut -d. -f2 | base64 -d') })
  const jku = ['jku', 'x5u', 'jwk'].filter((k) => k in h)
  if (jku.length)
    out.push({ id: fid('jwt-jku', key), ...base, confidence: 'possible', severity: 'medium', title: `A token in ${f.where} names where to get its key (${jku.join(', ')})`, cwe: 'CWE-345', description: `The header has ${jku.join(', ')}. If the server fetches the key from there without a strict allow-list, an attacker can host their own key and sign tokens. MacSec did not test this (it would send the server to another address): check by hand that the server only trusts its own key addresses.`, fix: 'Ignore jku, x5u and jwk from the token. Use only keys configured on the server.' })
  if (typeof h.kid === 'string' && /[./\\'";|`$]|\.\./.test(h.kid))
    out.push({ id: fid('jwt-kid', key), ...base, confidence: 'possible', severity: 'low', title: `A token in ${f.where} has a key id that looks like a path or a query`, cwe: 'CWE-22', description: 'The "kid" header contains characters used in file paths or database queries. If the server uses it to open a file or build a query, it can be abused. This is a lead only: it was not tested.', fix: 'Treat kid as an opaque label looked up in a fixed list, never as a path or part of a query.' })
  return out
}

/** Cookies, addresses and pages that carry a token. */
export function placementChecks(replies: Reply[]): Finding[] {
  const out: Finding[] = []
  for (const c of tokenCookies(replies)) {
    if (!c.httpOnly)
      out.push({ id: fid('jwt-cookie', c.name, new URL(c.url).origin), tool: 'MacSec', category: 'web', url: c.url, file: c.url, confidence: 'confirmed', severity: 'medium', title: `The cookie ${c.name} holds a token and is not HttpOnly`, cwe: 'CWE-1004', description: `The site sets a cookie that contains a JWT without the HttpOnly flag, so any script on the page (including an injected one) can read it and send it away.`, fix: 'Set HttpOnly (and Secure, and SameSite=Lax or Strict) on the cookie that holds the token.', proof: proofOf({ url: c.url, status: c.reply.status, headers: new Headers(), body: '', shows: [`Set-Cookie ${c.name} contains a JWT`, 'the cookie has no HttpOnly flag', 'the value is not shown'] }) })
  }
  for (const t of tokensInUrls(replies))
    out.push({ id: fid('jwt-url', new URL(t.url).pathname, t.where), tool: 'MacSec', category: 'web', url: t.url.replace(TOKEN, '…'), file: t.url.replace(TOKEN, '…'), confidence: 'confirmed', severity: 'medium', title: `A JWT travels in ${t.where === 'a redirect' ? 'a redirect address' : 'a page address'}: ${new URL(t.url).pathname}`, cwe: 'CWE-598', description: 'Addresses are written to browser history, proxy and server logs and sent in the Referer header, so a token in one is readable by others.', fix: 'Send tokens in a header or a cookie, never in an address.', proof: proofOf({ url: t.url.replace(TOKEN, '…'), status: t.reply.status, headers: t.reply.headers, body: '', shows: [`a JWT is in ${t.where}`, 'the value is not shown'] }) })
  for (const t of tokensInPages(replies)) {
    const exp = typeof t.jwt.payload.exp === 'number' ? t.jwt.payload.exp : null
    out.push({ id: fid('jwt-page', t.reply.url, fingerprint(t.jwt.token).slice(0, 8)), tool: 'MacSec', category: 'web', url: t.reply.url, file: t.reply.url, confidence: 'possible', severity: 'low', title: `A JWT is written into a public page: ${new URL(t.reply.url).pathname}`, cwe: 'CWE-200', description: `Signed out, the page contains a token with claims: ${Object.keys(t.jwt.payload).slice(0, 10).join(', ')}${exp && exp * 1000 < Date.now() ? ' (it has expired)' : ''}. If it is a public or anonymous token that is fine; if it belongs to a person or a service, it is exposed.`, fix: 'Check what the token allows and who it belongs to. Do not put tokens that carry rights into pages anyone can fetch.' })
  }
  return out
}

// ---------------------------------------------------------------- Does the server check signatures?

const tamper = (j: Jwt, how: 'none' | 'stripped'): string => {
  const [h, p] = j.token.split('.')
  if (how === 'stripped') return `${h}.${p}.`
  return `${b64u(JSON.stringify({ ...j.header, alg: 'none' }))}.${p}.`
}

/** Finds a page that treats the person's token differently from no token at all. */
async function pickProbe(c: ConfirmClient, urls: string[], headers: Record<string, string>): Promise<{ url: string; real: Reply; out: Reply } | null> {
  for (const u of urls.slice(0, 10)) {
    const real = await c.get(u, { headers }).catch((e) => (e instanceof Stop ? Promise.reject(e) : null))
    if (!real || real.status >= 400 || real.status < 200) continue
    const out = await c.get(u, { headers: 'none' }).catch((e) => (e instanceof Stop ? Promise.reject(e) : null))
    if (out && !similar(real, out)) return { url: u, real, out }
  }
  return null
}

/** Sends the person's own token without its signature, and with "alg":"none", and compares the answers. */
export async function signatureChecks(c: ConfirmClient, tokens: Found[], headers: Record<string, string>, urls: string[], note: (t: string) => void = () => undefined): Promise<Finding[]> {
  const out: Finding[] = []
  const usable = tokens.filter((t) => t.put)
  if (!usable.length) return out
  note('Looking for a page that treats the signed-in token differently')
  const probe = await pickProbe(c, urls, headers)
  if (!probe) {
    note('No page was found that answers differently with and without the token, so the signature test was skipped')
    return out
  }
  for (const t of usable) {
    for (const how of ['stripped', 'none'] as const) {
      const sent = t.put!(headers, tamper(t, how))
      const ask = (): Promise<Reply> => c.get(probe.url, { headers: sent })
      const r = await ask().catch((e) => (e instanceof Stop ? Promise.reject(e) : null))
      if (!r || !similar(r, probe.real) || similar(r, probe.out)) continue
      const again = await ask().catch(() => null)
      if (!again || !similar(again, probe.real)) continue
      out.push({ id: fid('jwt-unchecked', t.where, how), tool: 'MacSec', category: 'web', url: probe.url, file: probe.url, confidence: 'confirmed', severity: 'critical', title: `The server accepts a token ${how === 'none' ? 'with "alg":"none"' : 'with its signature removed'}: ${new URL(probe.url).pathname}`, cwe: 'CWE-347', description: `The token in ${t.where} was sent ${how === 'none' ? 'with its algorithm changed to "none"' : 'with the signature cut off'}, and the page answered as it does for the real token, not as it does for a visitor with no token. Nothing else in the token was changed (same user, same claims). The server does not check the signature, so anyone can write a token for any user.`, fix: 'Verify the signature on every request with a library that has a fixed list of allowed algorithms, and reject "none" and empty signatures.', proof: proofOf({ url: r.url, status: r.status, headers: r.headers, body: r.body.slice(0, 200000), shows: [`token sent ${how === 'none' ? 'with alg "none"' : 'without its signature'}, claims unchanged`, `answer matches the answer to the real token (status ${probe.real.status})`, `answer differs from the signed-out answer (status ${probe.out.status})`, 'the same on a second try', 'the token value is not shown'] }) })
      break
    }
  }
  return out
}

/** Everything about tokens in one go. */
export async function jwtChecks(c: ConfirmClient, o: { headers: Record<string, string>; replies: Reply[]; urls: string[] }, note: (t: string) => void = () => undefined): Promise<Finding[]> {
  const out: Finding[] = []
  const mine = tokensInHeaders(o.headers)
  for (const f of mine) out.push(...tokenChecks(f))
  for (const t of tokenCookies(o.replies)) out.push(...tokenChecks({ ...t.jwt, where: `the cookie ${t.name} the site sets` }))
  out.push(...placementChecks(o.replies))
  note(`${mine.length} ${mine.length === 1 ? 'token' : 'tokens'} in your sign-in headers`)
  try {
    out.push(...(await signatureChecks(c, mine, o.headers, o.urls, note)))
  } catch (e) {
    if (e instanceof Stop) note(e.message)
    else throw e
  }
  const seen = new Set<string>()
  return out.filter((f) => (seen.has(f.id) ? false : (seen.add(f.id), true)))
}
