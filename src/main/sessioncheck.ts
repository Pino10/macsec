/**
 * Cross-site requests and sessions, tested with GET only and made-up values:
 *
 *   CORS                a made-up website address (ending .invalid) is sent as the Origin. If the
 *                       server repeats it back in Access-Control-Allow-Origin together with
 *                       Access-Control-Allow-Credentials: true, any site can read private answers
 *                       with the visitor's cookies. The same for "null" and for look-alike hosts
 *   CSRF                forms that send data and carry no hidden token, on a site whose session cookie
 *                       has no SameSite setting. This is a lead (a form is never submitted)
 *   Session ids         a session id in an address (jsessionid, PHPSESSID in a link), and a server
 *                       that adopts a session id the visitor made up (the first half of session fixation)
 *
 * Nothing is signed in or changed. Every hit is repeated once and keeps its proof.
 */
import type { Finding } from '../shared/types'
import { ConfirmClient, parseForms, risky, Stop, type Reply } from './confirmtests'
import { fid } from './scanners/parse'
import { proofOf } from './seckit/confirm'

const rnd = (): string => Math.random().toString(36).slice(2, 8)
const STATIC = /\.(png|jpe?g|gif|svg|ico|webp|css|js|map|woff2?|ttf|pdf|zip|mp4|mp3)(\?|$)/i

const allow = (r: Reply): { origin: string | null; creds: boolean } => ({ origin: r.headers.get('access-control-allow-origin'), creds: (r.headers.get('access-control-allow-credentials') ?? '').toLowerCase() === 'true' })

/** The origins to try: a made-up site, "null", and look-alikes of the real host. */
export function corsOrigins(host: string): { label: string; value: string }[] {
  const id = rnd()
  return [
    { label: 'a made-up website', value: `https://macsec-${id}.invalid` },
    { label: 'the "null" origin', value: 'null' },
    { label: 'the real host with another domain added', value: `https://${host}.macsec-${id}.invalid` },
    { label: 'a look-alike that ends with the real host', value: `https://macsec-${id}${host}` }
  ]
}

/** Answers that repeat a foreign origin with credentials allowed. Public data that is meant to be public is not flagged. */
export async function corsChecks(c: ConfirmClient, urls: string[], o: { account?: Record<string, string>; note?: (t: string) => void } = {}): Promise<Finding[]> {
  const out: Finding[] = []
  const host = new URL(c.base).host
  const pages = [...new Set([c.base, ...urls.filter((u) => { try { return new URL(u).origin === c.origin && !STATIC.test(u) && !risky(u) } catch { return false } })])].slice(0, 10)
  const seen = new Set<string>()
  try {
    for (const p of pages) {
      for (const v of corsOrigins(host)) {
        const send = (headers: Record<string, string>): Promise<Reply> => c.get(p, { headers: { ...headers, Origin: v.value } })
        const tries: { signedIn: boolean; headers: Record<string, string> }[] = [{ signedIn: false, headers: {} }]
        if (o.account && Object.keys(o.account).length) tries.push({ signedIn: true, headers: o.account })
        for (const t of tries) {
          const r = await send(t.headers).catch((e) => (e instanceof Stop ? Promise.reject(e) : null))
          if (!r) continue
          const a = allow(r)
          const reflected = a.origin === v.value
          if (!reflected || !a.creds) continue
          const key = `${new URL(p).pathname}|${v.label}|${t.signedIn}`
          if (seen.has(key)) continue
          const again = await send(t.headers).catch(() => null)
          if (!again || allow(again).origin !== v.value || !allow(again).creds) continue
          seen.add(key)
          o.note?.(`CORS: ${new URL(p).pathname} repeats ${v.label}`)
          out.push({ id: fid('cors-reflect', new URL(p).pathname, v.label, String(t.signedIn)), tool: 'MacSec', category: 'web', url: r.url, file: r.url, confidence: 'confirmed', severity: t.signedIn ? 'high' : 'medium', title: `Any website can read ${t.signedIn ? 'private ' : ''}answers here with the visitor's cookies: ${new URL(p).pathname}`, cwe: 'CWE-942', description: `Sent ${v.label} (${v.value}) as the Origin, the server answered Access-Control-Allow-Origin: ${a.origin} with Access-Control-Allow-Credentials: true${t.signedIn ? ', on a page that needs sign-in' : ''}. A page on that address could then read this answer in a visitor's browser using the visitor's session. The origin ends in .invalid or is made up, so nothing was sent to a real site.`, fix: 'Do not reflect the Origin header. Keep an exact list of the sites that may call the API, compare as exact strings, never allow "null", and send Allow-Credentials only to listed origins.', proof: proofOf({ url: r.url, status: r.status, headers: r.headers, body: '', shows: [`Origin sent: ${v.value}`, `Access-Control-Allow-Origin: ${a.origin}`, 'Access-Control-Allow-Credentials: true', 'the same on a second try', t.signedIn ? 'asked with the signed-in account' : 'asked signed out'], sent: { Origin: v.value } }) })
        }
      }
    }
  } catch (e) {
    if (e instanceof Stop) o.note?.(e.message)
    else throw e
  }
  return out
}

// ---------------------------------------------------------------- CSRF leads

const TOKEN_FIELD = /(csrf|xsrf|authenticity|_token$|^token$|nonce|__requestverificationtoken|verification|formkey|form_key|anti-?forgery|wpnonce)/i
const BORING = /(search|query|q|login|signin|sign-in|logon|subscribe|newsletter)/i

/** The cookies a site sets and whether they carry a SameSite value. */
export function cookieSamesite(replies: Reply[]): { name: string; samesite: string | null }[] {
  const out: { name: string; samesite: string | null }[] = []
  for (const r of replies) {
    const list = (r.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie?.() ?? (r.headers.get('set-cookie') ? [r.headers.get('set-cookie')!] : [])
    for (const c of list) {
      const m = /^([^=;\s]+)=/.exec(c)
      if (!m) continue
      const ss = /;\s*samesite=(\w+)/i.exec(c)
      out.push({ name: m[1], samesite: ss ? ss[1].toLowerCase() : null })
    }
  }
  return out
}

/** Forms that send data and have no hidden token, as leads. */
export function csrfLeads(pages: { url: string; html: string }[], cookies: { name: string; samesite: string | null }[]): Finding[] {
  const weak = cookies.filter((c) => !c.samesite || c.samesite === 'none')
  const session = cookies.filter((c) => /sess|sid|auth|token|jwt|login/i.test(c.name))
  const exposed = session.length ? session.filter((c) => !c.samesite || c.samesite === 'none') : weak
  const bad: { page: string; action: string; fields: string[] }[] = []
  for (const p of pages) {
    for (const f of parseForms(p.html)) {
      if (f.method !== 'post') continue
      const names = f.inputs.map((i) => i.name)
      if (names.some((n) => TOKEN_FIELD.test(n))) continue
      if (f.inputs.some((i) => i.type === 'password') && names.length <= 3) continue
      const action = f.action || p.url
      if (BORING.test(action) && !names.some((n) => /email|name|message|comment|amount|account/i.test(n))) continue
      let abs = action
      try {
        abs = new URL(action, p.url).href
      } catch {
        /* keep */
      }
      bad.push({ page: p.url, action: abs, fields: names.slice(0, 8) })
    }
  }
  if (!bad.length) return []
  const uniq = [...new Map(bad.map((b) => [b.action, b])).values()]
  const cookieNote = exposed.length ? `The cookies ${exposed.map((c) => c.name).slice(0, 4).join(', ')} are sent without a SameSite setting, so a form on another site can still be submitted with them in some browsers and flows.` : 'The cookies seen have SameSite set, which blocks many cross-site posts, but a token is still the proper defence.'
  return [{ id: fid('csrf-lead', uniq.map((u) => u.action).join('|')), tool: 'MacSec', category: 'web', confidence: 'possible', severity: exposed.length ? 'medium' : 'low', title: `${uniq.length} ${uniq.length === 1 ? 'form that sends data has' : 'forms that send data have'} no anti-forgery token`, cwe: 'CWE-352', description: `No hidden field that looks like a CSRF token was found in: ${uniq.slice(0, 8).map((u) => `${(() => { try { return new URL(u.action).pathname } catch { return u.action } })()} [${u.fields.join(', ')}]`).join('; ')}${uniq.length > 8 ? '; and more' : ''}. ${cookieNote} This is a lead: MacSec never submits a form, and the site may protect these another way (a header, a double-submit cookie). Test by hand: submit the form from a page on another address while signed in.`, fix: 'Add a per-session anti-forgery token to every form that changes data (your framework has one: Laravel @csrf, Django {% csrf_token %}, Rails protect_from_forgery) and set SameSite=Lax on session cookies.' }]
}

// ---------------------------------------------------------------- Session ids

const SESSION_COOKIES = /^(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|ASPSESSIONID\w*|connect\.sid|sessionid|session_id|sid|SESSION|CFID|CFTOKEN)$/i
const MASK_SESSION = (u: string): string => u.replace(/([;?&](?:jsessionid|phpsessid|sessionid|session_id|aspsessionid\w*|sid|sessid)=)[A-Za-z0-9._-]{8,}/gi, '$1…')
const SESSION_IN_URL = /[;?&](jsessionid|phpsessid|sessionid|session_id|aspsessionid\w*|sid|sessid)=[A-Za-z0-9._-]{8,}/i

export function sessionsInUrls(replies: Reply[], urls: string[]): Finding[] {
  const out: Finding[] = []
  const seen = new Set<string>()
  for (const r of replies) {
    for (const [where, addr] of [['the page address', r.url], ['a redirect', r.headers.get('location') ?? '']] as const) {
      const m = SESSION_IN_URL.exec(addr)
      if (!m) continue
      const key = `${MASK_SESSION(new URL(r.url).pathname)}|${m[1].toLowerCase()}`
      if (seen.has(key)) continue
      seen.add(key)
      out.push({ id: fid('sess-url', key), tool: 'MacSec', category: 'web', url: MASK_SESSION(r.url), file: MASK_SESSION(r.url), confidence: 'confirmed', severity: 'medium', title: `A session id travels in ${where === 'a redirect' ? 'a redirect address' : 'an address'}: ${MASK_SESSION(new URL(r.url).pathname)}`, cwe: 'CWE-598', description: `The address contains ${m[1]}=… (the value is not kept). Session ids in links end up in logs, history and Referer headers, and can be planted in a link for a visitor to click (session fixation).`, fix: 'Keep session ids in cookies only, and turn off URL-based sessions (Java: <tracking-mode>COOKIE</tracking-mode>, PHP: session.use_trans_sid=0 and session.use_only_cookies=1).', proof: proofOf({ url: r.url.replace(/([;?&](?:jsessionid|phpsessid|sessionid|session_id|aspsessionid\w*|sid|sessid)=)[A-Za-z0-9._-]{8,}/i, '$1…'), status: r.status, headers: r.headers, body: '', shows: [`${m[1]} is in ${where}`, 'the value is hidden in this report'] }) })
    }
  }
  void urls
  return out
}

/** Does the server adopt a session id the visitor made up? Only the first half of session fixation: the login is not tried. */
export async function adoptsSessionId(c: ConfirmClient, replies: Reply[], note: (t: string) => void = () => undefined): Promise<Finding[]> {
  const out: Finding[] = []
  const setCookies = (r: Reply): string[] => (r.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie?.() ?? (r.headers.get('set-cookie') ? [r.headers.get('set-cookie')!] : [])
  const names = new Set<string>()
  for (const r of replies) for (const sc of setCookies(r)) {
    const m = /^([^=;\s]+)=/.exec(sc)
    if (m && SESSION_COOKIES.test(m[1])) names.add(m[1])
  }
  if (!names.size) return out
  try {
    // A visitor with no cookie: which session cookie does the home page hand out?
    const fresh = await c.get(c.base, { headers: {} })
    const handed = new Set(setCookies(fresh).map((x) => /^([^=;\s]+)=/.exec(x)?.[1]).filter((x): x is string => !!x))
    for (const name of [...names].filter((n) => handed.has(n)).slice(0, 3)) {
      const ask = async (value: string): Promise<{ r: Reply; adopted: boolean }> => {
        const r = await c.get(c.base, { headers: { Cookie: `${name}=${value}` } })
        const mine = setCookies(r).filter((x) => x.startsWith(`${name}=`))
        // Adopted: the server did not replace the id (no new value was set for that cookie).
        const replaced = mine.some((x) => !x.startsWith(`${name}=${value}`))
        return { r, adopted: r.status < 400 && !replaced }
      }
      const v1 = `macsec${rnd()}${rnd()}${rnd()}`
      const v2 = `macsec${rnd()}${rnd()}${rnd()}`
      const a1 = await ask(v1)
      if (!a1.adopted) continue
      const a2 = await ask(v2)
      if (!a2.adopted) continue
      note(`${name}: a made-up id was kept`)
      out.push({ id: fid('sess-adopt', name, c.origin), tool: 'MacSec', category: 'web', url: a1.r.url, file: a1.r.url, confidence: 'confirmed', severity: 'low', title: `The server keeps a session id the visitor made up: ${name}`, cwe: 'CWE-384', description: `A visitor with no cookie is given a new ${name}. Sent a made-up value for ${name} (twice, with different values), the server did not replace it with an id of its own. That is the first half of session fixation: if the site also keeps the same id when someone signs in, an attacker can plant an id in a visitor's browser and use it after the login. MacSec did not sign in, so the second half is not tested: check by hand that the id changes at login.`, fix: 'Reject session ids the server did not create (PHP: session.use_strict_mode=1), and create a new id at sign-in and at every change of rights.', proof: proofOf({ url: a1.r.url, status: a1.r.status, headers: a1.r.headers, body: '', shows: [`a visitor with no cookie is handed a new ${name}`, `${name} was set to a made-up value by the visitor, and the server did not replace it`, 'a second made-up value was also not replaced', 'no sign-in was attempted'], sent: { Cookie: `${name}=${v1}` } }) })
    }
  } catch (e) {
    if (e instanceof Stop) note(e.message)
    else throw e
  }
  return out
}

/** CORS, CSRF leads and session ids together. `pages` are pages already read; `replies` includes their answers. */
export async function sessionChecks(c: ConfirmClient, o: { urls: string[]; pages: Reply[]; account?: Record<string, string> }, note: (t: string) => void = () => undefined): Promise<Finding[]> {
  const out: Finding[] = []
  const htmlPages = o.pages.filter((r) => r.status === 200 && /html/i.test(r.headers.get('content-type') ?? '')).map((r) => ({ url: r.url, html: r.body }))
  out.push(...csrfLeads(htmlPages, cookieSamesite(o.pages)), ...sessionsInUrls(o.pages, o.urls))
  note('CORS with made-up origins')
  out.push(...(await corsChecks(c, o.urls, { account: o.account, note })))
  note('Session ids')
  out.push(...(await adoptsSessionId(c, o.pages, note)))
  const seen = new Set<string>()
  return out.filter((f) => (seen.has(f.id) ? false : (seen.add(f.id), true)))
}
