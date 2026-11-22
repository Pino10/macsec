/**
 * Business logic checks, the safe kind. Real logic bugs (a price changed in transit, a coupon used
 * twice, a step skipped) need a state change to prove, which MacSec never does. What it can prove
 * safely is the part that does not change anything:
 *
 *   Open redirect       a site sends visitors to any address named in a "next" or "return" parameter
 *   Host poisoning      a forwarded host name is written into links or redirects (password reset poisoning)
 *   Wrong-code limit    an one-time code or PIN form accepts ten wrong codes in a row
 *   Trusted by browser  prices, totals, roles and ids carried in form fields the visitor controls (a lead)
 *   Skipped steps       a late step of a purchase or sign-up flow that opens with no earlier step (a lead)
 *   Guessable ids       numbered records in addresses (a lead, tested properly by the two-account check)
 *
 * Everything goes through ConfirmClient. Only GET, plus made-up wrong codes on a code form with no
 * session, so no real account is touched. Proven findings are repeated once. Leads say they are leads.
 */
import type { Finding } from '../shared/types'
import { ConfirmClient, isCatchAll, calibrate, parseForms, risky, similar, Stop, visibleText, type Reply } from './confirmtests'
import { fid } from './scanners/parse'
import { proofOf, TEST_ORIGIN } from './seckit/confirm'

const f = (x: Omit<Finding, 'id' | 'tool' | 'category'>, key: string): Finding => ({ id: fid('logic', x.title, x.url ?? '', key), tool: 'MacSec', category: 'web', ...x })
const pathOf = (u: string): string => {
  try {
    const p = new URL(u)
    return p.pathname + (p.search ? '?…' : '')
  } catch {
    return u
  }
}

// ---------------------------------------------------------------- Open redirect

export const REDIRECT_PARAMS = ['next', 'url', 'redirect', 'redirect_uri', 'redirect_url', 'return', 'returnTo', 'return_url', 'returnUrl', 'continue', 'dest', 'destination', 'goto', 'target', 'back', 'to', 'out', 'forward', 'callback', 'checkout_url', 'image_url']
const REDIRECT_PATHS = ['login', 'signin', 'logout', 'signout', 'redirect', 'out', 'go', 'r', 'link', 'auth/login', 'account/login', 'sso', 'oauth/authorize']

/** Where a redirect answer sends the visitor, as a host name, or null when it is not a redirect. */
export function redirectHost(r: Reply): string | null {
  if (r.status < 300 || r.status >= 400) return null
  const loc = r.headers.get('location')
  if (!loc) return null
  try {
    return new URL(loc, r.url).hostname.toLowerCase()
  } catch {
    return null
  }
}

export async function openRedirect(c: ConfirmClient, urls: string[], note: (t: string) => void): Promise<Finding[]> {
  const out: Finding[] = []
  const host = new URL(TEST_ORIGIN).hostname
  // Paths that really exist, and the parameters the site's own addresses already use.
  const own = new Map<string, Set<string>>()
  for (const u of urls) {
    try {
      const p = new URL(u)
      if (p.origin !== c.origin || risky(u)) continue
      for (const k of p.searchParams.keys()) if (REDIRECT_PARAMS.includes(k)) (own.get(p.pathname) ?? own.set(p.pathname, new Set()).get(p.pathname)!).add(k)
    } catch {
      /* not an address */
    }
  }
  const targets: { path: string; params: string[] }[] = [...own].map(([path, s]) => ({ path, params: [...s] }))
  for (const p of REDIRECT_PATHS) if (!targets.some((t) => t.path === `/${p}`)) targets.push({ path: `/${p}`, params: REDIRECT_PARAMS.slice(0, 9) })
  for (const t of targets.slice(0, 14)) {
    note(`Checking redirects on ${t.path}`)
    let base: Reply
    try {
      base = await c.get(t.path, { headers: 'none' })
    } catch (e) {
      if (e instanceof Stop) throw e
      continue
    }
    if (base.status === 404 || base.status >= 500) continue
    for (const param of t.params) {
      if (c.left() < 8) return out
      const bait = `${TEST_ORIGIN}/macsec-redirect-check`
      const url = `${t.path}${t.path.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(bait)}`
      const r = await c.get(url, { headers: 'none' }).catch((e) => {
        if (e instanceof Stop) throw e
        return null
      })
      if (!r || redirectHost(r) !== host) continue
      const again = await c.get(url, { headers: 'none' })
      if (redirectHost(again) !== host) continue
      out.push(f({ severity: 'medium', confidence: 'confirmed', title: `Open redirect: ${t.path} sends visitors to any address in "${param}"`, url: r.url, file: r.url, cwe: 'CWE-601', description: `A harmless address on a name that does not exist (${host}) was put in the "${param}" parameter, and the site answered with a redirect to it, twice. Attackers use this to send people from your trusted address to a fake page, and to steal tokens in sign-in flows.`, fix: 'Only redirect to addresses on your own site: keep a list of allowed paths, or turn the value into a path and refuse anything that starts with a scheme or //.', proof: proofOf({ url: r.url, status: r.status, headers: r.headers, body: r.body, shows: [`HTTP ${r.status} with Location pointing at ${host}, the address sent in "${param}"`, 'the same answer came twice', 'MacSec did not follow the redirect'] }) }, `${t.path}${param}`))
      break
    }
  }
  return out
}

// ---------------------------------------------------------------- Host poisoning

/** Pages where a forwarded host name most often ends up in a link or redirect. */
const HOST_PATHS = ['/', '/forgot', '/forgot-password', '/password/reset', '/password/forgot', '/users/password/new', '/reset-password', '/login', '/register']

export async function hostPoisoning(c: ConfirmClient): Promise<Finding[]> {
  const marker = 'macsec-host-check.example'
  for (const path of HOST_PATHS) {
    const base = await c.get(path, { headers: 'none' })
    if (base.status === 404 || base.body.includes(marker) || (base.headers.get('location') ?? '').includes(marker)) continue
    const tryHeader = async (): Promise<{ r: Reply; where: string } | null> => {
      const r = await c.get(path, { headers: { 'X-Forwarded-Host': marker } })
      const loc = r.headers.get('location') ?? ''
      if (loc.includes(marker)) return { r, where: 'the Location header of the redirect' }
      const m = new RegExp(`(?:href|src|action)\\s*=\\s*["'][^"']*${marker.replace(/\./g, '\\.')}`, 'i').exec(r.body)
      return m ? { r, where: 'a link or form address in the page' } : null
    }
    const first = await tryHeader()
    if (!first) continue
    const second = await tryHeader()
    if (!second) continue
    const url = first.r.url
    return [f({ severity: 'medium', confidence: 'confirmed', title: 'The site trusts a forwarded host name when it builds links', url, file: url, cwe: 'CWE-644', description: `A made-up host name sent in the X-Forwarded-Host header came back inside ${first.where}, twice. If password reset or confirmation emails are built the same way, an attacker can make them point at their own site (password reset poisoning). It can also poison a cache.`, fix: 'Build absolute addresses from a fixed setting (APP_URL), not from request headers, and tell your framework which proxies to trust.', proof: proofOf({ url, status: first.r.status, headers: first.r.headers, body: first.r.body, sent: { 'X-Forwarded-Host': marker }, shows: [`the name ${marker} sent in X-Forwarded-Host appears in ${first.where}`, 'it was not there without the header', 'the same answer came twice'] }) }, 'xfh')]
  }
  return []
}

// ---------------------------------------------------------------- Wrong codes

const CODE_FIELD = /(^|[_-])(otp|code|pin|token|2fa|mfa|totp|verification|verify|passcode|sms)([_-]|$)/i
const THROTTLE = /too many|try again (later|in)|temporarily (locked|blocked)|locked|rate limit|slow down|captcha|recaptcha|hcaptcha|verify you are human|expired|request a new/i

export async function codeLimit(c: ConfirmClient, pages: string[], note: (t: string) => void): Promise<Finding[]> {
  const out: Finding[] = []
  const seen = new Set<string>()
  for (const page of pages.slice(0, 10)) {
    let r: Reply
    try {
      r = await c.get(page, { headers: 'none' })
    } catch (e) {
      if (e instanceof Stop) throw e
      continue
    }
    if (r.status !== 200) continue
    for (const fm of parseForms(r.body)) {
      const code = fm.inputs.find((i) => ['text', 'number', 'tel', 'password'].includes(i.type) && CODE_FIELD.test(i.name))
      if (!code || fm.method !== 'post' || fm.inputs.some((i) => i.type === 'password' && !CODE_FIELD.test(i.name))) continue
      const action = new URL(fm.action || r.url, r.url).href
      if (new URL(action).origin !== c.origin || seen.has(action)) continue
      seen.add(action)
      note(`Trying wrong codes on ${pathOf(action)}`)
      const hidden: Record<string, string> = {}
      for (const i of fm.inputs) if (i.type === 'hidden') hidden[i.name] = i.value
      const rows: Reply[] = []
      let throttled = false
      for (let i = 0; i < 10 && !throttled; i++) {
        const wrong = String(100000 + ((i * 7919 + 13) % 899999)).slice(0, 6)
        const a = await c.post(action, { ...hidden, [code.name]: wrong }, { headers: 'none' })
        rows.push(a)
        if (a.status === 429 || a.headers.get('retry-after') || THROTTLE.test(visibleText(a.body))) throttled = true
      }
      if (throttled || rows.length < 10) continue
      const statuses = [...new Set(rows.map((x) => x.status))]
      if (statuses.some((s) => s >= 500) || statuses.length > 1) continue
      const last = rows[rows.length - 1]
      out.push(f({ severity: 'medium', confidence: 'possible', title: `A code form accepts ten wrong codes in a row: ${pathOf(action)}`, url: action, file: action, cwe: 'CWE-307', description: `Ten different made-up six-digit codes were sent to the "${code.name}" box, without being signed in and without any real account. Nothing slowed down, blocked or asked for a captcha. A six-digit code has a million possibilities, so with no limit it can be guessed. It is marked possible because the limit may only count attempts inside a signed-in session, which this test does not have.`, fix: 'Allow about five wrong codes per code or account, then invalidate the code and slow down further tries. Count by account, not only by address.', proof: proofOf({ method: 'POST', url: action, status: last.status, headers: last.headers, body: last.body, shows: [`10 wrong codes answered ${statuses.join(', ')} with the same kind of page each time`, 'no 429, no Retry-After, no lock or captcha message'] }) }, action))
    }
  }
  return out
}

// ---------------------------------------------------------------- Leads that need no extra requests

const TRUSTED = /^(price|unit_?price|amount|total|subtotal|cost|discount|coupon_?value|fee|shipping|tax|balance|credit|points|quantity|qty|role|roles|admin|is_?admin|isadmin|user_?id|userid|account_?id|owner(_?id)?|permission(s)?|level|plan|tier|status|verified|is_?verified|approved|currency)$/i

/** Form fields the visitor controls that hold things the server must decide itself. A lead, never proof. */
export function trustedFields(pages: { url: string; html: string }[]): Finding[] {
  const out: Finding[] = []
  for (const p of pages) {
    const hits = new Set<string>()
    for (const fm of parseForms(p.html)) for (const i of fm.inputs) if (i.type === 'hidden' && TRUSTED.test(i.name) && i.value !== '') hits.add(`${i.name}=${i.value.slice(0, 20)}`)
    if (!hits.size) continue
    const names = [...hits].map((h) => h.split('=')[0])
    out.push(f({ severity: 'low', confidence: 'possible', title: `The browser sends values the server should decide: ${names.slice(0, 4).join(', ')} on ${pathOf(p.url)}`, url: p.url, file: p.url, cwe: 'CWE-472', description: `Hidden form fields carry ${[...hits].slice(0, 6).join(', ')}. Anything in a hidden field can be changed by the visitor. If the server believes the price, quantity, role or id it receives, a visitor can pay less, get more or act as someone else. Whether it does is for a hand test, because proving it would change data, which MacSec never does.`, fix: 'Look up prices, totals, roles and owners on the server from the record id, and ignore any such value sent by the browser.' }, `${p.url}${names.join()}`))
  }
  return out
}

const STEPS = ['checkout/confirm', 'checkout/success', 'checkout/complete', 'checkout/payment', 'checkout/review', 'order/complete', 'order/confirmation', 'order-confirmation', 'payment/success', 'payment/complete', 'thank-you', 'thankyou', 'register/step-3', 'onboarding/complete', 'verify/success']
const LATE = /(confirm|success|complete|receipt|invoice|thank|review|payment|step-?[2-9])/i

/** A late step of a purchase or sign-up flow that opens for a visitor who never did the earlier steps. A lead. */
export async function skippedSteps(c: ConfirmClient, urls: string[], note: (t: string) => void): Promise<Finding[]> {
  const out: Finding[] = []
  const cal = await calibrate(c)
  const list = [...new Set([...STEPS.map((s) => `/${s}`), ...urls.filter((u) => { try { return new URL(u).origin === c.origin && LATE.test(new URL(u).pathname) && !risky(u) } catch { return false } }).map((u) => new URL(u).pathname)])].slice(0, 24)
  for (const path of list) {
    note(`Checking flow step ${path}`)
    const r = await c.get(path, { headers: 'none' }).catch((e) => {
      if (e instanceof Stop) throw e
      return null
    })
    if (!r || r.status !== 200 || isCatchAll(path.replace(/^\//, ''), r, cal)) continue
    const text = visibleText(r.body)
    if (text.length < 250 || /<input[^>]+type=["']?password/i.test(r.body) || !/(order|payment|invoice|receipt|confirmation|total|your (account|details))/i.test(text)) continue
    const again = await c.get(path, { headers: 'none' })
    if (again.status !== 200 || !similar(r, again) && Math.abs(r.body.length - again.body.length) > 400) continue
    out.push(f({ severity: 'low', confidence: 'possible', title: `A late step opens without the earlier steps: ${path}`, url: r.url, file: r.url, cwe: 'CWE-841', description: `${path} answered with a full page to a visitor who was not signed in and had done none of the earlier steps, and the page talks about an order, payment or confirmation. It may be a harmless static page. If it shows or finalises something real, the flow can be skipped. Open it by hand: does it show another person's order, or let you finish without paying?`, fix: 'Check the state of the flow on the server at every step (is there a paid order for this session?) and not only in the order of the pages.', proof: proofOf({ url: r.url, status: r.status, headers: r.headers, body: r.body, shows: ['the page answered 200 without a login or an earlier step', 'it mentions an order, payment or confirmation', 'it is not the site\'s answer for pages that do not exist'] }) }, path))
  }
  return out
}

/** Numbered records in addresses. Whether another account can open them is tested by the two-account check. */
export function guessableIds(urls: string[]): Finding[] {
  const hits = new Map<string, string>()
  for (const u of urls) {
    try {
      const p = new URL(u)
      const m = /^(\/[a-z][\w-]*(?:\/[a-z][\w-]*)?)\/(\d{1,9})(?:\/|$)/i.exec(p.pathname)
      if (m && !/\.(js|css|png|jpe?g|gif|svg)$/i.test(p.pathname) && !hits.has(m[1])) hits.set(m[1], u)
    } catch {
      /* not an address */
    }
  }
  return [...hits].slice(0, 8).map(([prefix, u]) => f({ severity: 'info', confidence: 'possible', title: `Records are numbered in the address: ${prefix}/<number>`, url: u, file: u, cwe: 'CWE-639', description: 'Numbered records are easy to count through. That is only a problem when the server does not check that the record belongs to the person asking. The two-account check (control confirmations) tests exactly that, and a hand test is to change the number while signed in as another user.', fix: 'Check ownership on every record request, and prefer random ids (UUIDs) for records that belong to one person.' }, prefix))
}

export interface LogicOptions {
  /** Pages found by the crawl. */
  urls: string[]
  /** Pages to read forms from (their HTML is fetched here). */
  pages?: string[]
}

/** All of the logic checks. Each is wrapped so a stop returns what was found so far. */
export async function logicChecks(c: ConfirmClient, o: LogicOptions, note: (t: string) => void): Promise<Finding[]> {
  const out: Finding[] = []
  const run = async (fn: () => Promise<Finding[]> | Finding[]): Promise<void> => {
    try {
      out.push(...(await fn()))
    } catch (e) {
      if (e instanceof Stop) note(e.message)
      else throw e
    }
  }
  await run(() => hostPoisoning(c))
  await run(() => openRedirect(c, o.urls, note))
  const pages: { url: string; html: string }[] = []
  for (const p of [...new Set(['/', ...(o.pages ?? [])])].slice(0, 12)) {
    try {
      const r = await c.get(p, { headers: 'none' })
      if (r.status === 200 && /html/i.test(r.headers.get('content-type') ?? '')) pages.push({ url: r.url, html: r.body })
    } catch (e) {
      if (e instanceof Stop) break
    }
  }
  out.push(...trustedFields(pages))
  out.push(...guessableIds(o.urls))
  await run(() => codeLimit(c, [...new Set([...(o.pages ?? []), ...['verify', 'otp', '2fa', 'mfa', 'verify-code', 'auth/verify', 'login/verify', 'two-factor'].map((x) => `/${x}`)])], note))
  await run(() => skippedSteps(c, o.urls, note))
  return out
}
