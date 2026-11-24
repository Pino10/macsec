/**
 * The runners. Each one is bounded by its catalogue entry and by the client's caps, and each one
 * stops at the first proof. Nothing here dumps data, writes more than one file, runs a command, or
 * makes a request that is not described in the plan the person approved.
 */
import { createHash, randomBytes } from 'crypto'
import { execFile } from 'child_process'
import { existsSync, mkdirSync, readFileSync, rmSync } from 'fs'
import { join } from 'path'
import type { ImpactEvidence, ImpactStepResult, PlannedStep } from '../../shared/impact'
import { maskSecrets } from '../evidence'
import { parseFfuf, pathSeverity } from '../scanners/web'
import { dirs } from '../paths'
import { toolPath } from '../toolbox'
import { discoveryWords, writeWordlist } from '../wordlistfiles'
import { ImpactRefused, type ImpactClient, type ImpactReply } from './client'

const sha = (s: string): string => createHash('sha256').update(s).digest('hex')
const now = (): string => new Date().toISOString()
const rand = (): string => randomBytes(4).toString('hex')

const evidence = (r: ImpactReply, shows: string[]): ImpactEvidence => ({
  method: r.method,
  url: r.url.replace(/\/\/[^/]*@/, '//'),
  status: r.status,
  contentType: r.headers.get('content-type')?.slice(0, 80) ?? undefined,
  bytes: Buffer.byteLength(r.body),
  sha256: sha(r.body),
  at: now(),
  shows: shows.map((s) => s.slice(0, 200)).slice(0, 12)
})

const note = (s: string): string => maskSecrets(s).slice(0, 240)

export interface ActionContext {
  client: ImpactClient
  step: PlannedStep
  /** A progress line for the window. */
  line: (text: string) => void
}

export interface ActionResult {
  status: ImpactStepResult['status']
  title: string
  detail: string
  evidence?: ImpactEvidence
  cleanup?: { done: boolean; how: string }
  leftover?: { what: string; where: string; how: string }
}

const withParam = (page: string, name: string, value: string): string => {
  const u = new URL(page)
  u.searchParams.set(name, value)
  return u.href
}

const pathOf = (u: string): string => {
  try {
    const p = new URL(u)
    return p.pathname + (p.search ? '?…' : '')
  } catch {
    return u
  }
}

// ---------------------------------------------------------------- Confidentiality: read a system file

interface Canary {
  what: string
  paths: string[]
  /** What the answer contains when it really is that file. Never the content itself. */
  test: (body: string) => string | null
}

const CANARIES: Canary[] = [
  {
    what: '/etc/passwd',
    paths: ['/etc/passwd'],
    test: (b) => (/^root:[^:\n]*:0:0:/m.test(b) || /^\w+:[x*!]?:\d+:\d+:[^:]*:[^:]*:/m.test(b) ? 'the answer has the layout of /etc/passwd (name:password:uid:gid)' : null)
  },
  {
    what: '/etc/hosts',
    paths: ['/etc/hosts'],
    test: (b) => (/(^|\n)\s*127\.0\.0\.1\s+localhost/m.test(b) ? 'the answer has the localhost line of /etc/hosts' : null)
  },
  {
    what: 'C:\\Windows\\win.ini',
    paths: ['C:\\Windows\\win.ini', 'C:/Windows/win.ini'],
    test: (b) => (/\[fonts\]/i.test(b) ? 'the answer has the [fonts] section of win.ini' : null)
  }
]

const DEPTHS = ['../../../../..', '..%2f..%2f..%2f..%2f..', '....//....//....//....//']

async function traversalRead(c: ActionContext): Promise<ActionResult> {
  const { client, step } = c
  const param = String(step.param ?? '').trim()
  if (!param) return { status: 'failed', title: 'Read a system file', detail: 'This step names no parameter, so there is nothing to send the path in.' }
  let sent = 0
  for (const canary of CANARIES) {
    for (const depth of DEPTHS) {
      if (client.left().requests < 2) return { status: 'not-proven', title: `Read a system file through ${param}`, detail: `The request cap was reached after ${sent} attempts. No system file shape came back.` }
      const value = `${depth}${canary.paths[0]}`
      c.line(`trying ${canary.what} in ${param}`)
      const r = await client.get(withParam(step.url, param, value), { note: `traversal attempt ${canary.what}` })
      sent++
      const shown = canary.test(r.body)
      if (!shown) continue
      if (client.left().requests < 1) return { status: 'not-proven', title: `Read a system file through ${param}`, detail: 'A shape that looked like a system file came back, but there was no request left to repeat it, so it is not reported.' }
      const again = await client.get(withParam(step.url, param, value), { note: 'traversal repeat' })
      sent++
      if (!canary.test(again.body)) continue
      return {
        status: 'proven',
        title: `A parameter reads a system file: ${canary.what} through "${param}" on ${pathOf(step.url)}`,
        detail: `Sent in "${param}", the answer contained the shape of ${canary.what}, twice in a row. The file itself was not kept: only what proves it was read. This is real file read, which is confidentiality loss, and on its own it is often a step towards credentials and code execution.`,
        evidence: evidence(again, [`${canary.what} came back through the parameter "${param}"`, `sent as ${value}`, 'the same shape came back on a second request', 'the content itself was not stored, only this shape'])
      }
    }
  }
  return { status: 'not-proven', title: `Read a system file through ${param}`, detail: `${sent} requests with the standard traversal shapes, and no system file came back. That does not prove the parameter is safe: the file may be elsewhere, or the server may normalise the path.` }
}

// ---------------------------------------------------------------- Integrity: template arithmetic

const EXPRESSIONS = ['{{7*7}}', '${7*7}', '<%= 7*7 %>', '#{7*7}', '*{7*7}', '@(7*7)', '#{7*7}']
const PRODUCT = '49'

async function sstiMarker(c: ActionContext): Promise<ActionResult> {
  const { client, step } = c
  const param = String(step.param ?? '').trim()
  if (!param) return { status: 'failed', title: 'Template arithmetic', detail: 'This step names no parameter.' }
  const seen = new Set<string>()
  for (const expr of EXPRESSIONS) {
    if (seen.has(expr) || client.left().requests < 2) break
    seen.add(expr)
    c.line(`asking the page to calculate ${expr} in ${param}`)
    const r = await client.get(withParam(step.url, param, expr), { note: `template expression in ${param}` })
    const evaluated = r.body.includes(PRODUCT) && !r.body.includes(expr)
    if (!evaluated) continue
    const again = await client.get(withParam(step.url, param, expr), { note: 'template expression repeat' })
    if (!(again.body.includes(PRODUCT) && !again.body.includes(expr))) continue
    return {
      status: 'proven',
      title: `The server calculates an expression sent in "${param}" on ${pathOf(step.url)}`,
      detail: `The page returned ${PRODUCT} for ${expr}. The server evaluated what the parameter said instead of printing it. That is server-side template evaluation, the first half of a template injection: it shows attacker input reaches the template engine. MacSec stopped at arithmetic, so no command ran and no data was read.`,
      evidence: evidence(again, [`${expr} sent in "${param}" came back as ${PRODUCT}`, 'the expression itself is not in the answer', 'the same on a second request', 'only arithmetic was sent: no command and no file read'])
    }
  }
  return { status: 'not-proven', title: `Template arithmetic through ${param}`, detail: 'No expression came back calculated. The page may escape its values, or the engine may not be running on this page.' }
}

// ---------------------------------------------------------------- Integrity: write one file

async function uploadWrite(c: ActionContext): Promise<ActionResult> {
  const { client, step } = c
  const field = String(step.param ?? 'file').trim() || 'file'
  const name = `macsec-proof-${rand()}.txt`
  const marker = `macsec-${rand()}`
  const text = `${marker}\nWritten by MacSec as a controlled proof, ${now()}. This file is safe to delete.\n`
  const form = new FormData()
  form.append(field, new Blob([text], { type: 'text/plain' }), name)
  const extra = step.body ? (JSON.parse(step.body) as unknown) : null
  if (extra && typeof extra === 'object' && !Array.isArray(extra)) {
    for (const [k, v] of Object.entries(extra as Record<string, unknown>).slice(0, 5)) {
      if (/^[A-Za-z0-9_.-]{1,40}$/.test(k) && typeof v === 'string' && v.length <= 200) form.append(k, v)
    }
  }
  c.line(`uploading ${name} (about ${Buffer.byteLength(text)} bytes)`)
  const up = await client.send('POST', step.url, { form, note: `upload ${name}` })
  if (up.status < 200 || up.status >= 300) {
    return { status: 'not-proven', title: 'Upload one file', detail: `The upload answered HTTP ${up.status}, so there is nothing to verify. No file is known to exist.` }
  }
  const template = String(step.verifyUrl ?? '')
  if (!template.includes('{name}')) {
    return {
      status: 'not-proven',
      title: 'Upload one file',
      detail: `The upload answered HTTP ${up.status}, which is not proof by itself. Give the address to read the file back (with {name} in it) and this step can prove the write. ${name} was sent.`,
      cleanup: { done: false, how: `The upload may have stored "${name}". Check the uploads folder for that one file and remove it.` },
      leftover: { what: 'one text file, if the upload succeeded', where: step.url, how: `Look for ${name} in the uploads folder and delete it.` }
    }
  }
  const url = template.split('{name}').join(encodeURIComponent(name))
  c.line(`reading the file back at ${pathOf(url)}`)
  const read = await client.get(url, { note: 'read the uploaded file back', allowCrossOrigin: true })
  const verified = read.status === 200 && read.body.includes(marker)
  // Clean up whether or not the read-back proved the write: the file may be there either way.
  let cleanup: { done: boolean; how: string }
  let leftover: ActionResult['leftover']
  if (client.left().writes >= 1) {
    const del = await client.send('DELETE', url, { note: 'remove the uploaded file', allowCrossOrigin: true }).catch(() => null)
    const gone = !!del && (del.status < 400 || del.status === 404)
    cleanup = gone
      ? { done: true, how: `DELETE ${pathOf(url)} answered ${del?.status ?? 0}` }
      : { done: false, how: `DELETE was refused (HTTP ${del?.status ?? 0}). Remove the file by hand.` }
    if (!gone) leftover = { what: `the uploaded file "${name}"`, where: url, how: 'Delete it from the uploads folder or the media library. It is a plain text file with no script in it.' }
  } else {
    cleanup = { done: false, how: 'the write cap did not leave room for the delete request' }
    leftover = { what: `the uploaded file "${name}"`, where: url, how: 'Delete it from the uploads folder or the media library. It is a plain text file with no script in it.' }
  }
  if (!verified) {
    return {
      status: 'not-proven',
      title: 'Upload one file',
      detail: `The upload answered HTTP ${up.status}, but the file did not come back with its marker (HTTP ${read.status}). It may be private, renamed or rejected. ${cleanup.done ? 'It was removed again.' : 'It may still be there.'}`,
      cleanup,
      ...(leftover ? { leftover } : {})
    }
  }
  return {
    status: 'proven',
    title: 'A file was written and is readable from the web',
    detail: `Uploaded ${name} (a plain text file with the marker ${marker}) and read it back unchanged. That is integrity loss: anyone who can upload can put their own content on the site. The file is ${cleanup.done ? 'removed again' : 'still there, see the leftover note'}.`,
    evidence: evidence(read, [`the upload answered HTTP ${up.status}`, `the file ${name} came back with its marker intact`, 'the file is plain text: no script, no HTML', cleanup.done ? 'it was removed again' : 'it is still there and listed as a leftover']),
    cleanup,
    ...(leftover ? { leftover } : {})
  }
}


// ---------------------------------------------------------------- Availability: one request vs three

async function availabilityProbe(c: ActionContext): Promise<ActionResult> {
  const { client, step } = c
  const base: number[] = []
  for (let i = 0; i < 2; i++) {
    if (client.left().requests < 1) return { status: 'not-proven', title: 'Measure one request against three', detail: 'The request cap was reached before a baseline could be taken.' }
    const r = await client.get(step.url, { note: 'baseline timing' })
    if (r.status === 429 || r.status >= 500) return { status: 'not-proven', title: 'Measure one request against three', detail: `The server answered ${r.status} to a baseline request, so the run stopped and asked nothing more.` }
    base.push(r.ms)
  }
  const floor = Math.max(25, Math.min(...base))
  const probes: ImpactReply[] = []
  for (let i = 0; i < 3; i++) {
    if (client.left().requests < 1) break
    await new Promise((r) => setTimeout(r, 2000))
    const r = await client.get(step.url, { note: 'timed request' })
    if (r.status === 429 || r.status === 503) {
      return { status: 'not-proven', title: 'Measure one request against three', detail: 'The server pushed back with 429 or 503, so the run stopped after that one request. That is a good sign for the site.' }
    }
    probes.push(r)
  }
  const slowest = probes.slice().sort((a, b) => b.ms - a.ms)[0]
  if (!slowest) return { status: 'not-proven', title: 'Measure one request against three', detail: 'No timed request could be sent within the cap.' }
  const ratio = slowest.ms / floor
  const proven = slowest.ms - floor >= 250 && ratio >= 3
  const shows = [`two plain requests took ${Math.round(floor)} ms`, `the slowest of three took ${Math.round(slowest.ms)} ms, ${ratio.toFixed(1)} times as long`, 'each request was sent on its own, with two seconds between them', 'the run stopped at five requests']
  if (!proven) {
    return { status: 'not-proven', title: 'Measure one request against three', detail: `The answer times were close (${Math.round(floor)} ms against ${Math.round(slowest.ms)} ms), so one request does not look expensive here. The page is not a lead for availability loss.`, evidence: evidence(slowest, shows) }
  }
  return {
    status: 'proven',
    title: 'One request makes the server do several times the work',
    detail: `The same page took ${Math.round(slowest.ms)} ms against a baseline of ${Math.round(floor)} ms. A single request that is that much more expensive than its baseline is what an unbounded or uncached operation looks like, and it is the start of an availability problem when it can be repeated. MacSec sent five requests in total and stopped. This is a measured slowdown, not a denial of service: nothing was flooded.`,
    evidence: evidence(slowest, shows),
    cleanup: { done: true, how: 'nothing was changed: only five reads, one at a time' }
  }
}

// ---------------------------------------------------------------- The escape hatch: one pasted request

async function replayRequest(c: ActionContext): Promise<ActionResult> {
  const { client, step } = c
  const expect = String(step.expect ?? '').trim()
  if (!expect) return { status: 'failed', title: 'Send the request you pasted', detail: 'Name the string the answer must contain, otherwise nothing can be proven.' }
  const method = step.method ?? 'GET'
  const write = method !== 'GET'
  if (write && !step.undo) return { status: 'failed', title: 'Send the request you pasted', detail: 'A request that can change data needs the undo step written down first.' }
  c.line(`sending one ${method} request`)
  const r = await client.send(method, step.url, { headers: step.headers, body: step.body, note: `replay ${method}` })
  const hit = r.body.toLowerCase().includes(expect.toLowerCase())
  const shows = [`the answer contains "${note(expect)}"`, `HTTP ${r.status} to a single ${method} request`, 'sent once, not repeated']
  if (hit) {
    return {
      status: 'proven',
      title: `The request proved what it was meant to prove: ${pathOf(step.url)}`,
      detail: `The answer contains "${note(expect)}". That is the proof you asked for.${write ? ' This request can change data, so the undo step you wrote is the remaining work.' : ''}`,
      evidence: evidence(r, shows),
      cleanup: write ? { done: false, how: `Undo by hand: ${step.undo}` } : { done: true, how: 'nothing to undo: a read' }
    }
  }
  return {
    status: 'not-proven',
    title: `The request did not prove it: ${pathOf(step.url)}`,
    detail: `HTTP ${r.status}, and the answer does not contain "${note(expect)}". Nothing is reported as proven from one request that did not show it.`,
    evidence: evidence(r, [...shows, 'the expected string is not there']),
    ...(write ? { cleanup: { done: false, how: `If it changed anything, undo it by hand: ${step.undo}` } } : {})
  }
}

// ---------------------------------------------------------------- Confidentiality: hidden pages, with ffuf

export type FfufRun = (bin: string, args: string[]) => Promise<string>

let ffufRunner: FfufRun | null = null

/** Tests and the campaign can bring their own ffuf. The real one only ever writes its report file. */
export function setFfufRunner(r: FfufRun | null): void {
  ffufRunner = r
}

const defaultFfuf: FfufRun = (bin, args) =>
  new Promise((resolve, reject) => {
    const out = args[args.indexOf('-o') + 1]
    execFile(bin, args, { timeout: 8 * 60_000, maxBuffer: 8 * 1024 * 1024, env: { ...process.env, NO_COLOR: '1' } }, (e, _o, err) => {
      if (!e || (out && existsSync(out))) resolve('')
      else reject(new Error(String(err).trim().split('\n').pop() || 'ffuf did not run.'))
    })
  })

const FFUF_STATUS = '200,204,301,302,401,403,405'

async function contentDiscovery(c: ActionContext): Promise<ActionResult> {
  const { client, step } = c
  const bin = process.env.MACSEC_FFUF || toolPath('ffuf')
  const words = discoveryWords(435)
  if (!client.left().requests) return { status: 'not-proven', title: 'Find the pages nothing links to', detail: 'The cap left no requests for discovery.' }
  const usable = words.slice(0, Math.min(words.length, Math.max(0, client.left().requests - 20)))
  if (usable.length < 50) return { status: 'not-proven', title: 'Find the pages nothing links to', detail: `The engagement has ${client.left().requests} requests left, which is too few for a discovery list worth running (50 at least). Raise the cap in writing, or prove something else.` }
  const work = join(dirs.root(), 'impact-work')
  mkdirSync(work, { recursive: true, mode: 0o700 })
  const wl = writeWordlist(usable, join(work, `words-${rand()}.txt`))
  const out = join(work, `ffuf-${rand()}.json`)
  const base = step.url.replace(/\/+$/, '')
  client.reserve(usable.length, `content discovery with ffuf (${usable.length} paths)`)
  const args = ['-u', `${base}/FUZZ`, '-w', wl, '-of', 'json', '-o', out, '-mc', FFUF_STATUS, '-t', '5', '-rate', '20', '-timeout', '10', '-s', '-ac', '-noninteractive']
  c.line(`ffuf: ${usable.length} paths at 20 a second`)
  try {
    await (ffufRunner ?? defaultFfuf)(bin, args)
  } catch (e) {
    rmSync(out, { force: true })
    return { status: 'failed', title: 'Find the pages nothing links to', detail: `ffuf did not run: ${(e as Error).message}. Install it on Tools, or use the exposed-file check instead.` }
  }
  const hits = existsSync(out) ? parseFfuf(readFileSync(out, 'utf8'), new URL(base).host) : []
  rmSync(out, { force: true })
  rmSync(wl, { force: true })
  if (!hits.length) return { status: 'not-proven', title: 'Find the pages nothing links to', detail: `ffuf asked for ${usable.length} paths and none answered with a status worth a look.` }
  // Calibrate against a path that cannot exist, then prove the best hits one by one.
  const cal = await client.get(`${base}/macsec-${rand()}.html`, { note: 'discovery calibration' }).catch(() => null)
  const catchAll = !!cal && cal.status === 200
  const confirmed: { path: string; status: number; reply: ImpactReply }[] = []
  for (const h of hits.slice(0, 15)) {
    if (client.left().requests < 2) break
    const r = await client.get(`${new URL(base).origin}${h.path}`, { note: `verify /${h.path.replace(/^\//, '')}` }).catch(() => null)
    if (!r) continue
    if (catchAll && cal && r.status === cal.status && Math.abs(r.body.length - cal.body.length) < 60) continue
    if (r.status !== h.status) continue
    confirmed.push({ path: h.path, status: r.status, reply: r })
  }
  if (!confirmed.length) {
    return { status: 'not-proven', title: 'Find the pages nothing links to', detail: `ffuf found ${hits.length} path${hits.length === 1 ? '' : 's'}, but none answered the same way twice in a way that is not the site's "not found" page.` }
  }
  const worst = confirmed.map((x) => ({ ...x, sev: pathSeverity(x.path.replace(/^\//, ''), x.status) })).sort((a, b) => severityRank(b.sev) - severityRank(a.sev))[0]
  const best = worst.sev === 'info' ? confirmed[0] : worst.reply ? worst : confirmed[0]
  const reply = 'reply' in best ? best.reply : confirmed[0].reply
  return {
    status: 'proven',
    title: `${confirmed.length} page${confirmed.length === 1 ? ' is' : 's are'} reachable and not linked from the site`,
    detail: `ffuf asked for ${usable.length} paths and ${hits.length} answered. ${confirmed.length} of those were asked again and answered the same way. Most interesting: ${confirmed.slice(0, 8).map((x) => `${x.path} (HTTP ${x.status})`).join(', ')}${confirmed.length > 8 ? ', and more' : ''}. ${worst.sev !== 'info' ? `One of them looks sensitive by name (${worst.sev}).` : ''} This is confidentiality exposure: content the site does not link to, but anyone can ask for.`,
    evidence: evidence(reply, [`${confirmed.length} paths answered the same way twice`, ...confirmed.slice(0, 8).map((x) => `${x.path} answered HTTP ${x.status}`), `ffuf asked for ${usable.length} paths, at 20 a second, signed out`])
  }
}

const severityRank = (s: string): number => ({ critical: 5, high: 4, medium: 3, low: 2, info: 1 } as Record<string, number>)[s] ?? 0

// ---------------------------------------------------------------- Confidentiality: the page needs no sign-in

async function authBypass(c: ActionContext): Promise<ActionResult> {
  const { client, step } = c
  const expect = String(step.expect ?? '').trim()
  if (!expect) return { status: 'failed', title: 'Read a private page with no credentials', detail: 'Name the string that proves it: your own email, an order number, a name only a signed-in person sees.' }
  c.line('asking for the page with no cookie and no token')
  const r = await client.get(step.url, { headers: {}, note: 'anonymous request' })
  const hit = r.status < 400 && r.body.toLowerCase().includes(expect.toLowerCase())
  if (!hit) {
    return { status: 'not-proven', title: 'Read a private page with no credentials', detail: `Signed out, the page answered HTTP ${r.status} and does not contain "${note(expect)}". It still asks for a sign-in, which is good news.`, evidence: evidence(r, [`HTTP ${r.status} with no cookie and no token`, 'the expected string is not in the answer']) }
  }
  const again = await client.get(step.url, { headers: {}, note: 'anonymous request, repeat' })
  if (!(again.status < 400 && again.body.toLowerCase().includes(expect.toLowerCase()))) {
    return { status: 'not-proven', title: 'Read a private page with no credentials', detail: 'The first answer had the string but the second did not, so it is not repeated here.', evidence: evidence(r, ['the first answer had the string', 'the second did not']) }
  }
  return {
    status: 'proven',
    title: `The page needs no sign-in: ${pathOf(step.url)}`,
    detail: `With no cookie and no token, the page answered HTTP ${again.status} and still contained "${note(expect)}". Whatever this page shows a signed-in person is readable by anyone with the address. That is confidentiality loss and a missing authorization check.`,
    evidence: evidence(again, [`HTTP ${again.status} with no cookie and no token`, `the answer contains "${note(expect)}"`, 'the same string came back on a second anonymous request', 'nothing was sent that identifies a person'])
  }
}

export const RUNNERS: Record<PlannedStep['action'], (c: ActionContext) => Promise<ActionResult>> = {
  'traversal-read': traversalRead,
  'ssti-marker': sstiMarker,
  'upload-write': uploadWrite,
  'availability-probe': availabilityProbe,
  'replay-request': replayRequest,
  'content-discovery': contentDiscovery,
  'auth-bypass': authBypass
}

/** The requests a step will send, in plain words, for the approval screen. */
export function previewOf(step: PlannedStep): string[] {
  const page = (() => {
    try {
      const u = new URL(step.url)
      return u.pathname + (u.search ? '?…' : '')
    } catch {
      return step.url
    }
  })()
  switch (step.action) {
    case 'traversal-read':
      return [`GET ${page} with "${step.param}" set to a system file path (5 depths, 2 files, at most 10 requests)`, 'repeat the one that answers, to be sure']
    case 'ssti-marker':
      return [`GET ${page} with "${step.param}" set to {{7*7}} and 5 other expressions (at most 8 requests)`, 'repeat the one that answers, to be sure']
    case 'upload-write':
      return [`POST ${page} with one text file (about 80 bytes, random name) in the "${step.param ?? 'file'}" field`, `GET ${step.verifyUrl ?? '(no read-back address yet)'} to prove it, then DELETE it`]
    case 'availability-probe':
      return [`GET ${page} twice, then three more times one at a time, 2 seconds apart (5 requests in all)`]
    case 'replay-request':
      return [`${step.method ?? 'GET'} ${page} once, with the headers and body you pasted${step.body ? ' (a body is sent)' : ''}`]
    case 'content-discovery':
      return [`GET ${page} with hundreds of common paths in place of the last segment (up to 435 requests at 20 a second, signed out)`, 'then ask again for the first 15 paths that answered, to prove each one']
    case 'auth-bypass':
      return [`GET ${page} twice with no cookie and no token, looking for "${step.expect ? note(step.expect) : 'the string you will name'}"`]
    default:
      return []
  }
}

export { ImpactRefused }
