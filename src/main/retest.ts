/**
 * Re-test one finding after a fix, without running the whole scan again. It repeats the request in
 * the finding's proof (plain GET only, signed out, no redirects followed) and compares the answer
 * with what was seen the first time. It reports what it saw: it never marks anything fixed by itself.
 */
import { createHash } from 'crypto'
import type { Finding } from '../shared/types'

type Retest = NonNullable<Finding['retest']>

export async function retestFinding(f: Finding, fetchImpl: typeof fetch = fetch): Promise<Retest> {
  const at = new Date().toISOString()
  const p = f.proof
  const m = p && /^GET (https?:\/\/\S+)$/.exec(p.request)
  if (!p || !m || !p.status) return { at, state: 'unsupported', detail: 'This proof is not a plain web request, so it cannot be repeated here. Run the scan again to re-test it.' }
  let url: URL
  try {
    url = new URL(m[1])
  } catch {
    return { at, state: 'unsupported', detail: 'The address in the proof is not valid.' }
  }
  let r: Response
  let body: string
  try {
    r = await fetchImpl(url.href, { redirect: 'manual', headers: { 'User-Agent': 'MacSec re-test' }, signal: AbortSignal.timeout(20000) })
    body = r.status >= 300 && r.status < 400 ? '' : (await r.text()).slice(0, 200000)
  } catch {
    return { at, state: 'unreachable', detail: 'The site did not answer. Try again when it is up.' }
  }
  const sha = createHash('sha256').update(body).digest('hex')
  const sameClass = Math.floor(r.status / 100) === Math.floor(p.status / 100)
  const bytes = Buffer.byteLength(body)
  const close = Math.abs(bytes - p.bytes) <= Math.max(60, p.bytes * 0.03)
  if (sameClass && (sha === p.sha256 || close)) return { at, state: 'still', detail: `Still there: HTTP ${r.status}, ${sha === p.sha256 ? 'the same answer as before' : 'an answer of nearly the same size as before'}.` }
  if (r.status === 404 || r.status === 410 || r.status === 401 || r.status === 403 || (r.status >= 300 && r.status < 400)) return { at, state: 'gone', detail: `Now answers HTTP ${r.status} instead of ${p.status}, so it looks fixed. This re-check is signed out: if the finding needed your login, run the scan again to be sure.` }
  return { at, state: 'changed', detail: `The answer changed (HTTP ${r.status}, ${bytes.toLocaleString()} bytes, it was HTTP ${p.status}, ${p.bytes.toLocaleString()} bytes). Look at it by hand, or run the scan again.` }
}
