/**
 * GraphQL, tested the safe way. MacSec asks questions and never gives orders:
 *
 *   Is there an endpoint        a POST of {__typename} to the usual paths, and a real GraphQL answer
 *   Introspection               one small schema question: the whole map of the API is public
 *   An IDE in production        GraphiQL, Playground, Apollo Sandbox, Altair
 *   Hints when it is "off"      "Did you mean ..." errors give the schema away piece by piece
 *   Mutations over GET          the word mutation with only __typename in it (it changes nothing)
 *                               is accepted on a GET, which makes it possible to trigger from a link
 *   Odd content types           text/plain or a form body accepted: no CORS preflight, so other sites can send it
 *   Batching                    two tiny queries in one request: the usual way past per-request limits
 *   Error detail                a broken query shows a stack trace or server paths
 *
 * It never sends a mutation (the client refuses), never a deep, wide or aliased query, never a long
 * batch and never a guess at passwords or codes. Depth, size and batching limits are left for you to
 * test by hand on a copy: they can bring a server down. Everything is asked signed out first.
 */
import type { Finding } from '../shared/types'
import { ConfirmClient, Stop, type Reply } from './confirmtests'
import { fid } from './scanners/parse'
import { proofOf } from './seckit/confirm'

export const GRAPHQL_PATHS = ['/graphql', '/api/graphql', '/v1/graphql', '/graphql/v1', '/query', '/gql', '/api/gql', '/graphql/', '/api']

const json = (r: Reply): Record<string, unknown> | null => {
  if (!/json/i.test(r.headers.get('content-type') ?? '') && !/^\s*[{[]/.test(r.body)) return null
  try {
    const v = JSON.parse(r.body) as unknown
    return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null
  } catch {
    return null
  }
}

const dataOf = (r: Reply): Record<string, unknown> | null => {
  const j = json(r)
  return j && j.data && typeof j.data === 'object' ? (j.data as Record<string, unknown>) : null
}

const errorsOf = (r: Reply): string => {
  const j = json(r)
  return j && Array.isArray(j.errors) ? j.errors.map((e) => (e && typeof e === 'object' ? String((e as { message?: unknown }).message ?? '') : '')).join(' | ') : ''
}

const body = (q: string): string => JSON.stringify({ query: q })
const SENSITIVE_TYPES = /^(user|users|account|admin|role|permission|password|credential|token|session|secret|apikey|payment|card|invoice|order|customer|employee|salary|patient|ssn)s?$/i

export interface Endpoint {
  path: string
  reply: Reply
}

/** Endpoints that answer a GraphQL question. */
export async function findEndpoints(c: ConfirmClient, paths: string[] = GRAPHQL_PATHS, extra: string[] = []): Promise<Endpoint[]> {
  const out: Endpoint[] = []
  for (const p of [...new Set([...extra, ...paths])].slice(0, 14)) {
    const r = await c.query(p, body('{__typename}'), { headers: 'none' }).catch((e) => (e instanceof Stop ? Promise.reject(e) : null))
    const d = r && dataOf(r)
    if (r && d && typeof d.__typename === 'string') out.push({ path: new URL(r.url).pathname, reply: r })
  }
  return out
}

const IDE = /graphiql|graphql[ -]playground|apollo (sandbox|studio)|altair graphql|graphql-voyager|<title>[^<]*graphql[^<]*<\/title>/i

/** Everything about one endpoint. */
export async function endpointChecks(c: ConfirmClient, e: Endpoint, o: { headers?: Record<string, string> } = {}): Promise<Finding[]> {
  const out: Finding[] = []
  const path = e.path
  const base = { tool: 'MacSec', category: 'web' as const, url: e.reply.url, file: e.reply.url, confidence: 'confirmed' as const }
  const sent = { 'Content-Type': 'application/json' }
  const post = (b: string, ct?: string): Promise<Reply> => c.query(path, b, { headers: 'none', contentType: ct })

  out.push({ id: fid('gql-endpoint', e.reply.url), ...base, severity: 'info', title: `A GraphQL endpoint answers without signing in: ${path}`, description: 'The endpoint answered a {__typename} question with no sign-in. That is normal for many APIs, and it tells you where to test: access control on every query and field, rate limits, and the ways listed in the checklist (GraphQL section).', fix: 'Make sure every query and mutation checks who is asking, per object and per field.', proof: proofOf({ method: 'POST', url: e.reply.url, status: e.reply.status, headers: e.reply.headers, body: e.reply.body, shows: ['{__typename} answered with data.__typename', 'no sign-in was sent'], sent }) })

  // Introspection: a small question about the schema.
  const intro = await post(body('{__schema{queryType{name} mutationType{name} types{name kind}}}')).catch((er) => (er instanceof Stop ? Promise.reject(er) : null))
  const schema = intro && (dataOf(intro)?.__schema as { types?: { name: string; kind: string }[]; mutationType?: { name: string } | null } | undefined)
  if (intro && schema && Array.isArray(schema.types)) {
    const types = schema.types.filter((t) => !t.name.startsWith('__'))
    const interesting = types.filter((t) => SENSITIVE_TYPES.test(t.name)).map((t) => t.name).slice(0, 8)
    out.push({ id: fid('gql-introspection', e.reply.url), ...base, severity: 'medium', title: `Anyone can read the whole GraphQL schema: ${path}`, cwe: 'CWE-200', description: `A signed-out introspection question returned ${types.length} types${schema.mutationType ? ' and a mutation type' : ''}${interesting.length ? `, including ${interesting.join(', ')}` : ''}. The full map of the API (every query, mutation and field) is public, which saves an attacker all the guessing. Public APIs sometimes do this on purpose.`, fix: 'Turn introspection off in production (it is one setting in Apollo, graphql-js, Hasura, Yoga and most servers), and still check access on every field: hiding the map is not protection.', proof: proofOf({ method: 'POST', url: intro.url, status: intro.status, headers: intro.headers, body: intro.body, shows: [`__schema returned ${types.length} types`, schema.mutationType ? `mutation type: ${schema.mutationType.name}` : 'no mutation type', ...(interesting.length ? [`types such as ${interesting.join(', ')}`] : []), 'asked signed out'], sent }) })
  } else {
    // Introspection is off. Does the error give the schema away piece by piece?
    const typo = await post(body('{__typenam}')).catch((er) => (er instanceof Stop ? Promise.reject(er) : null))
    const msg = typo ? errorsOf(typo) : ''
    const dym = /did you mean ["'“]?[A-Za-z_]/i.exec(msg)
    if (typo && dym)
      out.push({ id: fid('gql-suggest', e.reply.url), ...base, severity: 'low', title: `GraphQL suggests field names even with introspection off: ${path}`, cwe: 'CWE-209', description: `A misspelt field got the answer "${msg.slice(0, 160)}". Those suggestions let an attacker rebuild the schema one name at a time, so turning introspection off is not enough.`, fix: 'Turn suggestions off (Apollo: hideSchemaDetailsFromClientErrors; graphql-js and others have a similar option), or use a validation plugin that removes them.', proof: proofOf({ method: 'POST', url: typo.url, status: typo.status, headers: typo.headers, body: typo.body, shows: ['an unknown field was asked for', `the error says: ${msg.slice(0, 120)}`], sent }) })
  }

  // Detail in errors.
  const broken = await post('{"query":"{"}').catch((er) => (er instanceof Stop ? Promise.reject(er) : null))
  if (broken) {
    const text = `${broken.body.slice(0, 20000)}`
    const trace = /"stacktrace"|"exception"\s*:|\bat [\w$.<>]+ \((?:\/|[A-Za-z]:\\)[^)]*:\d+:\d+\)|node_modules\/|\/usr\/(?:src|local)\/|Traceback \(most recent call last\)|\.java:\d+\)/.exec(text)
    if (trace)
      out.push({ id: fid('gql-trace', e.reply.url), ...base, severity: 'low', title: `GraphQL errors show server internals: ${path}`, cwe: 'CWE-209', description: 'A broken query returned a stack trace or file paths. That tells an attacker which framework, versions and folders the server uses.', fix: 'In production return only short error messages (Apollo: NODE_ENV=production, or formatError that removes extensions.exception and stacktrace).', proof: proofOf({ method: 'POST', url: broken.url, status: broken.status, headers: broken.headers, body: broken.body, shows: ['a query that is only "{" was sent', `the answer contains "${trace[0].slice(0, 60)}"`], sent }) })
  }

  // A mutation (with only __typename in it, which does nothing) over GET.
  const getMutation = await c.get(`${path}?query=${encodeURIComponent('mutation{__typename}')}`, { headers: 'none' }).catch((er) => (er instanceof Stop ? Promise.reject(er) : null))
  const gd = getMutation && dataOf(getMutation)
  if (getMutation && gd && typeof gd.__typename === 'string' && !/GET.*(only|not allowed)|only (be )?(performed|executed|allowed) (via|in|over|on) POST/i.test(errorsOf(getMutation)))
    out.push({ id: fid('gql-getmutation', e.reply.url), ...base, severity: 'medium', title: `GraphQL runs mutations sent as a GET: ${path}`, cwe: 'CWE-352', description: 'A request with only the address, "mutation{__typename}" (it changes nothing), was run as a mutation. A GET can be triggered from a link or an image on any web page, with the visitor’s cookies, so real mutations could be sent the same way (this is how CSRF on GraphQL works). MacSec did not send a real mutation.', fix: 'Accept mutations only on POST, and require a content type of application/json (not a form type) or a custom header.', proof: proofOf({ url: getMutation.url, status: getMutation.status, headers: getMutation.headers, body: getMutation.body, shows: ['GET ?query=mutation{__typename}', 'the answer has data.__typename: the mutation type ran', 'no data was changed: __typename has no effect'] }) })

  // Types that do not trigger a CORS preflight.
  for (const ct of ['text/plain', 'application/x-www-form-urlencoded']) {
    const r = await post(body('{__typename}'), ct).catch((er) => (er instanceof Stop ? Promise.reject(er) : null))
    const d = r && dataOf(r)
    if (r && d && typeof d.__typename === 'string') {
      out.push({ id: fid('gql-ctype', e.reply.url, ct), ...base, severity: 'low', title: `GraphQL accepts ${ct} bodies: ${path}`, cwe: 'CWE-352', description: `The endpoint answered a question sent as ${ct}. Browsers send that type from any web page without asking the server first (no CORS preflight), so another site can send requests here with the visitor's cookies. This is the second ingredient of CSRF on GraphQL; it matters when sign-in is by cookie.`, fix: 'Accept only application/json, and use SameSite cookies or a CSRF token.', proof: proofOf({ method: 'POST', url: r.url, status: r.status, headers: r.headers, body: r.body, shows: [`Content-Type ${ct}`, 'the answer has data.__typename'], sent: { 'Content-Type': ct } }) })
      break
    }
  }

  // Batching: two tiny queries in one request.
  const batch = await post(JSON.stringify([{ query: '{__typename}' }, { query: '{__typename}' }])).catch((er) => (er instanceof Stop ? Promise.reject(er) : null))
  if (batch) {
    try {
      const v = JSON.parse(batch.body) as unknown
      if (Array.isArray(v) && v.length === 2 && v.every((x) => x && typeof x === 'object' && 'data' in (x as object)))
        out.push({ id: fid('gql-batch', e.reply.url), ...base, severity: 'info', title: `GraphQL accepts batched requests: ${path}`, description: 'Two queries in one request were both answered. Batching lets one request carry hundreds of attempts, which gets around limits that count requests (login and one-time-code guessing are the usual targets). MacSec sent only two harmless queries and never tried guessing: test it by hand on a copy.', fix: 'Turn batching off if you do not use it, or limit the batch size and count each query against the rate limit.', proof: proofOf({ method: 'POST', url: batch.url, status: batch.status, headers: batch.headers, body: batch.body, shows: ['an array of two {__typename} queries was sent', 'an array of two answers came back'], sent }) })
    } catch {
      /* not JSON */
    }
  }
  return out
}

/** Pages that are a GraphQL IDE. */
export async function ideChecks(c: ConfirmClient, paths: string[] = ['/graphql', '/graphiql', '/playground', '/api/graphql', '/altair', '/explorer', '/v1/graphql', '/console']): Promise<Finding[]> {
  const out: Finding[] = []
  for (const p of paths) {
    const r = await c.get(p, { headers: 'none' }).catch((e) => (e instanceof Stop ? Promise.reject(e) : null))
    if (!r || r.status !== 200 || !/html/i.test(r.headers.get('content-type') ?? '')) continue
    const m = IDE.exec(r.body.slice(0, 200000))
    if (!m) continue
    out.push({ id: fid('gql-ide', r.url), tool: 'MacSec', category: 'web', url: r.url, file: r.url, confidence: 'confirmed', severity: 'medium', title: `A GraphQL IDE is open to everyone: ${new URL(r.url).pathname}`, cwe: 'CWE-489', description: `The page is a GraphQL development tool (${m[0].slice(0, 40)}). It lets anyone explore the API and build queries in the browser, and on its own it is rated high by many testers.`, fix: 'Turn the IDE off in production, or put it behind a sign-in for staff.', proof: proofOf({ url: r.url, status: r.status, headers: r.headers, body: r.body.slice(0, 200000), shows: [`the page contains "${m[0].slice(0, 40)}"`, 'asked signed out', 'an HTML page, not a data answer'] }) })
  }
  return out
}

/** The whole GraphQL check. */
export async function graphqlChecks(c: ConfirmClient, o: { extraPaths?: string[]; note?: (t: string) => void } = {}): Promise<Finding[]> {
  const note = o.note ?? (() => undefined)
  const out: Finding[] = []
  try {
    note('Looking for GraphQL endpoints')
    const eps = await findEndpoints(c, GRAPHQL_PATHS, o.extraPaths ?? [])
    note(`${eps.length} ${eps.length === 1 ? 'endpoint' : 'endpoints'} found`)
    for (const e of eps.slice(0, 3)) {
      note(`Testing ${e.path}`)
      out.push(...(await endpointChecks(c, e)))
    }
    out.push(...(await ideChecks(c)))
  } catch (e) {
    if (e instanceof Stop) note(e.message)
    else throw e
  }
  const seen = new Set<string>()
  return out.filter((f) => (seen.has(f.id) ? false : (seen.add(f.id), true)))
}
