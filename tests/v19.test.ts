import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { afterAll, describe, expect, it } from 'vitest'
import { knowledgeBlock, knowledgeCount, pickKnowledge } from '../src/main/knowledge'
import { methodText, BOUNTY_SKILLS } from '../src/main/bountyskills'
import { coveredBy, planContext, planMarkdown, profileSite, SECTIONS } from '../src/main/testplan'
import { apkSchemes, onlineChecks, scanCode, signingFindings } from '../src/main/mobilestatic'
import { summaryPrompt } from '../src/main/aisummary'
import kb from '../src/main/data/kb.json'
import checklist from '../src/main/data/webchecklist.json'

const dir = mkdtempSync(join(tmpdir(), 'macsec-v19-'))
afterAll(() => rmSync(dir, { recursive: true, force: true }))

describe('knowledge base', () => {
  it('has notes and finds the right ones', () => {
    expect(knowledgeCount()).toBeGreaterThan(100)
    const ids = pickKnowledge('idor another account object id authorization', { max: 5 }).map((p) => p.id)
    expect(ids.length).toBeGreaterThan(0)
    expect(ids.some((i) => /authz|logic/.test(i))).toBe(true)
    expect(knowledgeBlock('certificate pinning android', { max: 2, maxChars: 4000 }).length).toBeLessThanOrEqual(4600)
    expect(pickKnowledge('zzzzqqq')).toEqual([])
  })
  it('never contains an em dash', () => {
    expect(JSON.stringify(kb)).not.toContain('—')
    expect(JSON.stringify(checklist)).not.toContain('—')
  })
})

describe('bounty skills', () => {
  it('are used before the shared ones', () => {
    expect(Object.keys(BOUNTY_SKILLS)).toContain('verify-with-proof')
    expect(methodText(['verify-with-proof'])).toContain(BOUNTY_SKILLS['verify-with-proof'].slice(0, 30))
    expect(methodText(['no-such-skill-xyz'])).toBe('')
  })
  it('go into the AI prompt with matching notes and a next-steps section', () => {
    const p = summaryPrompt('web', 'https://x.test', 'Detected: nginx', [{ id: 'a', tool: 'MacSec', category: 'web', severity: 'high', title: 'Another account can open this order (IDOR)' }])
    expect(p).toContain('What to try next')
    expect(p).toContain('Expert notes')
  })
})

describe('web checklist plan', () => {
  it('has the sections and profiles a site from its addresses', () => {
    expect(SECTIONS.length).toBeGreaterThan(40)
    const p = profileSite(['https://x.test/', 'https://x.test/login', 'https://x.test/api/v1/users', 'https://x.test/checkout', 'https://x.test/graphql'])
    expect(p.pages.login).toBeTruthy()
    expect(p.pages.checkout).toBeTruthy()
    const md = planMarkdown(p, 'https://x.test', ['auth'])
    expect(md).toContain('Test plan')
    expect(md).not.toContain('—')
    expect(md.length).toBeGreaterThan(500)
    expect(planContext(p, ['auth']).length).toBeGreaterThan(100)
  })
  it('marks what MacSec already ran', () => {
    expect(coveredBy('Check the account lockout after many wrong passwords', ['auth'])).toBeTruthy()
    expect(coveredBy('Check the account lockout after many wrong passwords', [])).toBeNull()
  })
})

/** A tiny zip-shaped buffer with an APK Signing Block holding the given pair ids. */
function apkWith(ids: number[]): Buffer {
  const pairs = ids.map((id) => {
    const b = Buffer.alloc(8 + 4 + 4)
    b.writeBigUInt64LE(8n, 0)
    b.writeUInt32LE(id, 8)
    return b
  })
  const body = Buffer.concat(pairs)
  const size = body.length + 24
  const head = Buffer.alloc(8)
  head.writeBigUInt64LE(BigInt(size), 0)
  const tail = Buffer.alloc(8)
  tail.writeBigUInt64LE(BigInt(size), 0)
  const block = Buffer.concat([head, body, tail, Buffer.from('APK Sig Block 42', 'latin1')])
  const pre = Buffer.alloc(40)
  const cd = Buffer.alloc(46)
  const eocd = Buffer.alloc(22)
  eocd.writeUInt32LE(0x06054b50, 0)
  eocd.writeUInt32LE(pre.length + block.length, 16)
  return Buffer.concat([pre, block, cd, eocd])
}

describe('signing', () => {
  it('reads the v2 and v3 schemes from the signing block', () => {
    expect(apkSchemes(apkWith([0x7109871a]))).toEqual({ block: true, v2: true, v3: false })
    expect(apkSchemes(apkWith([0x7109871a, 0xf05368c0])).v3).toBe(true)
    expect(apkSchemes(Buffer.alloc(100)).block).toBe(false)
  })
  it('reports v1 only and the debug certificate as confirmed facts', () => {
    const un = join(dir, 'un')
    mkdirSync(join(un, 'META-INF'), { recursive: true })
    writeFileSync(join(un, 'META-INF', 'CERT.SF'), 'x')
    writeFileSync(join(un, 'META-INF', 'CERT.RSA'), 'CN=Android Debug, O=Android')
    const f = signingFindings(Buffer.alloc(100), un)
    expect(f.map((x) => x.title).join('|')).toMatch(/v1 scheme only/)
    expect(f.map((x) => x.title).join('|')).toMatch(/debug certificate/)
    expect(f.every((x) => x.confidence === 'confirmed' && x.proof)).toBe(true)
    expect(signingFindings(apkWith([0x7109871a]), join(dir, 'none'))).toEqual([])
  })
})

describe('what the code names', () => {
  it('finds weak settings, but only as possible', () => {
    const t = 'okhttp3 AllowAllHostnameVerifier AES/ECB/PKCS5Padding addJavascriptInterface setJavaScriptEnabled http://api.old-example-corp.com/v1 https://api.real-corp.com/x https://my-app-1234.firebaseio.com https://bucket-one.s3.amazonaws.com/a'
    const r = scanCode(t, 'android')
    const titles = r.findings.map((f) => f.title).join('|')
    expect(titles).toMatch(/accepts everything/)
    expect(titles).toMatch(/weak encryption/)
    expect(titles).toMatch(/WebView can call/)
    expect(titles).toMatch(/Plain http/)
    expect(titles).toMatch(/No certificate pinning/)
    expect(r.findings.every((f) => f.confidence === 'possible')).toBe(true)
    expect(r.refs.firebase).toEqual(['my-app-1234.firebaseio.com'])
    expect(r.refs.s3).toEqual(['bucket-one'])
    expect(r.hosts).toContain('api.real-corp.com')
  })
  it('recognises pinning and root checks, and ignores schema addresses', () => {
    const r = scanCode('Lokhttp3/CertificatePinner; com/scottyab/rootbeer http://schemas.android.com/apk/res/android http://localhost:8080', 'android')
    const titles = r.findings.map((f) => f.title).join('|')
    expect(titles).toMatch(/pinning is present/)
    expect(titles).toMatch(/checks for a rooted phone/)
    expect(titles).not.toMatch(/Plain http/)
  })
  it('reads iOS settings', () => {
    const r = scanCode('NSPinnedDomains /Applications/Cydia.app UIWebView CC_MD5 kSecAttrAccessibleAlways', 'ios')
    const titles = r.findings.map((f) => f.title).join('|')
    expect(titles).toMatch(/pinning is present/)
    expect(titles).toMatch(/jailbroken/)
    expect(titles).toMatch(/UIWebView/)
    expect(titles).toMatch(/Keychain/)
  })
})

describe('online checks', () => {
  const reply = (status: number, body: string) => (async () => new Response(body, { status })) as unknown as typeof fetch
  it('confirms an open Firebase database with proof, without saving key names', async () => {
    const f = await onlineChecks({ firebase: ['my-app-1234.firebaseio.com'], s3: [], gcs: [] }, reply(200, '{"users":true,"orders":true}'))
    expect(f).toHaveLength(1)
    expect(f[0].confidence).toBe('confirmed')
    expect(f[0].severity).toBe('high')
    expect(f[0].proof?.request).toBe('GET https://my-app-1234.firebaseio.com/.json?shallow=true')
    expect(JSON.stringify(f[0])).not.toContain('orders')
  })
  it('says nothing when the answer is a refusal', async () => {
    expect(await onlineChecks({ firebase: ['a-b.firebaseio.com'], s3: ['bucket-one'], gcs: ['bucket-two'] }, reply(401, '{"error":"Permission denied"}'))).toEqual([])
  })
  it('finds a listing bucket and a bucket nobody owns', async () => {
    const listing = await onlineChecks({ firebase: [], s3: ['bucket-one'], gcs: [] }, reply(200, '<ListBucketResult><Key>secret.txt</Key></ListBucketResult>'))
    expect(listing[0].severity).toBe('high')
    expect(JSON.stringify(listing[0])).not.toContain('secret.txt')
    const gone = await onlineChecks({ firebase: [], s3: ['bucket-one'], gcs: [] }, reply(404, '<Error><Code>NoSuchBucket</Code></Error>'))
    expect(gone[0].confidence).toBe('possible')
    const gcs = await onlineChecks({ firebase: [], s3: [], gcs: ['bucket-two'] }, reply(200, '{"kind":"storage#objects"}'))
    expect(gcs[0].title).toMatch(/Google Cloud Storage/)
  })
  it('refuses odd names and never follows redirects', async () => {
    let calls = 0
    let redirect = ''
    const f = (async (_u: string, o: RequestInit) => {
      calls++
      redirect = String(o.redirect)
      return new Response('', { status: 200 })
    }) as unknown as typeof fetch
    await onlineChecks({ firebase: ['evil.com/../x'], s3: ['bad name'], gcs: ['x'] }, f)
    expect(calls).toBe(0)
    await onlineChecks({ firebase: ['ok-1.firebaseio.com'], s3: [], gcs: [] }, f)
    expect(redirect).toBe('manual')
  })
})
