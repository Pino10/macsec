/**
 * Deeper checks of a built app, straight from the file with nothing to install or run:
 *
 *   Signing        which signature schemes an .apk uses, and whether it carries the debug certificate
 *   Code           what the app's compiled code names: certificate pinning, root or jailbreak checks,
 *                  accept-everything certificate code, weak crypto, WebView bridges, plain http addresses
 *   Online (opt-in) the Firebase, S3 and Google Cloud Storage addresses found inside the app, asked once
 *                  each with a read-only request, to see whether anyone can read them
 *
 * What the code names is not proof that it runs (it may be unused or part of a library), so those
 * findings are "possible". Signing facts and online answers are "confirmed" and carry proof.
 */
import { createHash } from 'crypto'
import { existsSync, readdirSync, readFileSync } from 'fs'
import { join } from 'path'
import type { Finding } from '../shared/types'
import { fid } from './scanners/parse'
import type { Proof } from './seckit/confirm'
import { printable } from './mobilelive'

// ---------------------------------------------------------------- Signing

/** Which signature schemes the APK Signing Block holds (v2 and later live in a block before the zip's directory). */
export function apkSchemes(buf: Buffer): { block: boolean; v2: boolean; v3: boolean } {
  const none = { block: false, v2: false, v3: false }
  const from = Math.max(0, buf.length - 65557)
  let eocd = -1
  for (let i = buf.length - 22; i >= from; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocd = i
      break
    }
  }
  if (eocd < 0) return none
  const cd = buf.readUInt32LE(eocd + 16)
  if (cd < 32 || cd > buf.length || buf.subarray(cd - 16, cd).toString('latin1') !== 'APK Sig Block 42') return none
  const size = Number(buf.readBigUInt64LE(cd - 24))
  const start = cd - size - 8
  if (start < 0 || size < 24) return none
  let v2 = false
  let v3 = false
  let pos = start + 8
  while (pos + 12 <= cd - 24) {
    const len = Number(buf.readBigUInt64LE(pos))
    if (len < 4 || pos + 8 + len > cd) break
    const id = buf.readUInt32LE(pos + 8)
    if (id === 0x7109871a) v2 = true
    if (id === 0xf05368c0 || id === 0x1b93ad61) v3 = true
    pos += 8 + len
  }
  return { block: true, v2, v3 }
}

const f = (x: Omit<Finding, 'id' | 'tool' | 'category'>, key: string): Finding => ({ id: fid('mobile-deep', x.title, x.file ?? '', key), tool: 'MacSec', category: 'mobile', ...x })

const fileProof = (what: string, shows: string[], body = ''): Proof => ({ request: what, reproduce: what, status: 0, bytes: Buffer.byteLength(body), sha256: createHash('sha256').update(body).digest('hex'), at: new Date().toISOString(), shows: shows.slice(0, 12).map((s) => s.slice(0, 200)) })

/** The signing facts of an unpacked .apk: its schemes, and whether the debug certificate was used. */
export function signingFindings(apk: Buffer, unpacked: string): Finding[] {
  const out: Finding[] = []
  const meta = join(unpacked, 'META-INF')
  const names = existsSync(meta) ? readdirSync(meta) : []
  const v1 = names.some((n) => /\.SF$/i.test(n))
  const s = apkSchemes(apk)
  if (!s.v2 && !s.v3 && v1)
    out.push(f({ severity: 'medium', confidence: 'confirmed', title: 'The app is signed with the old v1 scheme only', file: 'META-INF', cwe: 'CWE-347', description: 'It has no v2 or v3 signature. The v1 scheme does not cover the whole file, so on older Android versions someone can add code to the app and keep a valid signature (the “Janus” flaw).', fix: 'Sign with apksigner (v2 and v3 on), and raise the minimum Android version where you can.', proof: fileProof('apk signing block', ['the file has META-INF/*.SF (v1)', 'no APK Signing Block with a v2 or v3 signature was found']) }, 'v1only'))
  for (const n of names.filter((x) => /\.(RSA|DSA|EC)$/i.test(x))) {
    if (readFileSync(join(meta, n)).toString('latin1').includes('Android Debug'))
      out.push(f({ severity: 'medium', confidence: 'confirmed', title: 'The app is signed with the Android debug certificate', file: `META-INF/${n}`, cwe: 'CWE-489', description: 'This is a debug build, or the release was signed with the debug key. The debug key is the same on millions of machines, so anyone can re-sign and republish the app, and debug builds are often easier to attack.', fix: 'Build the release with your own release key, kept in a safe place, and never ship a debug build.', proof: fileProof(`META-INF/${n}`, ['the certificate’s name contains “Android Debug”']) }, `debugcert${n}`))
  }
  return out
}

// ---------------------------------------------------------------- What the code names

export type Platform = 'android' | 'ios'

interface Rule {
  id: string
  platform: Platform | 'both'
  re: RegExp
  /** All of these must match too. */
  and?: RegExp[]
  severity: Finding['severity']
  title: string
  description: string
  fix?: string
  cwe?: string
}

const NOTE = ' This is what the app’s code names; it may be unused or belong to a library, so confirm it by hand or with the live test.'

const RULES: Rule[] = [
  { id: 'trustall', platform: 'android', re: /ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier|NullHostnameVerifier|TrustAllCerts|TrustAllManager|trustAllCerts|AcceptAllCerts|NaiveTrustManager/, severity: 'medium', title: 'The code has a certificate or hostname check that accepts everything', cwe: 'CWE-295', description: `Names such as “trust all certificates” or “allow all hostnames” appear in the code. If used, anyone on the same network can read and change the app's traffic.${NOTE}`, fix: 'Remove it and use the system’s certificate checks, with pinning where the data is sensitive.' },
  { id: 'trustall-ios', platform: 'ios', re: /allowInvalidCertificates|setAllowsAnyHTTPSCertificate|kCFStreamSSLValidatesCertificateChain|disableEvaluation/, severity: 'medium', title: 'The code can turn certificate checks off', cwe: 'CWE-295', description: `Settings that disable certificate validation appear in the code.${NOTE}`, fix: 'Remove them and use the system’s certificate checks, with pinning where the data is sensitive.' },
  { id: 'webview-bridge', platform: 'android', re: /addJavascriptInterface/, and: [/setJavaScriptEnabled/], severity: 'medium', title: 'A WebView can call into the app’s code', cwe: 'CWE-749', description: `JavaScript is enabled and a native bridge is added. If the WebView ever loads a page the app does not control, that page can call the bridge.${NOTE}`, fix: 'Only load your own pages in that WebView, and expose the fewest methods, each marked @JavascriptInterface.' },
  { id: 'webview-file', platform: 'android', re: /setAllowFileAccessFromFileURLs|setAllowUniversalAccessFromFileURLs/, severity: 'medium', title: 'A WebView lets web pages read local files', cwe: 'CWE-200', description: `A WebView setting lets pages opened from a file read other files on the phone.${NOTE}`, fix: 'Leave file access off in WebViews.' },
  { id: 'webview-debug', platform: 'android', re: /setWebContentsDebuggingEnabled/, severity: 'low', title: 'WebView debugging may be turned on', cwe: 'CWE-489', description: `WebView debugging lets someone with the phone inspect and change what the app shows.${NOTE}`, fix: 'Turn it on only in debug builds.' },
  { id: 'ecb', platform: 'both', re: /AES\/ECB|DES\/ECB|kCCOptionECBMode|"DESede"|"DES"|\bRC4\b|kCCAlgorithmDES|kCCAlgorithmRC4/, severity: 'medium', title: 'The code names weak encryption (ECB mode, DES or RC4)', cwe: 'CWE-327', description: `ECB mode reveals patterns in the data, and DES and RC4 are broken.${NOTE}`, fix: 'Use AES-GCM (or ChaCha20-Poly1305) with a fresh random nonce for every message.' },
  { id: 'world', platform: 'android', re: /MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE/, severity: 'medium', title: 'The code can create files that other apps may read or write', cwe: 'CWE-922', description: `Android stopped honouring these modes in newer versions, but their presence suggests old code that stores data carelessly.${NOTE}`, fix: 'Keep app data private, and use a FileProvider to share files on purpose.' },
  { id: 'oldtls', platform: 'android', re: /"SSLv3"|"TLSv1"|"TLSv1\.0"|"TLSv1\.1"/, severity: 'low', title: 'The code names an outdated TLS version', cwe: 'CWE-326', description: `SSLv3, TLS 1.0 and 1.1 are retired.${NOTE}`, fix: 'Use TLS 1.2 or 1.3 only.' },
  { id: 'ios-keychain', platform: 'ios', re: /kSecAttrAccessibleAlways(?!ThisDeviceOnly)|kSecAttrAccessibleAlwaysThisDeviceOnly/, severity: 'medium', title: 'The code stores Keychain items that are readable while the phone is locked', cwe: 'CWE-311', description: `“Always” accessibility keeps secrets readable even before the first unlock.${NOTE}`, fix: 'Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly (or AfterFirstUnlock where background work needs it).' },
  { id: 'uiwebview', platform: 'ios', re: /UIWebView/, severity: 'low', title: 'The app uses UIWebView', cwe: 'CWE-1104', description: `UIWebView is deprecated and has weaker security than WKWebView. Apple no longer accepts new apps that use it.${NOTE}`, fix: 'Move to WKWebView.' },
  { id: 'weakhash', platform: 'both', re: /"MD5"|CC_MD5\b|"SHA-?1"|CC_SHA1\b/, severity: 'low', title: 'The code names MD5 or SHA-1', cwe: 'CWE-328', description: `Both are weak for passwords, signatures and integrity. They are fine for non-security uses such as cache keys.${NOTE}`, fix: 'Use SHA-256 or better, and a slow password hash (Argon2, bcrypt or scrypt) for passwords.' }
]

const INFO = {
  pinning: { android: /Lokhttp3\/CertificatePinner;|datatheorem\/android\/trustkit|TrustKit|CertificatePinning|appmattus\/certificatetransparency|ssl_pinning|SslPinning|certificate_pinning|PinningTrustManager/, ios: /TrustKit|AFSecurityPolicy|pinnedCertificates|ServerTrustManager|PinnedCertificatesTrustEvaluator|SSLPinning|CertificatePinning|NSPinnedDomains/ },
  root: { android: /com\/scottyab\/rootbeer|RootBeer|Superuser\.apk|\/system\/xbin\/su|isRooted|RootDetection|magisk|SafetyNetClient|com\/google\/android\/play\/core\/integrity|IntegrityManager/i, ios: /\/Applications\/Cydia\.app|\/Library\/MobileSubstrate|cydia:\/\/|\/usr\/sbin\/sshd|JailbreakDetection|IOSSecuritySuite|isJailbroken|DTTJailbreakDetection/i },
  debug: { android: /isDebuggerConnected|Debug\.waitingForDebugger/, ios: /PT_DENY_ATTACH|P_TRACED/ }
}

const BENIGN = /^(localhost|127\.|10\.0\.2\.2$|0\.0\.0\.0$|example\.|schemas\.|www\.w3\.org$|xmlns|ns\.adobe\.com$|apache\.org$|www\.apache\.org$|java\.sun\.com$|xml\.org$|www\.xmlpull\.org$|xmlpull\.org$|android\.com$|schemas\.android\.com$|developer\.android\.com$|play\.google\.com$|goo\.gl$|git|github\.com$|jsonschema\.org$|json-schema\.org$|www\.slf4j\.org$|slf4j\.org$|opensource\.org$|www\.opensource\.org$|creativecommons\.org$)/i

export interface Refs {
  firebase: string[]
  s3: string[]
  gcs: string[]
}

export interface CodeScan {
  findings: Finding[]
  refs: Refs
  /** Servers named in the code (https). */
  hosts: string[]
}

const uniq = <T>(a: T[]): T[] => [...new Set(a)]

/** Reads text from an app's compiled code (strings of a dex file or an iOS binary) and reports what it names. */
export function scanCode(text: string, platform: Platform, o: { hasPinSet?: boolean } = {}): CodeScan {
  const findings: Finding[] = []
  for (const r of RULES) {
    if (r.platform !== 'both' && r.platform !== platform) continue
    if (!r.re.test(text) || (r.and && !r.and.every((a) => a.test(text)))) continue
    findings.push(f({ severity: r.severity, confidence: 'possible', title: r.title, file: platform === 'android' ? 'classes.dex' : 'app binary', cwe: r.cwe, description: r.description, fix: r.fix, proof: fileProof(`strings of the app's ${platform === 'android' ? 'compiled code' : 'binary'}`, [`matched: ${(r.re.exec(text)?.[0] ?? '').slice(0, 80)}`]) }, r.id))
  }

  const pin = INFO.pinning[platform].exec(text)?.[0]
  if (pin || o.hasPinSet) findings.push(f({ severity: 'info', confidence: 'possible', title: 'Certificate pinning is present', file: pin ? (platform === 'android' ? 'classes.dex' : 'app binary') : 'network security config', description: `Pinning was found (${pin ?? 'a pin-set in the network security config'}). It makes it harder to read the app's traffic with a proxy. Whether it covers every server is for the live test or a manual check.`, proof: fileProof('static check', [`found: ${pin ?? '<pin-set> in network_security_config.xml'}`]) }, 'pin'))
  else findings.push(f({ severity: 'low', confidence: 'possible', title: 'No certificate pinning was found in the app', file: platform === 'android' ? 'classes.dex' : 'app binary', cwe: 'CWE-295', description: 'No known pinning library, pin-set or pinned-domain setting was found. Without pinning, someone who gets their own certificate trusted on the phone can read the traffic. It is optional for many apps, expected for banking, payment and health apps. The code may pin in its own way, which this check cannot see.', fix: 'Pin the server certificate or its public key (Android’s network security config or OkHttp CertificatePinner; iOS NSPinnedDomains or TrustKit), and plan for key rotation.', proof: fileProof('static check', ['no pinning library, pin-set or pinned domain was found']) }, 'nopin'))

  const root = INFO.root[platform].exec(text)?.[0]
  findings.push(f({ severity: 'info', confidence: 'possible', title: root ? `The app checks for a ${platform === 'android' ? 'rooted' : 'jailbroken'} phone` : `No ${platform === 'android' ? 'root' : 'jailbreak'} check was found`, file: platform === 'android' ? 'classes.dex' : 'app binary', description: root ? `Names such as “${root.slice(0, 40)}” appear in the code. This slows casual tampering but can be bypassed, so server-side checks still matter.` : 'Nothing that looks like a root or jailbreak check was found. It is optional, but banking, payment and health apps usually have one.', proof: fileProof('static check', [root ? `found: ${root.slice(0, 60)}` : 'no known root or jailbreak check was found']) }, 'root'))
  const dbg = INFO.debug[platform].exec(text)?.[0]
  if (dbg) findings.push(f({ severity: 'info', confidence: 'possible', title: 'The app looks for a debugger', file: platform === 'android' ? 'classes.dex' : 'app binary', description: 'An anti-debugging check is named in the code.', proof: fileProof('static check', [`found: ${dbg}`]) }, 'dbg'))

  // Plain http addresses, and the servers the app names.
  const http: string[] = []
  const hosts: string[] = []
  for (const m of text.matchAll(/\bhttps?:\/\/([a-z0-9.-]+\.[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?/gi)) {
    const h = m[1].toLowerCase()
    if (BENIGN.test(h)) continue
    if (m[0].toLowerCase().startsWith('http://')) http.push(h)
    else hosts.push(h)
  }
  const plain = uniq(http).slice(0, 25)
  if (plain.length)
    findings.push(f({ severity: 'low', confidence: 'possible', title: `Plain http addresses are written into the app (${plain.length})`, file: plain[0], cwe: 'CWE-319', description: `${plain.join(', ')}. Plain http is not encrypted. Some may be old, unused or only text, so check which ones the app really calls.`, fix: 'Use https everywhere, and turn cleartext traffic off in the network security config.', proof: fileProof('static check', plain.slice(0, 12).map((h) => `http://${h}`)) }, 'http'))
  const named = uniq(hosts).slice(0, 60)
  if (named.length)
    findings.push(f({ severity: 'info', confidence: 'possible', title: `Servers named in the app: ${named.length}`, file: named[0], description: `${named.join(', ')}. Staging, test and old API versions are worth testing: they are often weaker than the live API.`, proof: fileProof('static check', named.slice(0, 12)) }, 'hosts'))

  const refs = cloudRefs(text)
  return { findings, refs, hosts: named }
}

/** Firebase, S3 and Google Storage addresses written in some text (an app's code, a script). */
export function cloudRefs(text: string): Refs {
  const refs: Refs = { firebase: [], s3: [], gcs: [] }
  for (const m of text.matchAll(/\b([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.(?:firebaseio\.com|firebasedatabase\.app))\b/gi)) refs.firebase.push(m[1].toLowerCase())
  for (const m of text.matchAll(/\b([a-z0-9][a-z0-9.-]{2,62})\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\b/gi)) refs.s3.push(m[1].toLowerCase())
  for (const m of text.matchAll(/\bs3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\/([a-z0-9][a-z0-9.-]{2,62})\b/gi)) refs.s3.push(m[1].toLowerCase())
  for (const m of text.matchAll(/\bstorage\.googleapis\.com\/([a-z0-9][a-z0-9._-]{2,62})\b/gi)) refs.gcs.push(m[1].toLowerCase())
  for (const m of text.matchAll(/\b([a-z0-9][a-z0-9._-]{2,62})\.storage\.googleapis\.com\b/gi)) refs.gcs.push(m[1].toLowerCase())
  const skip = new Set(['v1', 'v2', 'storage', 'download', 'upload', 'b', 'www', 'static', 'cloud'])
  refs.firebase = uniq(refs.firebase).slice(0, 6)
  refs.s3 = uniq(refs.s3).filter((b) => !skip.has(b)).slice(0, 6)
  refs.gcs = uniq(refs.gcs).filter((b) => !skip.has(b)).slice(0, 6)
  return refs
}

/** The printable text of an app's compiled files, for scanCode. */
export function codeText(files: Buffer[]): string {
  return files.map((b) => printable(b)).join('\n')
}

// ---------------------------------------------------------------- Online checks (opt-in)

const UA = 'MacSec (+https://github.com/Pino10/macsec)'

async function get(f: typeof fetch, url: string): Promise<{ status: number; body: string } | null> {
  try {
    const r = await f(url, { redirect: 'manual', headers: { 'User-Agent': UA }, signal: AbortSignal.timeout(10_000) })
    return { status: r.status, body: (await r.text()).slice(0, 20000) }
  } catch {
    return null
  }
}

const reqProof = (url: string, status: number, body: string, shows: string[]): Proof => ({ request: `GET ${url}`, reproduce: `curl -sS -i '${url}'`, status, bytes: Buffer.byteLength(body), sha256: createHash('sha256').update(body).digest('hex'), at: new Date().toISOString(), shows })

/**
 * Asks once, read only, whether the cloud addresses found in an app can be read by anyone.
 * At most six of each kind. Names are checked before they are put in an address.
 */
export async function onlineChecks(refs: Refs, fetchImpl: typeof fetch = fetch): Promise<Finding[]> {
  const out: Finding[] = []
  for (const host of refs.firebase.filter((h) => /^[a-z0-9-]+(\.[a-z0-9-]+)*\.(firebaseio\.com|firebasedatabase\.app)$/.test(h))) {
    const url = `https://${host}/.json?shallow=true`
    const r = await get(fetchImpl, url)
    if (!r || r.status !== 200) continue
    let json: unknown
    try {
      json = JSON.parse(r.body)
    } catch {
      continue
    }
    const keys = json && typeof json === 'object' ? Object.keys(json as object).length : 0
    out.push(f({ severity: keys ? 'high' : 'low', confidence: 'confirmed', title: keys ? `A Firebase database named in the app can be read by anyone: ${host}` : `A Firebase database named in the app answers without sign-in (it is empty): ${host}`, url, file: host, cwe: 'CWE-284', description: keys ? `Asking for the database root without signing in returned its top-level data (${keys} entries). Anyone can read it, and writes may be open too.` : 'The database root can be read without signing in, but it holds no data. Its rules are still open, so check whether writes are allowed.', fix: 'Set Realtime Database rules so that reads and writes need an authenticated user and are limited to that user’s own data (not “.read”: true).', proof: reqProof(url, r.status, r.body, ['answered 200 with no sign-in', keys ? `${keys} top-level entries (names are not saved)` : 'an empty database']) }, host))
  }
  for (const b of refs.s3.filter((x) => /^[a-z0-9][a-z0-9.-]{2,62}$/.test(x))) {
    const url = `https://${b}.s3.amazonaws.com/?max-keys=1`
    const r = await get(fetchImpl, url)
    if (!r) continue
    if (r.status === 200 && /<ListBucketResult/.test(r.body))
      out.push(f({ severity: 'high', confidence: 'confirmed', title: `A storage bucket named in the app lists its files to anyone: ${b}`, url, file: b, cwe: 'CWE-538', description: 'Asking for the bucket without signing in returned a file listing, so anyone can see what is stored, and often download it.', fix: 'Turn on S3 Block Public Access for the bucket, and give the app access through signed links or an identity instead.', proof: reqProof(url, r.status, r.body, ['answered 200 with a file listing, nothing signed', 'file names are not saved']) }, b))
    else if (r.status === 404 && /NoSuchBucket/.test(r.body))
      out.push(f({ severity: 'medium', confidence: 'possible', title: `The app names a storage bucket that does not exist: ${b}`, url, file: b, cwe: 'CWE-1390', description: 'The app points at a bucket name nobody owns. Anyone could create a bucket with that name and serve files to the app.', fix: 'Remove the reference, or create the bucket yourself and lock it down.', proof: reqProof(url, r.status, r.body, ['answered 404 NoSuchBucket']) }, `nsb${b}`))
  }
  for (const b of refs.gcs.filter((x) => /^[a-z0-9][a-z0-9._-]{2,62}$/.test(x))) {
    const url = `https://storage.googleapis.com/storage/v1/b/${b}/o?maxResults=1`
    const r = await get(fetchImpl, url)
    if (r?.status === 200 && /storage#objects/.test(r.body))
      out.push(f({ severity: 'high', confidence: 'confirmed', title: `A Google Cloud Storage bucket named in the app lists its files to anyone: ${b}`, url, file: b, cwe: 'CWE-538', description: 'Asking for the bucket without signing in returned a file listing.', fix: 'Remove allUsers and allAuthenticatedUsers from the bucket’s permissions, and turn on public access prevention.', proof: reqProof(url, r.status, r.body, ['answered 200 with an object listing, nothing signed', 'file names are not saved']) }, `gcs${b}`))
  }
  return out
}
