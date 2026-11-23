/**
 * More read-only mobile checks from the files of an app: deep links, entitlements, the iOS privacy
 * manifest, third-party SDKs, the addresses written into the code, and the app bundle formats
 * Android uses for the store (.aab, .apks) and Xcode produces (.xcarchive).
 * Nothing here runs the app or sends a request.
 */
import { readdirSync, statSync } from 'fs'
import { join } from 'path'
import type { Finding, Severity } from '../shared/types'
import { fid } from './scanners/parse'

const mk = (tool: string, key: string, severity: Severity, title: string, file: string | undefined, description: string, fix: string, extra: Partial<Finding> = {}): Finding => ({
  id: fid(tool, key, file), tool, category: 'mobile', severity, confidence: 'possible', title, file, description, fix, ...extra
})

// ---------------------------------------------------------------- File formats

export type MobileFormat = 'source' | 'apk' | 'ipa' | 'aab' | 'apks' | 'xcarchive'

export function formatOf(path: string, isDir: boolean): MobileFormat {
  const e = /\.([a-z]+)\/?$/i.exec(path)?.[1]?.toLowerCase()
  if (e === 'xcarchive') return 'xcarchive'
  if (isDir) return 'source'
  return e === 'apk' ? 'apk' : e === 'ipa' ? 'ipa' : e === 'aab' ? 'aab' : e === 'apks' ? 'apks' : 'source'
}

/** Inside an .apks set: the file that holds the app's own code and manifest. */
export function baseApkIn(names: string[]): string | null {
  const pick = (re: RegExp): string | undefined => names.find((n) => re.test(n))
  return pick(/(^|\/)base-master\.apk$/) ?? pick(/(^|\/)base\.apk$/) ?? pick(/(^|\/)(standalone|universal)[^/]*\.apk$/) ?? pick(/\.apk$/) ?? null
}

/** The .app inside an .xcarchive (Products/Applications/Name.app). */
export function appInArchive(archive: string): string | null {
  const dir = join(archive, 'Products', 'Applications')
  try {
    const app = readdirSync(dir).find((n) => n.endsWith('.app') && statSync(join(dir, n)).isDirectory())
    return app ? join(dir, app) : null
  } catch {
    return null
  }
}

// ---------------------------------------------------------------- Android App Bundle manifest

/** Reads one protobuf message into its fields (field number -> values). Only what a manifest needs. */
function fields(buf: Buffer): Map<number, (Buffer | number)[]> {
  const out = new Map<number, (Buffer | number)[]>()
  let i = 0
  const varint = (): number => {
    let r = 0
    let shift = 0
    for (;;) {
      if (i >= buf.length) throw new Error('cut short')
      const b = buf[i++]
      r += (b & 0x7f) * 2 ** shift
      if (!(b & 0x80)) return r
      shift += 7
      if (shift > 49) throw new Error('number too long')
    }
  }
  while (i < buf.length) {
    const tag = varint()
    const num = Math.floor(tag / 8)
    const wire = tag % 8
    let v: Buffer | number
    if (wire === 0) v = varint()
    else if (wire === 2) {
      const len = varint()
      if (i + len > buf.length) throw new Error('cut short')
      v = buf.subarray(i, i + len)
      i += len
    } else if (wire === 1) {
      v = buf.subarray(i, i + 8)
      i += 8
    } else if (wire === 5) {
      v = buf.subarray(i, i + 4)
      i += 4
    } else throw new Error('unknown field')
    out.set(num, [...(out.get(num) ?? []), v])
  }
  return out
}
const str = (v: Buffer | number | undefined): string => (Buffer.isBuffer(v) ? v.toString('utf8') : '')
const esc = (s: string): string => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;')

/**
 * An .aab keeps AndroidManifest.xml as protobuf (aapt2's XmlNode), which Androguard cannot read. This turns it
 * back into the XML text the manifest check reads. Only the manifest's own words are used.
 */
export function protoManifestToXml(buf: Buffer): string {
  const prefixes = new Map<string, string>()
  const collect = (node: Buffer, depth = 0): void => {
    if (depth > 40) throw new Error('too deep')
    const el = fields(node).get(1)?.[0]
    if (!Buffer.isBuffer(el)) return
    const f = fields(el)
    for (const ns of f.get(1) ?? []) if (Buffer.isBuffer(ns)) {
      const n = fields(ns)
      prefixes.set(str(n.get(2)?.[0]), str(n.get(1)?.[0]))
    }
    for (const c of f.get(5) ?? []) if (Buffer.isBuffer(c)) collect(c, depth + 1)
  }
  collect(buf)
  const write = (node: Buffer, depth = 0): string => {
    if (depth > 40) throw new Error('too deep')
    const nf = fields(node)
    const text = nf.get(2)?.[0]
    if (Buffer.isBuffer(text)) return esc(text.toString('utf8'))
    const el = nf.get(1)?.[0]
    if (!Buffer.isBuffer(el)) return ''
    const f = fields(el)
    const name = str(f.get(3)?.[0])
    const attrs = (f.get(4) ?? [])
      .filter(Buffer.isBuffer)
      .map((a) => {
        const af = fields(a)
        const ns = str(af.get(1)?.[0])
        let value = str(af.get(3)?.[0])
        if (!value && Buffer.isBuffer(af.get(6)?.[0])) {
          // A compiled value with no text: a number or a true/false.
          const prim = fields(fields(af.get(6)![0] as Buffer).get(6)?.[0] as Buffer ?? Buffer.alloc(0))
          if (prim.has(8)) value = prim.get(8)![0] ? 'true' : 'false'
          else if (prim.has(6)) value = String(prim.get(6)![0])
          else if (prim.has(7)) value = `0x${Number(prim.get(7)![0]).toString(16)}`
        }
        const p = ns ? prefixes.get(ns) : ''
        return `${p ? `${p}:` : ''}${str(af.get(2)?.[0])}="${esc(value)}"`
      })
    const decl = (f.get(1) ?? []).filter(Buffer.isBuffer).map((ns) => {
      const n = fields(ns)
      return `xmlns:${str(n.get(1)?.[0])}="${esc(str(n.get(2)?.[0]))}"`
    })
    const kids = (f.get(5) ?? []).filter(Buffer.isBuffer).map((c) => write(c, depth + 1)).join('')
    return `<${name}${[...decl, ...attrs].map((x) => ` ${x}`).join('')}>${kids}</${name}>`
  }
  return write(buf)
}

// ---------------------------------------------------------------- Android deep links

const attrOf = (tag: string, name: string): string | undefined => new RegExp(`(?:android:)?${name}\\s*=\\s*"([^"]*)"`).exec(tag)?.[1]

/** Links that open the app from a web page or another app: custom schemes can be claimed by any app. */
export function deepLinks(xml: string, file = 'AndroidManifest.xml'): Finding[] {
  const out: Finding[] = []
  const custom = new Set<string>()
  const webNoVerify = new Set<string>()
  const verified = new Set<string>()
  for (const m of xml.matchAll(/<intent-filter\b([^>]*)>([\s\S]*?)<\/intent-filter>/g)) {
    const body = m[2]
    if (!/android\.intent\.category\.BROWSABLE/.test(body)) continue
    const auto = attrOf(m[1], 'autoVerify') === 'true'
    for (const d of body.matchAll(/<data\b([^>]*?)\/?>/g)) {
      const scheme = attrOf(d[1], 'scheme')
      if (!scheme) continue
      const host = attrOf(d[1], 'host')
      if (/^https?$/i.test(scheme)) (auto ? verified : webNoVerify).add(host ?? '(any host)')
      else custom.add(`${scheme}://${host ?? ''}`)
    }
  }
  if (custom.size)
    out.push(mk('MacSec manifest check', 'deeplink-custom', 'low', `Opens from custom links: ${[...custom].slice(0, 6).join(', ')}`, file, 'Any other app can claim the same custom scheme and receive the data in the link. They are not safe for sign-in codes, tokens or payments.', 'Use verified App Links (https with autoVerify) for anything sensitive, and treat every value in a link as untrusted.'))
  if (webNoVerify.size)
    out.push(mk('MacSec manifest check', 'deeplink-web', 'low', `Web links open the app without verification: ${[...webNoVerify].slice(0, 6).join(', ')}`, file, 'Without android:autoVerify and a digital asset links file, Android may ask the user which app to use, and another app can offer to handle these links.', 'Add android:autoVerify="true" and publish /.well-known/assetlinks.json on each host.'))
  if (verified.size) out.push(mk('MacSec manifest check', 'deeplink-ok', 'info', `Verified app links: ${[...verified].slice(0, 6).join(', ')}`, file, 'These links are tied to your website, which is the safer way.', 'Keep assetlinks.json up to date, and still treat every value in a link as untrusted.'))
  return out
}

// ---------------------------------------------------------------- iOS entitlements and privacy manifest

const plistKey = (xml: string, key: string): string | null => new RegExp(`<key>${key.replace(/\./g, '\\.')}</key>\\s*(<array>[\\s\\S]*?</array>|<[a-z]+\\s*/>|<[a-z]+>[^<]*</[a-z]+>)`).exec(xml)?.[1] ?? null
const strings = (frag: string | null): string[] => [...(frag ?? '').matchAll(/<string>([^<]*)<\/string>/g)].map((m) => m[1])

/** The entitlements in a signing profile or an .entitlements file. */
export function entitlementFindings(text: string, file: string): Finding[] {
  const out: Finding[] = []
  const groups = strings(plistKey(text, 'keychain-access-groups'))
  const wide = groups.filter((g) => /\.\*$|^\*$/.test(g))
  if (wide.some((g) => g === '*' || /\$\(AppIdentifierPrefix\)\*?$/.test(g) || /^[A-Z0-9]{10}\.\*$/.test(g)))
    out.push(mk('MacSec entitlements check', 'keychain-wide', 'low', 'The app can share Keychain items with every app of your team', file, `keychain-access-groups includes ${wide.join(', ')}. Any app signed by the same team can then read these Keychain items.`, 'Name the groups the app needs, and keep banking tokens in a group only this app uses.'))
  const domains = strings(plistKey(text, 'com.apple.developer.associated-domains'))
  if (domains.length) out.push(mk('MacSec entitlements check', 'domains', 'info', `Universal links and shared sign-in for ${domains.slice(0, 5).join(', ')}`, file, 'These are the websites that can open the app and share credentials with it. Each one needs a matching apple-app-site-association file.', 'Check each host serves a correct apple-app-site-association file over HTTPS, and treat link values as untrusted.'))
  if (/<key>com\.apple\.developer\.associated-domains<\/key>/.test(text) && domains.some((d) => /^webcredentials:/.test(d)))
    out.push(mk('MacSec entitlements check', 'webcred', 'info', 'The app shares saved passwords with a website', file, 'webcredentials lets iOS fill saved passwords between the app and the site.', 'Keep it only if you want that, and only for your own domains.'))
  if (plistKey(text, 'com.apple.security.application-groups'))
    out.push(mk('MacSec entitlements check', 'appgroup', 'info', `Shares files with other apps: ${strings(plistKey(text, 'com.apple.security.application-groups')).slice(0, 4).join(', ')}`, file, 'An app group is a folder shared by apps of your team (an extension, a widget).', 'Keep nothing sensitive in the shared folder, or encrypt it.'))
  return out
}

/** PrivacyInfo.xcprivacy: required by Apple, and it says what the app and its SDKs collect and track. */
export function privacyManifest(files: { path: string; text: string }[], hasApp: boolean): Finding[] {
  const out: Finding[] = []
  const own = files.find((f) => !/\.framework\/|\/Pods\//.test(f.path))
  if (!files.length || !own) {
    if (hasApp) out.push(mk('MacSec privacy check', 'missing', 'low', 'No privacy manifest (PrivacyInfo.xcprivacy) was found', undefined, 'Apple asks every app to list what data it collects, whether it tracks users, and why it uses certain system APIs. Apps without one can be rejected.', 'Add a PrivacyInfo.xcprivacy file to the app target.'))
    return out
  }
  const t = own.text
  if (/<key>NSPrivacyTracking<\/key>\s*<true\s*\/>/.test(t)) {
    const d = strings(plistKey(t, 'NSPrivacyTrackingDomains'))
    out.push(mk('MacSec privacy check', 'tracking', 'low', `The privacy manifest says the app tracks users${d.length ? `: ${d.slice(0, 4).join(', ')}` : ''}`, own.path, 'Tracking needs the user’s permission, and it is unusual in a banking app.', 'Remove the tracking, or check the permission prompt and your privacy labels match.'))
  }
  const types = (t.match(/<key>NSPrivacyCollectedDataType<\/key>/g) ?? []).length
  out.push(mk('MacSec privacy check', 'present', 'info', `Privacy manifest found: ${types} kinds of data declared`, own.path, 'Compare these with your privacy policy and the store’s privacy labels.', 'Keep the manifest in step with what the app and its SDKs really collect.'))
  return out
}

// ---------------------------------------------------------------- Third-party SDKs

interface Sdk {
  name: string
  kind: 'analytics' | 'ads' | 'crash' | 'payments' | 'social' | 'support' | 'other'
  /** Package prefix (Android, with slashes) or framework name (iOS). */
  android?: RegExp
  ios?: RegExp
}

export const SDKS: Sdk[] = [
  { name: 'Firebase Analytics', kind: 'analytics', android: /com\/google\/firebase\/analytics|com\/google\/android\/gms\/measurement/, ios: /FirebaseAnalytics/ },
  { name: 'Firebase Crashlytics', kind: 'crash', android: /com\/google\/firebase\/crashlytics|com\/crashlytics/, ios: /FirebaseCrashlytics|Crashlytics/ },
  { name: 'Google Mobile Ads', kind: 'ads', android: /com\/google\/android\/gms\/ads/, ios: /GoogleMobileAds|GoogleAppMeasurement/ },
  { name: 'Facebook SDK', kind: 'social', android: /com\/facebook\/(appevents|login|share|FacebookSdk)/, ios: /FBSDKCoreKit|FBSDKLoginKit|FacebookCore/ },
  { name: 'AppsFlyer', kind: 'ads', android: /com\/appsflyer/, ios: /AppsFlyerLib|AppsFlyerFramework/ },
  { name: 'Adjust', kind: 'ads', android: /com\/adjust\/sdk/, ios: /AdjustSdk|(^|\n)Adjust\.framework/ },
  { name: 'Branch', kind: 'ads', android: /io\/branch\/referral/, ios: /(^|\n)Branch\.framework/ },
  { name: 'Mixpanel', kind: 'analytics', android: /com\/mixpanel/, ios: /Mixpanel/ },
  { name: 'Amplitude', kind: 'analytics', android: /com\/amplitude/, ios: /Amplitude/ },
  { name: 'Segment', kind: 'analytics', android: /com\/segment\/analytics/, ios: /(^|\n)(Segment|Analytics)\.framework/ },
  { name: 'Sentry', kind: 'crash', android: /io\/sentry/, ios: /Sentry/ },
  { name: 'Bugsnag', kind: 'crash', android: /com\/bugsnag/, ios: /Bugsnag/ },
  { name: 'Stripe', kind: 'payments', android: /com\/stripe\//, ios: /Stripe(Core|Payments|UI)?\b/ },
  { name: 'Braintree', kind: 'payments', android: /com\/braintreepayments/, ios: /Braintree/ },
  { name: 'Adyen', kind: 'payments', android: /com\/adyen/, ios: /Adyen/ },
  { name: 'OneSignal', kind: 'other', android: /com\/onesignal/, ios: /OneSignal/ },
  { name: 'Intercom', kind: 'support', android: /io\/intercom/, ios: /Intercom/ },
  { name: 'Zendesk', kind: 'support', android: /com\/zendesk|zendesk\//, ios: /Zendesk/ },
  { name: 'Datadog', kind: 'analytics', android: /com\/datadog/, ios: /Datadog/ },
  { name: 'New Relic', kind: 'analytics', android: /com\/newrelic/, ios: /NewRelic/ },
  { name: 'Hotjar / session replay', kind: 'analytics', android: /com\/hotjar|com\/smartlook|com\/uxcam|io\/sessionreplay/i, ios: /Hotjar|Smartlook|UXCam/ },
  { name: 'Okta / Auth0', kind: 'other', android: /com\/(okta|auth0)/, ios: /OktaOidc|Auth0/ },
  { name: 'React Native', kind: 'other', android: /com\/facebook\/react\//, ios: /React\.framework|RCTBridge/ },
  { name: 'Flutter', kind: 'other', android: /io\/flutter/, ios: /Flutter\.framework/ },
  { name: 'Xamarin / .NET MAUI', kind: 'other', android: /mono\/android|xamarin/i, ios: /Xamarin|Mono\.framework/ }
]

/** SDKs named in the app's code (Android) or its framework and binary names (iOS). */
export function sdkFindings(text: string, platform: 'android' | 'ios', file?: string): Finding[] {
  const found = SDKS.filter((s) => (platform === 'android' ? s.android : s.ios)?.test(text))
  if (!found.length) return []
  const tracking = found.filter((s) => s.kind === 'ads' || s.kind === 'analytics' || s.kind === 'social')
  const list = found.map((s) => `${s.name} (${s.kind})`).join(', ')
  const out: Finding[] = [
    mk('MacSec SDK check', 'list', 'info', `Third-party SDKs in the app: ${found.length}`, file, `${list}. Each one runs inside the app with its permissions and can see what the app sees.`, 'Keep only what you need, update each one, and check what data it sends.')
  ]
  if (tracking.length)
    out.push(mk('MacSec SDK check', 'tracking', 'low', `Analytics, advertising or social SDKs in the app: ${tracking.map((s) => s.name).join(', ')}`, file, 'In a banking app these can send device identifiers and screen names to outside companies. Many regulators expect this to be disclosed, and some to be avoided on screens that show balances.', 'Remove what you do not need, turn off advertising IDs, keep them away from sensitive screens, and list them in your privacy policy.'))
  const replay = found.find((s) => /session replay/.test(s.name))
  if (replay) out.push(mk('MacSec SDK check', 'replay', 'medium', 'A session-replay SDK may record the screen', file, 'Screen recording tools can capture account numbers and balances unless every sensitive field is masked.', 'Remove it, or mask all sensitive views and test the recordings.', { cwe: 'CWE-359' }))
  return out
}

/** SDK names from the file names of an iOS app's Frameworks folder. */
export function frameworkNames(appDir: string): string {
  try {
    return readdirSync(join(appDir, 'Frameworks')).join('\n')
  } catch {
    return ''
  }
}

// ---------------------------------------------------------------- Addresses in the code

const BORING = /(^|\.)(w3\.org|apache\.org|schemas\.android\.com|xmlpull\.org|ietf\.org|mozilla\.org|example\.(com|org)|localhost|googleapis\.com\/auth|developer\.android\.com|developer\.apple\.com|apple\.com\/DTDs|github\.com|stackoverflow\.com|creativecommons\.org|android\.com|goo\.gl|xml\.org|java\.sun\.com|oracle\.com)$/i

/** The full web addresses written into the code (not only the servers). They are the app's API map. */
export function urlFindings(text: string): Finding[] {
  const seen = new Set<string>()
  for (const m of text.matchAll(/\bhttps?:\/\/[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?(?:\/[A-Za-z0-9._~!$&'()*+,;=:@%\/-]*)?/gi)) {
    let u: URL
    try {
      u = new URL(m[0])
    } catch {
      continue
    }
    if (BORING.test(u.hostname)) continue
    const clean = `${u.protocol}//${u.host}${u.pathname.length > 1 ? u.pathname.slice(0, 80) : ''}`
    seen.add(clean)
    if (seen.size >= 400) break
  }
  const urls = [...seen]
  if (!urls.length) return []
  const api = urls.filter((u) => /\/(api|v\d+|graphql|rest|oauth|auth|token|login)\b/i.test(u))
  return [
    mk('MacSec address check', 'urls', 'info', `Addresses written into the app: ${urls.length}${api.length ? ` (${api.length} look like API calls)` : ''}`, urls[0], `${(api.length ? api : urls).slice(0, 40).join('\n')}${(api.length ? api : urls).length > 40 ? '\n…' : ''}\n\nThese are the starting points for testing the app’s API. Look for test, staging and old versions: they are often weaker than the live API.`, 'Test each address with a test account. Remove addresses of servers that no longer exist.')
  ]
}

