import { describe, expect, it } from 'vitest'
import { appInArchive, baseApkIn, deepLinks, entitlementFindings, formatOf, privacyManifest, protoManifestToXml, sdkFindings, urlFindings } from '../src/main/mobiledeep'
import { sessionMasvs, controlsOf } from '../src/main/masvs'
import { checkAndroidManifest } from '../src/main/scanners/mobile'
import type { Finding } from '../src/shared/types'

// A tiny protobuf writer, enough to build what aapt2 puts in an .aab manifest.
const varint = (n: number): Buffer => {
  const out: number[] = []
  while (n > 127) {
    out.push((n & 127) | 128)
    n = Math.floor(n / 128)
  }
  out.push(n)
  return Buffer.from(out)
}
const field = (num: number, v: Buffer | number): Buffer => (typeof v === 'number' ? Buffer.concat([varint(num * 8), varint(v)]) : Buffer.concat([varint(num * 8 + 2), varint(v.length), v]))
const s = (num: number, text: string): Buffer => field(num, Buffer.from(text))
const attr = (ns: string, name: string, value: string): Buffer => field(4, Buffer.concat([s(1, ns), s(2, name), s(3, value)]))
const el = (name: string, parts: Buffer[]): Buffer => field(1, Buffer.concat([s(3, name), ...parts]))
const node = (name: string, attrs: Buffer[], kids: Buffer[] = [], decl: Buffer[] = []): Buffer => el(name, [...decl, ...attrs, ...kids.map((k) => field(5, k))])
const ANDROID = 'http://schemas.android.com/apk/res/android'

const f = (o: Partial<Finding>): Finding => ({ id: o.title ?? 'x', tool: 'MacSec', category: 'mobile', severity: 'medium', confidence: 'possible', title: 't', ...o }) as Finding

describe('app formats', () => {
  it('knows each format', () => {
    expect(formatOf('/a/app.aab', false)).toBe('aab')
    expect(formatOf('/a/app.apks', false)).toBe('apks')
    expect(formatOf('/a/My.xcarchive', true)).toBe('xcarchive')
    expect(formatOf('/a/My.xcarchive/', true)).toBe('xcarchive')
    expect(formatOf('/a/proj', true)).toBe('source')
    expect(formatOf('/a/proj.xcodeproj', true)).toBe('source')
  })
  it('finds the base apk in a set', () => {
    expect(baseApkIn(['splits/base-xxhdpi.apk', 'splits/base-master.apk'])).toBe('splits/base-master.apk')
    expect(baseApkIn(['standalones/standalone-arm64.apk'])).toBe('standalones/standalone-arm64.apk')
    expect(baseApkIn(['toc.pb'])).toBeNull()
  })
  it('finds no app in an empty archive folder', () => {
    expect(appInArchive('/nonexistent/x.xcarchive')).toBeNull()
  })
})

describe('.aab manifest', () => {
  const pb = node(
    'manifest',
    [attr('', 'package', 'bank.example')],
    [
      node('application', [attr(ANDROID, 'debuggable', 'true'), attr(ANDROID, 'allowBackup', 'true')], [
        node('activity', [attr(ANDROID, 'name', 'bank.example.Pay'), attr(ANDROID, 'exported', 'true')]),
        node('activity', [attr(ANDROID, 'name', 'bank.example.Link'), attr(ANDROID, 'exported', 'true')], [
          node('intent-filter', [], [
            node('category', [attr(ANDROID, 'name', 'android.intent.category.BROWSABLE')]),
            node('data', [attr(ANDROID, 'scheme', 'mybank'), attr(ANDROID, 'host', 'pay')])
          ])
        ])
      ])
    ],
    [field(1, Buffer.concat([s(1, 'android'), s(2, ANDROID)]))]
  )
  it('turns the protobuf back into XML the manifest check can read', () => {
    const xml = protoManifestToXml(pb)
    expect(xml).toContain('<manifest')
    expect(xml).toContain('android:debuggable="true"')
    const titles = checkAndroidManifest(xml).map((x) => x.title)
    expect(titles).toContain('The app is built as debuggable')
    expect(titles.some((t) => /Other apps can open the activity Pay/.test(t))).toBe(true)
  })
  it('finds deep links in it', () => {
    const d = deepLinks(protoManifestToXml(pb))
    expect(d.some((x) => /custom links: mybank:\/\/pay/.test(x.title))).toBe(true)
  })
  it('refuses nonsense without crashing', () => {
    expect(() => protoManifestToXml(Buffer.from([0xff, 0xff, 0xff]))).toThrow()
  })
})

describe('deep links', () => {
  it('flags web links without verification and keeps verified ones as info', () => {
    const xml = `<activity><intent-filter android:autoVerify="true"><category android:name="android.intent.category.BROWSABLE"/><data android:scheme="https" android:host="a.bank"/></intent-filter>
      <intent-filter><category android:name="android.intent.category.BROWSABLE"/><data android:scheme="https" android:host="b.bank"/></intent-filter></activity>`
    const d = deepLinks(xml)
    expect(d.find((x) => /without verification: b.bank/.test(x.title))?.severity).toBe('low')
    expect(d.find((x) => /Verified app links: a.bank/.test(x.title))?.severity).toBe('info')
  })
})

describe('iOS entitlements and privacy', () => {
  it('flags a wide keychain group and lists associated domains', () => {
    const t = '<key>keychain-access-groups</key><array><string>ABCDE12345.*</string></array><key>com.apple.developer.associated-domains</key><array><string>applinks:bank.example</string></array>'
    const out = entitlementFindings(t, 'x.entitlements')
    expect(out.some((x) => /share Keychain items/.test(x.title))).toBe(true)
    expect(out.some((x) => /applinks:bank.example/.test(x.title))).toBe(true)
    expect(entitlementFindings('<key>keychain-access-groups</key><array><string>ABCDE12345.bank.tokens</string></array>', 'x').length).toBe(0)
  })
  it('says when there is no privacy manifest, and reads tracking', () => {
    expect(privacyManifest([], true)[0].title).toMatch(/No privacy manifest/)
    expect(privacyManifest([], false)).toEqual([])
    const t = '<key>NSPrivacyTracking</key><true/><key>NSPrivacyTrackingDomains</key><array><string>t.example</string></array><key>NSPrivacyCollectedDataType</key><string>x</string>'
    const out = privacyManifest([{ path: 'PrivacyInfo.xcprivacy', text: t }], true)
    expect(out.some((x) => /tracks users: t.example/.test(x.title))).toBe(true)
    // An SDK's own manifest is not the app's.
    expect(privacyManifest([{ path: 'Frameworks/X.framework/PrivacyInfo.xcprivacy', text: t }], true)[0].title).toMatch(/No privacy manifest/)
  })
})

describe('SDKs and addresses', () => {
  it('names SDKs and warns about tracking ones', () => {
    const out = sdkFindings('Lcom/facebook/appevents/AppEventsLogger; Lio/sentry/Sentry; Lcom/stripe/android/Stripe;', 'android')
    expect(out[0].title).toBe('Third-party SDKs in the app: 3')
    expect(out.some((x) => /Analytics, advertising or social/.test(x.title) && /Facebook/.test(x.title))).toBe(true)
    expect(sdkFindings('nothing here', 'android')).toEqual([])
    expect(sdkFindings('FirebaseAnalytics.framework\nStripe.framework', 'ios')[0].title).toContain('2')
  })
  it('lists addresses and leaves out schema and documentation hosts', () => {
    const out = urlFindings('https://api.bank.example/v2/accounts http://schemas.android.com/apk/res/android https://staging.bank.example/api/login https://www.w3.org/2001/XMLSchema')
    expect(out[0].title).toBe('Addresses written into the app: 2 (2 look like API calls)')
    expect(out[0].description).toContain('https://api.bank.example/v2/accounts')
    expect(out[0].description).not.toContain('w3.org')
    expect(urlFindings('no addresses')).toEqual([])
  })
})

describe('MASVS checklist', () => {
  const steps = (ids: string[]) => ids.map((id) => ({ id, label: id, status: 'done' as const }))
  it('says needs work, clear, partly clear and needs a person, honestly', () => {
    const m = sessionMasvs({
      steps: steps(['settings', 'binary', 'deep', 'gitleaks']) as never,
      findings: [f({ title: 'No certificate pinning was found in the app', severity: 'low' }), f({ title: 'The app allows unencrypted HTTP', severity: 'medium' })]
    })
    const by = (id: string) => m.items.find((i) => i.id === id)!
    expect(by('MASVS-NETWORK-2').status).toBe('found')
    expect(by('MASVS-NETWORK-1').status).toBe('found')
    expect(by('MASVS-CRYPTO-1').status).toBe('clear')
    expect(by('MASVS-CRYPTO-2').status).toBe('partly')
    expect(by('MASVS-AUTH-1').status).toBe('not-tested')
    expect(by('MASVS-AUTH-1').manual).not.toBe('')
    expect(by('MASVS-CRYPTO-1').manual).toBe('')
  })
  it('does not call something clear when its step did not run', () => {
    const m = sessionMasvs({ steps: steps(['settings']) as never, findings: [] })
    expect(m.items.find((i) => i.id === 'MASVS-CRYPTO-1')!.status).toBe('not-tested')
    expect(m.items.find((i) => i.id === 'MASVS-CODE-1')!.status).toBe('clear')
  })
  it('ignores findings marked as not a problem or false', () => {
    const m = sessionMasvs({ steps: steps(['deep']) as never, findings: [f({ title: 'The code names MD5 or SHA-1', verdict: 'false-positive' }), f({ title: 'The code names MD5 or SHA-1', triage: 'not-a-problem' })] })
    expect(m.items.find((i) => i.id === 'MASVS-CRYPTO-1')!.status).toBe('clear')
  })
  it('keeps keys and packages under their controls, and an info "No ..." gap counts', () => {
    expect(controlsOf(f({ title: 'Generic API Key', category: 'secret' }))).toContain('MASVS-CRYPTO-2')
    expect(controlsOf(f({ title: 'lodash 4.17.0', category: 'dependency' }))).toContain('MASVS-CODE-3')
    const m = sessionMasvs({ steps: steps(['deep']) as never, findings: [f({ title: 'No root check was found', severity: 'info' })] })
    expect(m.items.find((i) => i.id === 'MASVS-RESILIENCE-1')!.status).toBe('found')
  })
})
