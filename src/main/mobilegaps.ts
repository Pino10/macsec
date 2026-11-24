/**
 * The mobile checks that are about how the app is put together rather than one file:
 * task hijacking, backup, pinning, resilience, WebView, screenshot and Keychain classes.
 * These are static indicators; the report says so, and the dynamic test confirms them.
 */
import type { Finding, Severity } from '../shared/types'
import { fid } from './scanners/parse'

const mk = (tool: string, key: string, severity: Severity, title: string, file: string | undefined, description: string, fix: string): Finding => ({
  id: fid(tool, key, file),
  tool,
  category: 'mobile',
  severity,
  confidence: 'possible',
  title,
  file,
  description,
  fix
})

const attr = (tag: string, name: string): string | null => new RegExp(`android:${name}="([^"]*)"`).exec(tag)?.[1] ?? null

/** Android task hijacking: singleTask without a task affinity on an exported activity (Android 8-9). */
export function androidManifestGaps(xml: string, file: string): Finding[] {
  const out: Finding[] = []
  for (const m of xml.matchAll(/<activity\b[^>]*>/g)) {
    const tag = m[0]
    const name = attr(tag, 'name') ?? ''
    if (attr(tag, 'launchMode') !== '2') continue
    if (attr(tag, 'taskAffinity')) continue
    if (attr(tag, 'exported') !== 'true') continue
    out.push(
      mk('MacSec platform check', 'task-hijack', 'low', 'Task-hijacking configuration in an exported activity', file,
        `${name} is exported, singleTask and has no taskAffinity. On Android 8.0-9 a malicious app can claim the task and show its own screen inside the banking task (StrandHogg-style). Android 10 and later block it.`,
        'Give the activity an explicit unique taskAffinity and keep singleTask only if it is needed; otherwise use the platform defaults.')
    )
  }
  const app = /<application\b[^>]*>/.exec(xml)?.[0] ?? ''
  if (attr(app, 'allowBackup') === 'true' && !attr(app, 'dataExtractionRules') && !attr(app, 'fullBackupContent'))
    out.push(
      mk('MacSec platform check', 'backup', 'low', 'Android backup is on without rules', file,
        'allowBackup is true and no dataExtractionRules or fullBackupContent file is set. Android may copy app data, including tokens stored in shared preferences, into a cloud backup.',
        'Set allowBackup="false", or add explicit backup rules that exclude tokens and account data.')
    )
  return out
}

/** Pinning evidence: a pin-set in the network config, a known pinning API, or a pin hash. */
export function pinningGap(text: string, platform: 'android' | 'ios', file: string): Finding[] {
  if (/<pin-set|CertificatePinner|sha256\/[A-Za-z0-9+/=]{20,}|TrustKit/i.test(text)) return []
  return [
    mk('MacSec network check', 'pinning', 'info', 'No certificate pinning evidence', file,
      platform === 'android'
        ? 'No pin-set in the network security configuration and no pinning API or pin hash in the code. A user-installed CA can intercept traffic unless the server or a native library pins.'
        : 'No pin hash or pinning configuration was found. The app may pin natively; verify with a proxy and a user CA.',
      'Confirm pinning at runtime. If it is absent, add it with at least one backup pin and a rotation plan.')
  ]
}

/** Root, jailbreak, debugger and hooking checks: present is a positive, absent is a gap for banking. */
export function resilienceGap(text: string, platform: 'android' | 'ios', file: string): Finding[] {
  const found = /Frida|frida|Xposed|xposed|isRooted|RootBeer|jailbreak|Jailbreak|Cydia|isEmulator|isDebugged|tamper/i.test(text)
  if (found) return []
  return [
    mk('MacSec resilience check', 'resilience', 'low', 'No root, jailbreak or hooking checks found', file,
      `The ${platform === 'android' ? 'DEX/Hermes' : 'binary/Hermes'} text has no sign of root, jailbreak, debugger or Frida detection. A banking app should at least notice a compromised device and decide what to do.`,
      'Add root/jailbreak, debugger and hooking detection, and test that it reports rather than only hiding. Treat it as a speed bump, not a hard control.')
  ]
}

/** WebView settings: present is a reason to verify the loaded hosts and the bridge, not a vulnerability by itself. */
export function webviewGap(text: string, platform: 'android' | 'ios', file: string): Finding[] {
  const android = /addJavascriptInterface|setJavaScriptEnabled|setAllowFileAccess|WebView/i.test(text)
  const ios = /WKWebView|UIWebView|evaluateJavaScript|JSBridge/i.test(text)
  if (platform === 'android' ? !android : !ios) return []
  return [
    mk('MacSec WebView check', 'webview', 'info', 'The app uses a WebView with script or file access', file,
      'A WebView with JavaScript, a bridge or file access can be dangerous if it loads user-controlled or untrusted content.',
      'Load only allow-listed HTTPS hosts, disable file access, expose the smallest possible bridge, and test a malicious page if the app opens user links.')
  ]
}

/** Android screenshot protection is an inlined constant, so this is an indicator, not proof. */
export function screenshotGap(platform: 'android' | 'ios', text: string, iosFlag: boolean, file: string): Finding[] {
  if (platform === 'ios' ? iosFlag : /FLAG_SECURE/.test(text)) return []
  return [
    mk('MacSec privacy check', 'screenshot', 'info', 'No screenshot-protection evidence', file,
      platform === 'android'
        ? 'No FLAG_SECURE reference was found. FLAG_SECURE is an inlined constant, so this is an indicator: verify on a device that balances and statements cannot be captured.'
        : 'No ScreenshotBlockEnabled flag was found in Info.plist. Verify the app switcher snapshot and screen recording on a device.',
      'Verify screenshots, screen recording and the app-switcher snapshot; add protection where balances, statements and cards are shown.')
  ]
}

/** iOS Keychain accessibility classes that are weaker than ThisDeviceOnly. */
export function keychainClasses(text: string, file: string): Finding[] {
  const out: Finding[] = []
  if (/kSecAttrAccessibleAlways(?!ThisDeviceOnly)/.test(text))
    out.push(
      mk('MacSec storage check', 'keychain-always', 'medium', 'A Keychain item can be read while the device is locked', file,
        'kSecAttrAccessibleAlways (without ThisDeviceOnly) keeps an item available even when the phone is locked, and can migrate in a backup.',
        'Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly or an access control with biometry for tokens, PINs and card data.')
    )
  else if (/kSecAttrAccessibleWhenUnlocked(?!ThisDeviceOnly)/.test(text))
    out.push(
      mk('MacSec storage check', 'keychain-when-unlocked', 'low', 'A Keychain item is not limited to this device', file,
        'kSecAttrAccessibleWhenUnlocked without ThisDeviceOnly can be restored to another device from a backup.',
        'Use the ThisDeviceOnly variant for banking tokens unless a backup is explicitly required.')
    )
  return out
}
