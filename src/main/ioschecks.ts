/**
 * iOS checks that the signing profile alone cannot answer: what the signed app actually requests,
 * how the build is distributed, what Info.plist exposes, and what the JavaScript bundle left in.
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

const mask = (s: string): string => `${s.slice(0, 4)}…${s.slice(-4)}`
const str = (xml: string, key: string): string => new RegExp(`<key>${key}</key>\\s*<string>([^<]*)</string>`).exec(xml)?.[1] ?? ''
const arr = (xml: string, key: string): string[] => {
  const frag = new RegExp(`<key>${key}</key>\\s*<array>([\\s\\S]*?)</array>`).exec(xml)?.[1] ?? ''
  return [...frag.matchAll(/<string>([^<]*)<\/string>/g)].map((m) => m[1])
}
const yes = (xml: string, key: string): boolean => new RegExp(`<key>${key}</key>\\s*<true\\s*/>`).test(xml)

/** The distribution profile: ad hoc, development, enterprise or App Store, and for how long. */
export function provisioningFindings(xml: string, file: string): Finding[] {
  const out: Finding[] = []
  const name = str(xml, 'Name')
  const team = str(xml, 'TeamName')
  const teamId = arr(xml, 'TeamIdentifier')[0] ?? ''
  const devices = arr(xml, 'ProvisionedDevices')
  const adhoc = /ad hoc/i.test(name) || devices.length > 0
  const dev = /development/i.test(name)
  if (adhoc)
    out.push(
      mk('MacSec signing check', 'adhoc', 'medium', `Ad hoc build for ${devices.length} device${devices.length === 1 ? '' : 's'}`, file,
        `Profile "${name}", team ${team || 'unknown'} (${teamId || 'no team id'}), ${devices.length} provisioned device${devices.length === 1 ? '' : 's'}. An ad hoc profile is for named test devices, expires, and is not an App Store or organisation distribution.`,
        'If this build is for customers or staff, re-sign it with the bank’s organisation Apple Developer account and distribute through the approved App Store, TestFlight or managed channel. Keep ad hoc for test devices only.')
    )
  if (dev)
    out.push(
      mk('MacSec signing check', 'development', 'high', 'Development build (not for release)', file,
        `Profile "${name}" is a development profile. It is installable with debugging tools and is not a release signature.`,
        'Archive a release build with a distribution profile.')
    )
  const exp = str(xml, 'ExpirationDate')
  if (exp) {
    const days = Math.round((new Date(exp).getTime() - Date.now()) / 86400_000)
    if (Number.isFinite(days) && days < 60 && days >= 0)
      out.push(mk('MacSec signing check', 'expiry', 'low', `The signing profile expires in ${days} day${days === 1 ? '' : 's'}`, file, `Profile expiry: ${exp}. An expired profile stops the app installing or updating.`, 'Regenerate the profile and rebuild before it expires.'))
  }
  if (team && !/bank|systems|technologies|limited|ltd|plc|inc|gmbh|corp|company/i.test(team))
    out.push(mk('MacSec signing check', 'team', 'info', `The signing team is named "${team}"`, file, `Team ${team} (${teamId}). Confirm this is the bank’s organisation account and not an individual or contractor account.`, 'If the bank distributes the app, it should be signed by the bank’s organisation team; verify the Team ID against the release record.'))
  return out
}

/** The entitlements in the signed app, not merely what the profile permits. */
export function signedEntitlementFindings(xml: string, file: string): Finding[] {
  const out: Finding[] = []
  const groups = arr(xml, 'keychain-access-groups')
  const wide = groups.filter((g) => /\.\*$|^\*$/.test(g))
  if (wide.length)
    out.push(
      mk('MacSec signing check', 'keychain-wide', 'low', 'The signed app can share Keychain items with every app of its team', file,
        `The signed app’s keychain-access-groups includes ${wide.join(', ')}. Any app signed by the same team can read Keychain items stored under that wildcard group.`,
        'Remove the wildcard. Use only explicit groups the app needs, and keep banking tokens in the app-specific group.')
    )
  if (yes(xml, 'get-task-allow'))
    out.push(mk('MacSec signing check', 'task-allow', 'high', 'The signed app allows a debugger (get-task-allow)', file, 'This build is signed for development: a debugger can attach, read memory and change behaviour.', 'Archive a release build with a distribution profile.'))
  return out
}

/** Info.plist details that are not ATS or file sharing: keys, permissions, screenshot claims. */
export function infoPlistExtra(xml: string, file: string): Finding[] {
  const out: Finding[] = []
  const gms = /<key>GMSApiKey<\/key>\s*<string>(AIza[0-9A-Za-z_-]{35})<\/string>/.exec(xml)?.[1]
  if (gms)
    out.push(mk('MacSec Info.plist check', 'gms-key', 'medium', 'A Google Maps API key is in Info.plist', file, `GMSApiKey is ${mask(gms)}. Anyone with the IPA can read it. If it is not restricted to this bundle ID and the Maps APIs, it can be used at your expense.`, 'Restrict the key to the app’s bundle ID and only the APIs it needs, rotate it if it was ever unrestricted, and keep server-side secrets out of the app.'))
  if (str(xml, 'NSLocationAlwaysUsageDescription') || str(xml, 'NSLocationAlwaysAndWhenInUseUsageDescription'))
    out.push(mk('MacSec Info.plist check', 'always-location', 'low', 'The app asks for always-on location', file, 'An always-location permission is much stronger than when-in-use. The purpose text here only mentions showing nearby ATMs and branches.', 'Request when-in-use location only, unless a background feature genuinely needs always.'))
  const sensitive = [
    str(xml, 'NSContactsUsageDescription') ? 'contacts' : '',
    str(xml, 'NSMicrophoneUsageDescription') ? 'microphone' : '',
    str(xml, 'NSPhotoLibraryUsageDescription') ? 'photo library' : ''
  ].filter(Boolean)
  if (sensitive.length)
    out.push(mk('MacSec Info.plist check', 'sensitive', 'info', `Sensitive permissions requested: ${sensitive.join(', ')}`, file, 'Each of these shows a system prompt and gives the app access to personal data. A banking app should justify each one in its privacy policy.', 'Remove the ones no feature needs, request them at the point of use, and explain them in the privacy policy.'))
  if (!yes(xml, 'ScreenshotBlockEnabled'))
    out.push(mk('MacSec Info.plist check', 'screenshot', 'info', 'No screenshot-block flag found', file, 'The app does not declare ScreenshotBlockEnabled. Screenshot blocking on iOS needs a view overlay or a secure field; verify on a device that sensitive screens cannot be captured.', 'Verify screenshots, screen recording and the app switcher snapshot; if they show balances or statements, add protection.'))
  return out
}

const BORING = /(^|\.)(w3\.org|reactnavigation\.org|reactjs\.org|momentjs\.com|swmansion\.com|callstack\.github\.io|github\.com|redux\.js\.org|npms\.io|fb\.me|bit\.ly|googleapis\.com|localhost)$/i

/** Facts the JavaScript bundle gives away: test servers, keys, and whether pinning is evidenced. */
export function bundleFindings(text: string, file: string): Finding[] {
  const out: Finding[] = []
  const urls = [...new Set((text.match(/https?:\/\/[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?(?:\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?/gi) ?? []).map((u) => u.replace(/[),;]+$/, '')))]
  const hosts = new Map<string, string>()
  for (const u of urls) {
    try {
      const h = new URL(u).host
      if (BORING.test(h) || BORING.test(h.replace(/^www\./, ''))) continue
      if (/test|uat|staging|sandbox|demo|preprod|dev\.|localhost|127\.0\.0\.1/i.test(h)) hosts.set(h, u.slice(0, 120))
    } catch {
      // Not a URL.
    }
  }
  if (hosts.size)
    out.push(
      mk('MacSec bundle check', 'test-hosts', 'medium', `Test or demo servers are written into the app: ${[...hosts.keys()].slice(0, 5).join(', ')}`, file,
        `The JavaScript bundle contains ${hosts.size} non-production host${hosts.size === 1 ? '' : 's'}:\n${[...hosts.values()].slice(0, 10).join('\n')}\n\nTest estates are often less protected and may hold realistic data.`, 'Build per environment, remove test and demo hosts from release, and make test systems unreachable from production.')
    )
  const keys = new Set<string>()
  for (const m of text.matchAll(/(AIza[0-9A-Za-z_-]{35})/g)) keys.add(m[1])
  for (const m of text.matchAll(/(AKIA[0-9A-Z]{16})/g)) keys.add(m[1])
  for (const m of text.matchAll(/(sk_live_[0-9A-Za-z]{20,})/g)) keys.add(m[1])
  if (keys.size)
    out.push(mk('MacSec bundle check', 'keys', 'medium', 'API keys are written into the JavaScript bundle', file, `Found ${keys.size} key-like string${keys.size === 1 ? '' : 's'} (${[...keys].slice(0, 3).map(mask).join(', ')}). Anyone with the app can read them.`, 'Restrict or rotate each key, and move server-side secrets to the backend.'))
  if (/sslPinning/i.test(text) && !/sha256\/[A-Za-z0-9+/=]{20,}/i.test(text))
    out.push(mk('MacSec bundle check', 'pinning', 'info', 'Pinning is mentioned but no pin hash is present', file, 'The bundle mentions sslPinning, but no sha256/ pin was found. Pinning may still be native; verify with a proxy.', 'Confirm pinning at runtime; if absent, add it with a rotation plan.'))
  return out
}

/** Build a single finding from codesign's authority lines, independent of the profile. */
export function signingAuthorityFindings(dv: string, file: string): Finding[] {
  const authority = [...dv.matchAll(/^Authority=(.+)$/gm)].map((m) => m[1].trim())
  const team = /^TeamIdentifier=(.+)$/m.exec(dv)?.[1]?.trim() ?? ''
  if (!authority.length) return []
  const first = authority[0]
  const individual = /Apple Distribution:\s*[^()]+\(\s*[A-Z0-9]{10}\s*\)/i.test(first) && !/bank|systems|technologies|limited|ltd|plc/i.test(first)
  return [
    mk('MacSec signing check', 'authority', 'info', `Signed by ${first}`, file, `Signing authority chain: ${authority.join(' → ')}. Team ${team || 'unknown'}.`, 'Confirm the signing authority is the bank’s organisation account and matches the distributed build. If this is a re-signed copy, treat it as untrusted.')
  ]
}
