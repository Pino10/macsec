/**
 * OWASP MASVS 2.0 as a checklist for a mobile check: what was found, what was looked at and is clear,
 * and what only a person can test. The automatic checks never claim more than they did:
 *   - "Needs work"    a finding belongs to the control.
 *   - "Clear"         the checks that can see this control ran and found nothing.
 *   - "Partly clear"  the same, but a person still has to test part of it (named in the list).
 *   - "Not tested"    no check can see it, or the step that could has not run. It says how to test it.
 * Nothing here sends a request: it reads the findings and the steps of a session.
 */
import type { Finding, MasvsInfo, MasvsItem, SessionDetail } from '../shared/types'

interface Control {
  id: string
  group: string
  name: string
  about: string
  /** Does a finding belong to this control? Read from its title, tool and details. */
  match?: RegExp
  /** Steps whose run lets this control read "clear". */
  steps: string[]
  /** How much of the control the automatic checks can see. */
  auto: 'full' | 'partial' | 'none'
  /** What a person tests by hand (shown when the control is not fully automatic). */
  manual: string
}

const GROUPS: Record<string, string> = {
  STORAGE: 'Data storage',
  CRYPTO: 'Cryptography',
  AUTH: 'Authentication',
  NETWORK: 'Network',
  PLATFORM: 'Platform use',
  CODE: 'Code quality',
  RESILIENCE: 'Resilience',
  PRIVACY: 'Privacy'
}

export const CONTROLS: Control[] = [
  { id: 'MASVS-STORAGE-1', group: 'STORAGE', name: 'Sensitive data is stored securely', about: 'Tokens, card and account data live in the Keychain or Keystore, not in plain files, preferences or databases.', match: /world[- ]readable|world[- ]writ|keychain|kSecAttrAccessible|shared preferences|sqlite|external storage|plain (text|file)/i, steps: ['deep', 'mobsfscan', 'settings'], auto: 'partial', manual: 'Run the app on an emulator, sign in, then look in its files, databases and preferences for tokens, card numbers and personal data.' },
  { id: 'MASVS-STORAGE-2', group: 'STORAGE', name: 'Sensitive data is not leaked', about: 'No sensitive data in logs, backups, the clipboard, screenshots or the app switcher.', match: /backup|log(s|ging)?\b|clipboard|screenshot|Documents folder is visible|file sharing/i, steps: ['settings', 'mobsfscan'], auto: 'partial', manual: 'Watch the device log while using the app, copy a card number and paste it elsewhere, and check the app switcher shows no balances.' },
  { id: 'MASVS-CRYPTO-1', group: 'CRYPTO', name: 'Strong, current cryptography', about: 'No weak algorithms (MD5, SHA-1, DES, ECB) for anything that protects data.', match: /\bECB\b|\bMD5\b|SHA-?1\b|\bDES\b|\bRC4\b|weak (crypto|hash|cipher)|insecure random|constant iv|cryptograph/i, steps: ['deep', 'mobsfscan'], auto: 'full', manual: '' },
  { id: 'MASVS-CRYPTO-2', group: 'CRYPTO', name: 'Keys are managed properly', about: 'No keys, passwords or secrets inside the app, and keys are kept in the Keystore or Keychain.', match: /secret|api key|private key|password|token|credential|hard-?coded|gitleaks|key in/i, steps: ['gitleaks', 'mobsfscan'], auto: 'partial', manual: 'Check how the app creates and stores its own keys at run time (Keystore or Keychain, never exportable).' },
  { id: 'MASVS-AUTH-1', group: 'AUTH', name: 'Secure authentication and authorization', about: 'Sign-in, sessions and tokens are handled by the server, with expiry and checks on every request.', steps: [], auto: 'none', manual: 'With a test account: log in, log out, reuse an old token, change an account number in a request, and try the same call as another user.' },
  { id: 'MASVS-AUTH-2', group: 'AUTH', name: 'Secure local authentication', about: 'Biometrics and PIN are tied to a key in the Keystore or Keychain, not just a yes or no in the app.', steps: [], auto: 'none', manual: 'Try to skip the biometric prompt (on an emulator), repeat wrong PINs, and check what happens after new fingerprints are added.' },
  { id: 'MASVS-AUTH-3', group: 'AUTH', name: 'Extra checks for sensitive actions', about: 'Payments and changes to the account ask again (an OTP, PIN or biometric).', steps: [], auto: 'none', manual: 'Make a payment and change a phone number: each should ask for a second proof, and the server should insist on it.' },
  { id: 'MASVS-NETWORK-1', group: 'NETWORK', name: 'Traffic is encrypted and secure', about: 'Everything uses TLS with current settings. No plain HTTP.', match: /cleartext|plain http|unencrypted|App Transport Security|\bATS\b|http addresses|outdated TLS|TLSv1|SSLv3|insecure http|trust(s)? certificates the phone owner/i, steps: ['settings', 'deep', 'mobsfscan'], auto: 'full', manual: '' },
  { id: 'MASVS-NETWORK-2', group: 'NETWORK', name: 'The server’s identity is checked (pinning)', about: 'The app only talks to your servers, even if an attacker’s certificate is installed on the phone.', match: /pinning|trust ?all|TrustAll|hostname verif|allow[- ]invalid|invalid certificates|user-ca|certificate validation/i, steps: ['deep', 'settings', 'mobsfscan'], auto: 'partial', manual: 'Route the app through a proxy with its own certificate (Burp or mitmproxy on an emulator): it should refuse to connect.' },
  { id: 'MASVS-PLATFORM-1', group: 'PLATFORM', name: 'Other apps and links can’t misuse it', about: 'Exported components, deep links, URL schemes and content providers are locked down.', match: /other apps can open|exported|deep link|url scheme|opens links with|universal link|content provider|intent|custom scheme|permission is not required/i, steps: ['settings', 'mobsfscan'], auto: 'partial', manual: 'Send crafted deep links and intents to every exported screen, with the app signed out, and check nothing sensitive opens.' },
  { id: 'MASVS-PLATFORM-2', group: 'PLATFORM', name: 'Web views are safe', about: 'WebViews load only your own content and cannot reach files or the app’s code.', match: /webview|UIWebView|javascript interface|JavaScript can call/i, steps: ['deep', 'mobsfscan'], auto: 'full', manual: '' },
  { id: 'MASVS-PLATFORM-3', group: 'PLATFORM', name: 'The screen is protected', about: 'Sensitive screens block screenshots, recording and overlays.', match: /screenshot|overlay|FLAG_SECURE|tapjack/i, steps: ['mobsfscan'], auto: 'none', manual: 'Open the card and account screens, take a screenshot, and check the app switcher thumbnail is hidden.' },
  { id: 'MASVS-CODE-1', group: 'CODE', name: 'Runs on a supported system', about: 'The app asks for a recent Android or iOS version, so old, unfixed systems are left out.', match: /old android|minimum API|targets an old|very old Android|minimum (os|ios)/i, steps: ['settings'], auto: 'full', manual: '' },
  { id: 'MASVS-CODE-2', group: 'CODE', name: 'Old versions can be forced to update', about: 'You can make users move to a fixed version.', steps: [], auto: 'none', manual: 'Check that the server can refuse an old app version and that the app then shows an update screen.' },
  { id: 'MASVS-CODE-3', group: 'CODE', name: 'Third-party code is up to date', about: 'No libraries with known flaws.', match: /vulnerable|CVE-|deprecated|known flaws|outdated (library|sdk)/i, steps: ['deps', 'deep'], auto: 'partial', manual: 'Check the SDK list against your own inventory and the vendors’ security notices. A built app hides many versions.' },
  { id: 'MASVS-CODE-4', group: 'CODE', name: 'Input is validated', about: 'Data from links, files, web views and servers is checked before use.', match: /injection|\bsql\b|path traversal|untrusted input|deserial|zip slip|command execution/i, steps: ['mobsfscan'], auto: 'partial', manual: 'Send unexpected data into every field, link and file the app accepts, and watch for crashes and odd behaviour.' },
  { id: 'MASVS-RESILIENCE-1', group: 'RESILIENCE', name: 'Detects a rooted or jailbroken phone', about: 'The app notices a modified system and limits what it does.', match: /rooted|jailbroken|root (detection|check)|jailbreak/i, steps: ['deep'], auto: 'partial', manual: 'Run it on a rooted emulator and check it reacts (warning, limits or sign-out). A check that exists is not a check that works.' },
  { id: 'MASVS-RESILIENCE-2', group: 'RESILIENCE', name: 'Detects tampering', about: 'The release is correctly signed, not debuggable, and checks its own integrity.', match: /debuggable|test-only|get-task-allow|signed with|debug certificate|signing|v1 scheme|\bPIE\b|stack protection|RELRO|executable stack|\bARC\b|integrity|tamper/i, steps: ['settings', 'binary', 'deep'], auto: 'partial', manual: 'Repackage the app with a change and check it refuses to run or to talk to the server.' },
  { id: 'MASVS-RESILIENCE-3', group: 'RESILIENCE', name: 'Hard to read (obfuscation)', about: 'Code is obfuscated and symbols stripped so reverse engineering takes real effort.', match: /obfuscat|symbols|source map|proguard|\br8\b|stripped/i, steps: [], auto: 'none', manual: 'Open the app in jadx or Ghidra: class and method names should not read like your source code.' },
  { id: 'MASVS-RESILIENCE-4', group: 'RESILIENCE', name: 'Detects debugging and hooking', about: 'The app notices debuggers and tools like Frida.', match: /debugger|frida|hook|instrumentation/i, steps: ['deep', 'live'], auto: 'partial', manual: 'Attach Frida on an emulator and try to hook the login and payment code: the app should notice.' },
  { id: 'MASVS-PRIVACY-1', group: 'PRIVACY', name: 'Asks for as little data as needed', about: 'Few permissions, and only for features the user can see.', match: /sensitive permissions?|permission|privacy manifest|usage description|tracking|advertising|analytics sdk/i, steps: ['settings', 'deep'], auto: 'partial', manual: 'Compare each permission and SDK with a feature the user can see. Remove what is not needed.' },
  { id: 'MASVS-PRIVACY-2', group: 'PRIVACY', name: 'Users can’t be tracked across apps', about: 'No device or advertising IDs shared more than needed.', steps: [], auto: 'none', manual: 'Check the traffic for device IDs and advertising IDs sent to third parties.' },
  { id: 'MASVS-PRIVACY-3', group: 'PRIVACY', name: 'Clear about what is collected', about: 'A privacy policy, privacy labels and an accurate privacy manifest.', match: /privacy manifest/i, steps: ['settings'], auto: 'none', manual: 'Compare your privacy policy and store privacy labels with what the app really collects.' },
  { id: 'MASVS-PRIVACY-4', group: 'PRIVACY', name: 'Users stay in control', about: 'Users can see, export and delete their data and withdraw consent.', steps: [], auto: 'none', manual: 'Try to delete an account and withdraw consent in the app, and check the data really goes.' }
]

const GROUP_OF = /\b(storage|crypto|auth|network|platform|code|resilience|privacy)-\d/i

const GAP = /^(no |the app does not|missing)/i

function textOf(f: Finding): string {
  return `${f.title} ${f.tool} ${f.category ?? ''} ${f.description ?? ''}`
}

/** Which controls a finding belongs to. mobsfscan names its MASVS group, so a finding it gives is never lost. */
export function controlsOf(f: Finding): string[] {
  const title = `${f.title} ${f.tool}`
  const hit = CONTROLS.filter((c) => c.match?.test(title)).map((c) => c.id)
  if (f.category === 'secret' && !hit.includes('MASVS-CRYPTO-2')) hit.push('MASVS-CRYPTO-2')
  if (f.category === 'dependency' && !hit.includes('MASVS-CODE-3')) hit.push('MASVS-CODE-3')
  if (!hit.length && f.tool === 'mobsfscan') {
    const g = GROUP_OF.exec(f.description ?? '')?.[1]?.toUpperCase()
    const first = g ? CONTROLS.find((c) => c.group === g) : undefined
    if (first) hit.push(first.id)
  }
  return hit
}

/** The checklist for one mobile check. */
export function sessionMasvs(s: Pick<SessionDetail, 'findings' | 'steps'>): MasvsInfo {
  const done = new Set(s.steps.filter((x) => x.status === 'done').map((x) => x.id))
  const findings = s.findings.filter((f) => f.verdict !== 'false-positive' && f.triage !== 'not-a-problem')
  const byControl = new Map<string, Finding[]>()
  for (const f of findings) for (const id of controlsOf(f)) byControl.set(id, [...(byControl.get(id) ?? []), f])
  const items: MasvsItem[] = CONTROLS.map((c) => {
    const mine = byControl.get(c.id) ?? []
    const problems = mine.filter((f) => (f.severity !== 'info' || GAP.test(f.title)) && f.severity !== undefined)
    const ran = c.steps.some((st) => done.has(st))
    const status: MasvsItem['status'] = problems.length ? 'found' : c.auto === 'full' && ran ? 'clear' : c.auto === 'partial' && ran ? 'partly' : 'not-tested'
    return {
      id: c.id,
      group: GROUPS[c.group],
      name: c.name,
      about: c.about,
      status,
      findings: problems.map((f) => ({ id: f.id, title: f.title, severity: f.severity })),
      manual: status === 'clear' ? '' : c.manual
    }
  })
  const count = (st: MasvsItem['status']): number => items.filter((i) => i.status === st).length
  return { items, found: count('found'), clear: count('clear'), partly: count('partly'), notTested: count('not-tested') }
}
