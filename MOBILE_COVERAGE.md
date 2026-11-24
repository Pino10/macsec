# Mobile coverage: what MacSec checks statically

This is the checklist the mobile scanner now works to, mapped to the OWASP Mobile Application
Security Verification Standard (MASVS). Static checks are the ones that can be read from an
artefact; the last column is what still needs a device, a proxy or a test account.

Sources used to shape it:

- [OWASP MASVS: the eight control groups](https://safeguard.sh/resources/blog/masvs-eight-control-groups-explained)
- [A pre-release security checklist for mobile apps](https://safeguard.sh/resources/blog/mobile-app-security-pre-release-checklist)
- [OWASP MASTG](https://mas.owasp.org/MASTG/)
- [Android task hijacking (StrandHogg)](https://hacktricks.wiki/jp/mobile-pentesting/android-app-pentesting/android-task-hijacking.html)
- [Bank of Ghana CISD exposure draft](https://www.bog.gov.gh/wp-content/uploads/2025/09/CISD-Exposure-Draft.pdf)
- [CISD 2026 and Ghana's financial sector](https://www.group-ib.com/resources/research-hub/cisd-2026-ghana-compliance/)

| MASVS group | MacSec static checks | Still needs a live test |
| --- | --- | --- |
| **STORAGE** | Android backup flag and backup rules; iOS file sharing and document opening; iOS Keychain accessibility classes; signed Keychain entitlements (profile vs app). | Files written by the app; Keychain dump; screenshot of local data; backup extraction. |
| **CRYPTO** | Hard-coded keys/tokens in DEX, Hermes, Info.plist and strings; weak algorithms named in the code; iOS binary encryption (`cryptid`); Google/AWS/Stripe key patterns. | Actual crypto misuse, IV reuse, key derivation, RNG quality, key storage. |
| **AUTH** | Nothing reliable statically; the app's authentication is a backend concern. | Session expiry, logout revocation, biometric bypass, MFA downgrade, account enumeration, rate limiting. |
| **NETWORK** | Android network security config (cleartext, pin-set); iOS ATS; pinning evidence (`sha256/`, TrustKit, CertificatePinner); test/UAT/demo/localhost hosts in the bundle. | MITM with a user CA; pinning bypass; TLS versions; certificate validation; API authorization. |
| **PLATFORM** | Android exported components, task hijacking (`singleTask` without `taskAffinity`), deep links; iOS URL schemes, associated domains, WebView symbols, screenshot flag; **WebView script/file access**; permissions and purpose strings. | Intent redirection, task hijack with a malicious app, WebView with a hostile page, screenshot/screen recording, app-switcher snapshot. |
| **CODE** | Debuggable/`get-task-allow`; Android v2/v3 signing and iOS profile/authority/team/devices/expiry; ad hoc/development builds; PIE, canary, ARC; iOS cryptid; min/target SDK; readable bundle; third-party SDK inventory. | Hooking, Frida, class dumping, binary patching, update integrity. |
| **RESILIENCE** | Root/jailbreak/Frida/debugger strings in DEX/Hermes/binary (presence or absence). | Whether the checks work, and what the app does when they fire; bypass with Frida/objection. |
| **PRIVACY** | Permissions, always-location, contacts, microphone, photo library; third-party/tracking SDKs; privacy manifests; screenshot protection. | Data actually sent by SDKs; consent flows; analytics on sensitive screens; retention. |

## Added in 1.33.0

- Android task-hijacking configuration (exported `singleTask` without `taskAffinity`).
- Android backup without extraction rules.
- Pinning evidence (Android pin-set, CertificatePinner, iOS pin hashes/TrustKit) as a gap when absent.
- Root/jailbreak/debugger/Frida checks: absence is a finding for a banking app; presence is recorded.
- WebView script/file access as a verification finding.
- Android screenshot-protection indicator (with the inlined-constant caveat).
- iOS Keychain accessibility classes weaker than `ThisDeviceOnly`.
- iOS binary encryption (`cryptid`) and ad hoc/profile checks from 1.32.0.
- Test/demo host and key detection in the Hermes bundle, Android and iOS.

## Deliberately not claimed

- A static scan cannot confirm a backend authorization flaw, a session-fixation bug or an open test
  API. Those need the test target and a test account.
- "No pinning evidence" is not "no pinning". It is a request to verify.
- "No root detection strings" is not proof the app does nothing; it is a gap in the artefact.

## Live techniques worth using (and what MacSec can automate)

These are the techniques mobile testers use on a real test phone or a permitted emulator. MacSec's
static checks tell you where to look; the live steps prove it.

| Technique | Android | iOS | MacSec today |
| --- | --- | --- | --- |
| TLS interception with a user CA | mitmproxy/Burp, system CA on a rooted test image | Proxy + profile, certificate trust | Traffic capture (mitmproxy, person configures the phone) |
| Certificate pinning bypass | Frida/objection, apk-mitm on a test build | Frida/objection on a jailbroken or test-signed build | Live test watches, does not bypass; bypass needs explicit approval |
| Root/jailbreak detection bypass | Frida, Magisk DenyList | Frida, palera1n/rootless | Static presence check; bypass is manual |
| Stored data | `run-as`, adb backup, `/data/data/<pkg>` | Keychain dump, app container, NSUserDefaults | Static backup/Keychain checks; extraction manual |
| Exported components and intents | `am start`, `am broadcast`, drozer | URL schemes, universal links | Static manifest/scheme checks; runtime manual |
| Task hijacking | malicious companion app, singleTask/taskAffinity | n/a | Static configuration check |
| Tapjacking/overlay | overlay app, `filterTouchesWhenObscured` | n/a | Not yet static; manual |
| Screenshot and app-switcher leakage | FLAG_SECURE test, screen recording | screen recording, app switcher snapshot | Indicator check; device test |
| WebView and JS bridge | hostile page, deep link into WebView | WKWebView load with a hostile page | Static WebView symbols; runtime manual |
| Deep link abuse | `adb shell am start -d ...` | `xcrun simctl openurl` on a simulator build | Static schemes; runtime manual |
| Emulator/root integrity | Play Integrity, SafetyNet, custom checks | DeviceCheck/App Attest | Static checks; the app may refuse an emulator |
| Backup and data extraction | `adb backup`, cloud backup rules | iTunes/Finder backup, Keychain migration | Static backup/Keychain classes; extraction manual |

The app under review may deliberately refuse emulators or rooted devices. That is a control, not a
bug; use a physical test phone or a vendor test build that permits instrumentation, with written
authorization.
