/** 1.32: the iOS checks that go beyond the provisioning profile. */
import { describe, expect, it } from 'vitest'
import { readFileSync, existsSync } from 'fs'
import { join } from 'path'
import { bundleFindings, infoPlistExtra, provisioningFindings, signedEntitlementFindings, signingAuthorityFindings } from '../src/main/ioschecks'

const profile = `<?xml version="1.0"?><plist><dict>
<key>Name</key><string>iOS Team Ad Hoc Provisioning Profile: com.example.bank</string>
<key>TeamName</key><string>Sathish Manju</string>
<key>TeamIdentifier</key><array><string>G9U425A65X</string></array>
<key>ExpirationDate</key><string>2027-09-23T05:50:34Z</string>
<key>get-task-allow</key><false/>
<key>ProvisionedDevices</key><array><string>00008120-000203D121F9A01E</string><string>00008020-000824423A43002E</string></array>
</dict></plist>`

describe('the signed app, not just the profile', () => {
  it('does not report a wildcard when the profile has it but the signed app does not request it', () => {
    const signed = '<plist><dict><key>application-identifier</key><string>T.com.example.bank</string><key>get-task-allow</key><false/></dict></plist>'
    expect(signedEntitlementFindings(signed, 'app.entitlements')).toEqual([])
  })
  it('reports a wildcard only when the signed entitlements ask for it', () => {
    const signed = '<plist><dict><key>keychain-access-groups</key><array><string>T.*</string></array></dict></plist>'
    const f = signedEntitlementFindings(signed, 'app.entitlements')
    expect(f).toHaveLength(1)
    expect(f[0]).toMatchObject({ severity: 'low', title: expect.stringContaining('Keychain') })
  })
  it('reads ad hoc distribution, device count and team', () => {
    const f = provisioningFindings(profile, 'embedded.mobileprovision')
    expect(f.some((x) => x.severity === 'medium' && /Ad hoc build for 2/.test(x.title))).toBe(true)
    expect(f.some((x) => /signing team is named/.test(x.title))).toBe(true)
  })
})

describe('Info.plist and bundle facts', () => {
  it('finds the Google key, always-location and the absent screenshot flag', () => {
    const xml = '<plist><dict><key>GMSApiKey</key><string>AIzaSyDpCW0wZTt7WzOPNGEn1r28QT2llJN05Z4</string><key>NSLocationAlwaysUsageDescription</key><string>Nearby ATMs</string></dict></plist>'
    const f = infoPlistExtra(xml, 'Info.plist')
    expect(f.some((x) => /Google Maps API key/.test(x.title) && x.severity === 'medium')).toBe(true)
    expect(f.some((x) => /always-on location/.test(x.title))).toBe(true)
    expect(f.some((x) => /screenshot-block flag/.test(x.title))).toBe(true)
  })
  it('finds test hosts, keys and unproven pinning in the bundle', () => {
    const text = 'fetch("https://ebankingtest.bank.example.gh/apigateway"); const k="AIzaSyDpCW0wZTt7WzOPNGEn1r28QT2llJN05Z4"; sslPinning = true;'
    const f = bundleFindings(text, 'main.jsbundle')
    expect(f.some((x) => /Test or demo servers/.test(x.title) && x.severity === 'medium')).toBe(true)
    expect(f.some((x) => /API keys are written/.test(x.title))).toBe(true)
    expect(f.some((x) => /Pinning is mentioned/.test(x.title))).toBe(true)
  })
  it('gives the signing authority without claiming it is a bug', () => {
    const f = signingAuthorityFindings('Authority=Apple Distribution: Sathish Manju (G9U425A65X)\nTeamIdentifier=G9U425A65X', 'app')
    expect(f).toHaveLength(1)
    expect(f[0].description).toContain('Sathish Manju')
  })
})

// Run the same checks against the real IPA when it has been unpacked (manual verification).
const real = process.env.OMNI_IPA_DIR
describe.runIf(!!real)('the real OmniBisic IPA', () => {
  it('matches the manual assessment', () => {
    const dir = real as string
    const prof = readFileSync(join(dir, 'profile.plist'), 'utf8')
    const ent = readFileSync(join(dir, 'signed-entitlements.xml'), 'utf8')
    const plist = readFileSync(join(dir, 'Info.xml'), 'utf8')
    const strings = readFileSync(join(dir, 'strings.txt'), 'utf8')
    const pf = provisioningFindings(prof, 'embedded.mobileprovision')
    expect(pf.some((x) => /Ad hoc build for 25/.test(x.title))).toBe(true)
    expect(signedEntitlementFindings(ent, 'app')).toEqual([])
    expect(infoPlistExtra(plist, 'Info.plist').some((x) => /Google Maps API key/.test(x.title))).toBe(true)
    const bf = bundleFindings(strings, 'main.jsbundle')
    expect(bf.some((x) => /Test or demo servers/.test(x.title))).toBe(true)
    expect(bf.some((x) => /API keys are written/.test(x.title))).toBe(true)
  })
})
