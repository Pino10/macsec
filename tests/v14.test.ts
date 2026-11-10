import { describe, expect, it } from 'vitest'
import { airdrop, autoLogin, findMy, guestAccount, hostsFile, lastUpdateCheck, mdm, openServices, pathDirs, proxies, screenLock, sharingFrom, timeMachine, trustedCerts } from '../src/main/machecks'
import type { ListeningPort } from '../src/main/checkup'

const port = (command: string, p: number, everyone = true): ListeningPort => ({ command, pid: 1, address: everyone ? '*' : '127.0.0.1', port: p, everyone })

describe('This Mac: sign-in and lock', () => {
  it('flags a missing lock password and accepts an immediate one', () => {
    expect(screenLock('2026-11-02 08:00:00 sysadminctl[1:2] screenLock is off').status).toBe('bad')
    expect(screenLock('sysadminctl[1:2] screenLock delay is immediate').status).toBe('ok')
    expect(screenLock('something else').status).toBe('info')
  })
  it('reads the guest user and automatic login', () => {
    expect(guestAccount('1\n').status).toBe('warn')
    expect(guestAccount('0\n').status).toBe('ok')
    expect(autoLogin('pino\n').status).toBe('bad')
    expect(autoLogin('The domain/default pair of (/Library/Preferences/com.apple.loginwindow, autoLoginUser) does not exist').status).toBe('ok')
  })
})

describe('This Mac: lost or stolen', () => {
  it('Find My and backups', () => {
    expect(findMy('fmm-mobileme-token-FMM\t%00\nboot-args\t').status).toBe('ok')
    expect(findMy('boot-args\t').status).toBe('warn')
    expect(timeMachine('tmutil: No destinations configured.').status).toBe('warn')
    expect(timeMachine('====================================================\nName          : Backup\nKind          : Local\n').status).toBe('ok')
    expect(timeMachine('').status).toBe('info')
  })
})

describe('This Mac: reachable from other devices', () => {
  it('AirDrop', () => {
    expect(airdrop('Everyone').status).toBe('warn')
    expect(airdrop('Contacts Only').status).toBe('ok')
  })
  it('sharing and open databases come from the ports', () => {
    expect(sharingFrom([port('launchd', 22)]).status).toBe('warn')
    expect(sharingFrom([port('node', 3000)]).status).toBe('ok')
    expect(sharingFrom([port('sshd', 22, false)]).status).toBe('ok')
    expect(openServices([port('redis-server', 6379)]).status).toBe('bad')
    expect(openServices([port('mysqld', 3306)]).status).toBe('warn')
    expect(openServices([port('mysqld', 3306, false)]).status).toBe('ok')
  })
})

describe('This Mac: where traffic goes', () => {
  const dict = '<dictionary> {\n  ExceptionsList : <array> {\n    0 : *.local\n  }\n  HTTPEnable : 1\n  HTTPPort : 8080\n  HTTPProxy : 10.1.1.9\n  ProxyAutoConfigEnable : 0\n}\n'
  it('proxies', () => {
    const c = proxies(dict)
    expect(c.status).toBe('warn')
    expect(c.detail).toContain('10.1.1.9:8080')
    expect(proxies('<dictionary> {\n  HTTPEnable : 0\n}').status).toBe('ok')
  })
  it('hosts file ignores local development names', () => {
    const normal = '127.0.0.1\tlocalhost\n255.255.255.255\tbroadcasthost\n::1 localhost\n127.0.0.1 shop.test blog.local\n0.0.0.0 ads.example.com\n'
    expect(hostsFile(normal).status).toBe('ok')
    const c = hostsFile(normal + '203.0.113.7 www.mybank.com # added\n')
    expect(c.status).toBe('warn')
    expect(c.detail).toContain('www.mybank.com → 203.0.113.7')
  })
  it('extra trusted certificates', () => {
    expect(trustedCerts('SecTrustSettingsCopyCertificates: No Trust Settings were found.', 'SecTrustSettingsCopyCertificates: No Trust Settings were found.').status).toBe('ok')
    const c = trustedCerts('Number of trusted certs = 1\nCert 0: mkcert pino@mac\n   Number of trust settings : 1\n', 'No Trust Settings were found.')
    expect(c.status).toBe('info')
    expect(c.detail).toContain('mkcert pino@mac')
  })
})

describe('This Mac: updates and management', () => {
  const now = new Date('2026-11-10T00:00:00Z').getTime()
  it('how long ago macOS looked for updates', () => {
    expect(lastUpdateCheck('"2026-11-08 08:12:11 +0000"', now).status).toBe('ok')
    expect(lastUpdateCheck('"2026-10-20 08:12:11 +0000"', now).status).toBe('warn')
    expect(lastUpdateCheck('"2026-08-01 08:12:11 +0000"', now).status).toBe('bad')
    expect(lastUpdateCheck('', now).status).toBe('info')
  })
  it('device management', () => {
    expect(mdm('Enrolled via DEP: No\nMDM enrollment: No').detail).toContain('not enrolled')
    expect(mdm('Enrolled via DEP: Yes\nMDM enrollment: Yes (User Approved)').detail).toContain('managed by an organisation')
  })
  it('PATH folders other people can write to', () => {
    const modes: Record<string, number> = { '/usr/local/bin': 0o40755, '/tmp/tools': 0o40777, '/opt/sticky': 0o41777 }
    const c = pathDirs('/usr/local/bin:/tmp/tools:/opt/sticky:/nowhere', (p) => modes[p] ?? null)
    expect(c.status).toBe('bad')
    expect(c.detail).toContain('/tmp/tools')
    expect(c.detail).not.toContain('/usr/local/bin')
    expect(c.detail).not.toContain('/opt/sticky')
  })
})

import { checkFirebaseConfig, checkNetworkSecurityConfig, checkProvisioning, checkTargetSdk } from '../src/main/scanners/mobile'

describe('mobile: more checks from files inside the app', () => {
  const nsc = `<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors><certificates src="system"/><certificates src="user"/></trust-anchors>
  </base-config>
  <domain-config cleartextTrafficPermitted="true"><domain includeSubdomains="true">api.staging.example.com</domain></domain-config>
  <debug-overrides><trust-anchors><certificates src="user"/></trust-anchors></debug-overrides>
</network-security-config>`
  it('network security config: plain HTTP and added certificates', () => {
    const f = checkNetworkSecurityConfig(nsc)
    expect(f.map((x) => x.title).join('|')).toContain('api.staging.example.com')
    expect(f.some((x) => /trusts certificates the phone owner added/.test(x.title))).toBe(true)
    expect(f.some((x) => /Debug builds trust/.test(x.title))).toBe(true)
  })
  it('a clean config has no findings, and user certificates inside debug-overrides are only information', () => {
    const clean = '<network-security-config><base-config cleartextTrafficPermitted="false"><trust-anchors><certificates src="system"/></trust-anchors></base-config><debug-overrides><trust-anchors><certificates src="user"/></trust-anchors></debug-overrides></network-security-config>'
    expect(checkNetworkSecurityConfig(clean).every((x) => x.severity === 'info')).toBe(true)
  })
  it('an expired pin set is reported', () => {
    expect(checkNetworkSecurityConfig('<domain-config><pin-set expiration="2020-01-01"><pin digest="SHA-256">x</pin></pin-set></domain-config>').some((x) => /pinning expired/.test(x.title))).toBe(true)
  })
  it('provisioning profile of a development build', () => {
    const dev = '<dict><key>Entitlements</key><dict><key>get-task-allow</key>\n<true/><key>aps-environment</key><string>development</string></dict></dict>'
    const f = checkProvisioning(dev)
    expect(f.map((x) => x.severity)).toEqual(['high', 'low'])
    expect(checkProvisioning('<key>get-task-allow</key><false/>')).toHaveLength(0)
  })
  it('Firebase address is noted without reading it', () => {
    const f = checkFirebaseConfig('{"project_info":{"firebase_url":"https://shop-demo-default-rtdb.firebaseio.com"}}', 'google-services.json')
    expect(f).toHaveLength(1)
    expect(f[0].description).toContain('did not read the database')
    expect(checkFirebaseConfig('{}', 'x')).toHaveLength(0)
  })
  it('old target SDK', () => {
    expect(checkTargetSdk('<uses-sdk android:minSdkVersion="21" android:targetSdkVersion="30"/>')).toHaveLength(1)
    expect(checkTargetSdk('<uses-sdk android:targetSdkVersion="35"/>')).toHaveLength(0)
  })
})

import { expandTargets, isPrivateTarget, MAX_TARGETS } from '../src/main/targets'

describe('servers inside a network', () => {
  it('takes a list, a range and a small network', () => {
    expect(expandTargets('db1.corp.local, 10.0.0.5\n10.0.0.5 app.example.com')).toEqual(['db1.corp.local', '10.0.0.5', 'app.example.com'])
    expect(expandTargets('192.168.1.10-13')).toEqual(['192.168.1.10', '192.168.1.11', '192.168.1.12', '192.168.1.13'])
    const net = expandTargets('192.168.1.0/29')
    expect(net[0]).toBe('192.168.1.1')
    expect(net).toHaveLength(6)
  })
  it('refuses anything that could be read as an option, a typo or a sweep', () => {
    expect(() => expandTargets('-iL /etc/passwd')).toThrow()
    expect(() => expandTargets('10.0.0.0/16')).toThrow(/bigger/)
    expect(() => expandTargets('10.0.0.300')).toThrow()
    expect(() => expandTargets('10.0.0.9-5')).toThrow()
    expect(() => expandTargets('')).toThrow()
    expect(() => expandTargets('a b; rm -rf')).toThrow()
    expect(() => expandTargets('10.0.0.0/24, 10.0.1.0/24')).toThrow(new RegExp(`${MAX_TARGETS}`))
  })
  it('knows private network addresses', () => {
    expect(isPrivateTarget('192.168.4.2')).toBe(true)
    expect(isPrivateTarget('172.20.1.1')).toBe(true)
    expect(isPrivateTarget('172.40.1.1')).toBe(false)
    expect(isPrivateTarget('203.0.113.4')).toBe(false)
  })
})
