import { describe, expect, it } from 'vitest'
import { adminAccounts, brewOutdated, cronJobs, dnsServers, envFilesCheck, historyCheck, historySecrets, idleLock, internetSharing, rejectedApps, rootAccount, savedOpenWifi, secretFiles, secretFilesCheck, sshdConfig, thirdPartyExtensions, wifiSecurity, xprotectAge } from '../src/main/machecks2'

describe('This Mac deeper checks (each has a clean case and a bad case)', () => {
  it('root account', () => {
    expect(rootAccount('No such key: AuthenticationAuthority').status).toBe('ok')
    expect(rootAccount('AuthenticationAuthority: ;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>').status).toBe('bad')
  })
  it('admins', () => {
    expect(adminAccounts('GroupMembership: root alice', 'bob').status).toBe('ok')
    expect(adminAccounts('GroupMembership: root alice', 'alice').status).toBe('info')
    expect(adminAccounts('GroupMembership: root a b c', 'x').status).toBe('warn')
    expect(adminAccounts('', 'x').status).toBe('info')
  })
  it('idle lock', () => {
    expect(idleLock('300', '0').status).toBe('ok')
    expect(idleLock('0', '0').status).toBe('warn')
    expect(idleLock('300', '900').status).toBe('warn')
    expect(idleLock('The domain/default pair does not exist', '0').status).toBe('info')
  })
  it('secret files never keep the value', () => {
    const files: Record<string, string> = { '.aws/credentials': '[default]\naws_access_key_id = AKIAAAAAAAAAAAAAAAAA\naws_secret_access_key = SUPERSECRETVALUE123' }
    const found = secretFiles((rel) => (files[rel] ? { text: files[rel], mode: 0o100644 } : null))
    expect(found).toHaveLength(1)
    const c = secretFilesCheck(found)
    expect(c.status).toBe('bad')
    expect(JSON.stringify([found, c])).not.toContain('SUPERSECRET')
    expect(secretFilesCheck([]).status).toBe('ok')
    expect(secretFilesCheck(secretFiles((rel) => (rel === '.aws/credentials' ? { text: '[default]\nregion=eu-west-1', mode: 0o600 } : null))).status).toBe('ok')
    expect(secretFilesCheck([{ file: '~/.netrc', kind: 'x', mode: 0o600 }]).status).toBe('warn')
  })
  it('history: kinds and counts, never the secret', () => {
    const h = 'ls\nexport AWS=AKIAIOSFODNN7EXAMPLE\ncurl -u admin:hunter2pass https://x.example\ngit status\ncurl -H "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456" https://a.example\n'
    const hits = historySecrets(h)
    expect(hits.map((x) => x.kind)).toEqual(expect.arrayContaining(['an AWS access key', 'a password on a command line', 'a bearer token']))
    const c = historyCheck(hits)
    expect(c.status).toBe('warn')
    expect(c.detail).not.toContain('hunter2pass')
    expect(c.detail).not.toContain('AKIAIOSFODNN7EXAMPLE')
    expect(historySecrets('ls\ncd ..\ngit commit -m "password reset page"\n')).toEqual([])
    expect(historyCheck([]).status).toBe('ok')
  })
  it('env files', () => {
    expect(envFilesCheck([]).status).toBe('ok')
    expect(envFilesCheck([{ file: '~/a/.env', mode: 0o600 }]).status).toBe('info')
    expect(envFilesCheck([{ file: '~/a/.env', mode: 0o644 }]).status).toBe('warn')
  })
  it('xprotect age', () => {
    const now = Date.parse('2026-06-01T00:00:00Z')
    expect(xprotectAge(now - 3 * 86400000, now).status).toBe('ok')
    expect(xprotectAge(now - 30 * 86400000, now).status).toBe('warn')
    expect(xprotectAge(now - 90 * 86400000, now).status).toBe('bad')
    expect(xprotectAge(null, now).status).toBe('info')
  })
  it('extensions', () => {
    const kext = 'Index Refs Address Size Wired Name (Version) <Linked Against>\n    1    0 0xffff 0x1000 0x1000 com.apple.driver.AppleFoo (1.0) <1>\n   90    0 0xffff 0x1000 0x1000 com.vendor.driver (2.0) <1>\n'
    expect(thirdPartyExtensions(kext, '').status).toBe('info')
    expect(thirdPartyExtensions('Index Refs\n 1 0 0 0 0 com.apple.driver.X (1) <1>\n', '--- com.apple.system_extension.endpoint_security\n').status).toBe('ok')
  })
  it('rejected apps, brew', () => {
    expect(rejectedApps([]).status).toBe('ok')
    expect(rejectedApps(['Odd']).status).toBe('warn')
    expect(brewOutdated(null).status).toBe('info')
    expect(brewOutdated('a\nb\n').status).toBe('ok')
    expect(brewOutdated(Array.from({ length: 40 }, (_, i) => `p${i}`).join('\n')).status).toBe('warn')
  })
  it('sshd settings matter only when Remote Login is on', () => {
    expect(sshdConfig('PermitRootLogin yes', false).status).toBe('ok')
    expect(sshdConfig('PermitRootLogin yes\nPasswordAuthentication no', true).status).toBe('bad')
    expect(sshdConfig('PermitRootLogin no\nPasswordAuthentication yes', true).status).toBe('warn')
    expect(sshdConfig('# PermitRootLogin yes\nPermitRootLogin no\nPasswordAuthentication no', true).status).toBe('ok')
  })
  it('cron', () => {
    expect(cronJobs('crontab: no crontab for alice').status).toBe('ok')
    expect(cronJobs('# comment\n0 * * * * /usr/bin/thing').status).toBe('info')
  })
  it('wifi', () => {
    const wpa3 = `Wi-Fi:\n      Current Network Information:\n        HomeNet:\n          PHY Mode: 802.11ax\n          Security: WPA3 Personal\n          Channel: 36\n\n        Other Networks:\n`
    const open = wpa3.replace('WPA3 Personal', 'None')
    const wep = wpa3.replace('WPA3 Personal', 'WEP')
    expect(wifiSecurity(wpa3).status).toBe('ok')
    expect(wifiSecurity(open).status).toBe('bad')
    expect(wifiSecurity(wep).status).toBe('warn')
    expect(wifiSecurity('Wi-Fi:\n  Status: Off\n').status).toBe('info')
    expect(savedOpenWifi('Preferred networks on en0:\n\tHomeNet\n\tOffice\n').status).toBe('ok')
    expect(savedOpenWifi('Preferred networks on en0:\n\tHomeNet\n\tFree WiFi\n').status).toBe('warn')
  })
  it('internet sharing, dns', () => {
    expect(internetSharing('The domain/default pair does not exist').status).toBe('ok')
    expect(internetSharing('{ NAT = { Enabled = 1; }; }').status).toBe('warn')
    expect(dnsServers('resolver #1\n  nameserver[0] : 192.168.1.1\nresolver #2\n  nameserver[0] : 1.1.1.1').status).toBe('ok')
    expect(dnsServers('resolver #1\n  nameserver[0] : 203.0.113.9').status).toBe('warn')
    expect(dnsServers('nothing').status).toBe('info')
  })
})
