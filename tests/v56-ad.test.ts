/** 1.40: BloodHound export parsing and the AD findings. */
import { describe, expect, it } from 'vitest'
import { analyzeAd, parseAdExport } from '../src/main/adreview'

describe('the BloodHound review', () => {
  it('reads users, computers and nested properties', () => {
    const nodes = parseAdExport(JSON.stringify({
      users: [{ name: 'svc_sql', Properties: { serviceprincipalnames: ['MSSQLSvc/db:1433'], enabled: true } }],
      computers: [{ name: 'WEB01$', Properties: { unconstraineddelegation: true, haslaps: false } }]
    }))
    expect(nodes.find((n) => n.name === 'svc_sql')?.kind).toBe('user')
    expect(nodes.find((n) => n.name === 'WEB01$')?.kind).toBe('computer')
  })
  it('reports Kerberoastable, AS-REP, delegation, AdminCount and LAPS', () => {
    const text = JSON.stringify({
      users: [
        { name: 'svc_sql', serviceprincipalnames: ['MSSQLSvc/db:1433'], enabled: true },
        { name: 'old_user', dontreqpreauth: true, enabled: true },
        { name: 'admin_old', admincount: 1, pwdneverexpires: true, enabled: true }
      ],
      computers: [{ name: 'WEB01$', unconstraineddelegation: true, haslaps: false, enabled: true }]
    })
    const f = analyzeAd(parseAdExport(text), 'users.json')
    const titles = f.map((x) => x.title)
    expect(titles).toContain('Kerberoastable service account: svc_sql')
    expect(titles).toContain('AS-REP roastable account: old_user')
    expect(titles).toContain('Unconstrained delegation: WEB01$')
    expect(titles).toContain('AdminCount=1 account: admin_old')
    expect(titles).toContain('Password never expires: admin_old')
    expect(titles).toContain('LAPS not detected: WEB01$')
    expect(f.every((x) => x.confidence === 'possible')).toBe(true)
  })
  it('does not report disabled accounts', () => {
    const f = analyzeAd(parseAdExport(JSON.stringify({ users: [{ name: 'disabled', dontreqpreauth: true, enabled: false }] })), 'users.json')
    expect(f.some((x) => x.title.includes('disabled'))).toBe(false)
  })
})
