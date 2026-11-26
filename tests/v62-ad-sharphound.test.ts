import { describe, expect, it } from 'vitest'
import { analyzeAd, parseAdExport } from '../src/main/adreview'

const users = JSON.stringify({
  data: [
    { ObjectIdentifier: 'S-1-5-21-1-1105', Properties: { name: 'SVC_SQL@CORP.LOCAL', enabled: true, serviceprincipalnames: ['MSSQLSvc/db01.corp.local:1433'], admincount: false } },
    { ObjectIdentifier: 'S-1-5-21-1-502', Properties: { name: 'KRBTGT@CORP.LOCAL', enabled: true, serviceprincipalnames: ['kadmin/changepw'] } },
    { ObjectIdentifier: 'S-1-5-21-1-1106', Properties: { name: 'OLD@CORP.LOCAL', enabled: false, dontreqpreauth: true } },
    { ObjectIdentifier: 'S-1-5-21-1-1107', Properties: { name: 'NOPW@CORP.LOCAL', enabled: true, passwordnotreqd: true } }
  ],
  meta: { type: 'users', count: 4, version: 5 }
})

describe('a SharpHound export', () => {
  it('reads the data wrapper and the type', () => {
    const nodes = parseAdExport(users, 'users.json')
    expect(nodes).toHaveLength(4)
    expect(nodes.every((n) => n.kind === 'user')).toBe(true)
  })
  it('finds the real problems and skips krbtgt and disabled accounts', () => {
    const f = analyzeAd(parseAdExport(users, 'users.json'), 'users.json')
    const titles = f.map((x) => x.title)
    expect(titles).toContain('Kerberoastable service account: SVC_SQL@CORP.LOCAL')
    expect(titles.some((t) => t.includes('KRBTGT'))).toBe(false)
    expect(titles.some((t) => t.includes('OLD@'))).toBe(false)
    expect(titles).toContain('Password not required: NOPW@CORP.LOCAL')
  })
})
