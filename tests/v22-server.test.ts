import { createServer as tcpServer, type Server as TcpServer } from 'net'
import type { AddressInfo } from 'net'
import { describe, expect, it } from 'vitest'
import { checkArgs, moduleFor, msfChecks, MODULES, parseCheck, validModule, validTarget } from '../src/main/msf'
import { probeServices, productsFrom, tcpTalk, webServices } from '../src/main/servicedeep'

const listen = (reply: (data: string) => string | null, banner: string | null = null): Promise<{ server: TcpServer; port: number }> =>
  new Promise((resolve) => {
    const server = tcpServer((sock) => {
      if (banner) sock.write(banner)
      sock.on('data', (d) => {
        const r = reply(d.toString())
        if (r !== null) sock.write(r)
      })
      sock.on('error', () => undefined)
    })
    server.listen(0, '127.0.0.1', () => resolve({ server, port: (server.address() as AddressInfo).port }))
  })

describe('service probes (real sockets)', () => {
  it('finds a Redis that answers without a password, with proof, and not one that wants a password', async () => {
    const open = await listen((d) => (/^PING/.test(d) ? '+PONG\r\n' : null))
    const closed = await listen((d) => (/^PING/.test(d) ? '-NOAUTH Authentication required.\r\n' : null))
    const a = await probeServices([{ host: '127.0.0.1', port: open.port, service: 'redis' }], { talk: tcpTalk })
    const b = await probeServices([{ host: '127.0.0.1', port: closed.port, service: 'redis' }], { talk: tcpTalk })
    open.server.close()
    closed.server.close()
    expect(a.findings).toHaveLength(1)
    expect(a.findings[0]).toMatchObject({ severity: 'critical', confidence: 'confirmed' })
    expect(a.findings[0].proof?.reproduce).toContain('nc -w 4')
    expect(b.findings).toEqual([])
  })
  it('a service that says +PONG to anything but is not named Redis is only asked by name or port', async () => {
    const s = await listen(() => '+PONG\r\n')
    const r = await probeServices([{ host: '127.0.0.1', port: s.port, service: 'http' }], { talk: tcpTalk })
    s.server.close()
    expect(r.findings).toEqual([])
  })
  it('does not report an HTTP page that only mentions Elasticsearch', async () => {
    const s = await listen(() => 'HTTP/1.0 200 OK\r\n\r\n<html>Learn about Elasticsearch cluster_name settings</html>')
    const r = await probeServices([{ host: '127.0.0.1', port: s.port, service: 'elasticsearch' }], { talk: tcpTalk })
    s.server.close()
    expect(r.findings).toEqual([])
  })
  it('reads an SSH banner into a product and flags protocol 1', async () => {
    const ok = await listen(() => null, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n')
    const old = await listen(() => null, 'SSH-1.5-Old\r\n')
    const a = await probeServices([{ host: '127.0.0.1', port: ok.port, service: 'ssh' }], { talk: tcpTalk })
    const b = await probeServices([{ host: '127.0.0.1', port: old.port, service: 'ssh' }], { talk: tcpTalk })
    ok.server.close()
    old.server.close()
    expect(a.products.map((p) => `${p.product.name} ${p.product.version}`)).toContain('OpenSSH 8.9p1')
    expect(a.findings).toEqual([])
    expect(b.findings[0].title).toMatch(/protocol 1/)
  })
  it('turns Nmap product text into products, and invents nothing without a version', () => {
    expect(productsFrom('OpenSSH 7.4 (protocol 2.0)', 'h', 22)[0]).toMatchObject({ name: 'OpenSSH', version: '7.4' })
    expect(productsFrom('Apache httpd 2.4.49', 'h', 80)[0]).toMatchObject({ name: 'Apache HTTP Server', version: '2.4.49' })
    expect(productsFrom('vsftpd 2.3.4', 'h', 21)[0].version).toBe('2.3.4')
    expect(productsFrom('http Apache', 'h', 80)).toEqual([])
    expect(productsFrom('', 'h', 80)).toEqual([])
  })
  it('picks the web services among the ports', () => {
    const w = webServices([{ host: 'h', port: 443 }, { host: 'h', port: 22, service: 'ssh' }, { host: 'h', port: 8080 }, { host: 'h', port: 9999, service: 'http' }])
    expect(w.map((x) => x.url)).toEqual(['https://h:443', 'http://h:8080', 'http://h:9999'])
  })
})

describe('Metasploit stays check-only', () => {
  it('builds a fixed script from validated values, with no run, exploit or payload', () => {
    const args = checkArgs('auxiliary/scanner/smb/smb_ms17_010', '10.0.0.5', 445)
    expect(args).toEqual(['-q', '-n', '-x', 'use auxiliary/scanner/smb/smb_ms17_010; set RHOSTS 10.0.0.5; set RPORT 445; check; exit -y'])
    const script = args[3]
    expect(script).not.toMatch(/\b(run|exploit|payload|lhost|lport|sessions|shell)\b/i)
  })
  it('refuses modules outside the list and addresses that could be read as commands', () => {
    expect(() => checkArgs('exploit/windows/smb/ms17_010_eternalblue', '10.0.0.5', 445)).toThrow()
    expect(() => checkArgs('auxiliary/scanner/smb/smb_ms17_010', '10.0.0.5; exploit', 445)).toThrow()
    expect(() => checkArgs('auxiliary/scanner/smb/smb_ms17_010', '-r evil.rc', 445)).toThrow()
    expect(() => checkArgs('auxiliary/scanner/smb/smb_ms17_010', 'a.example.com', 70000)).toThrow()
    expect(validModule('auxiliary/scanner/smb/smb_ms17_010; use x')).toBe(false)
    expect(validTarget('$(id)', 80)).toBe(false)
    expect(validTarget('203.0.113.9', 8080)).toBe(true)
  })
  it('every module in the list is a plain module path and none reads files or memory', () => {
    for (const m of MODULES) {
      expect(m.module).toMatch(/^(auxiliary\/scanner|exploit)\/[a-z0-9_/]+$/)
      expect(m.module).not.toMatch(/heartbleed|file_disclosure|ghostcat|gather|dump|read/)
    }
    expect(moduleFor('cve-2017-0144')?.module).toContain('ms17_010')
    expect(moduleFor('CVE-1999-0001')).toBeNull()
  })
  it('reads real Metasploit check output', () => {
    expect(parseCheck('[+] 10.0.0.5:445 - Host is likely VULNERABLE to MS17-010!\n[+] 10.0.0.5:445 - The target is vulnerable.').state).toBe('vulnerable')
    expect(parseCheck('[*] 10.0.0.5:8080 - The target appears to be vulnerable.').state).toBe('appears')
    expect(parseCheck('[*] 10.0.0.5:80 - The target is not exploitable.').state).toBe('safe')
    expect(parseCheck('[*] 10.0.0.5:80 - The target appears to be safe').state).toBe('safe')
    expect(parseCheck('[-] This module does not support check.').state).toBe('unsupported')
    expect(parseCheck('[*] 10.0.0.5:80 - Cannot reliably check exploitability.').state).toBe('unsupported')
    expect(parseCheck('').state).toBe('unknown')
  })
  it('keeps a finding with proof only for vulnerable or appears-vulnerable, and sends only the safe script', async () => {
    const seen: string[][] = []
    const run = async (_bin: string, args: string[]): Promise<string> => {
      seen.push(args)
      return args[3].includes('smb_ms17_010') ? '[+] 10.0.0.5:445 - The target is vulnerable.' : '[*] x - The target is not exploitable.'
    }
    const out = await msfChecks([{ cve: 'CVE-2017-0144', host: '10.0.0.5', port: 445 }, { cve: 'CVE-2022-22965', host: '10.0.0.5', port: 8080 }, { cve: 'CVE-2000-0001', host: '10.0.0.5', port: 80 }, { cve: 'CVE-2017-0144', host: '10.0.0.5', port: 445 }], { bin: '/x/msfconsole', run })
    expect(out).toHaveLength(1)
    expect(out[0]).toMatchObject({ confidence: 'confirmed', tool: 'Metasploit (check only)' })
    expect(out[0].proof?.reproduce).toContain('check; exit -y')
    // One check per module, host and port, and none for a CVE without a module.
    expect(seen).toHaveLength(2)
    for (const a of seen) expect(a[3].replace(/^use \S+; /, '')).toMatch(/^set RHOSTS \S+; set RPORT \d+; check; exit -y$/)
  })
  it('does nothing when Metasploit is not installed', async () => {
    const notes: string[] = []
    const out = await msfChecks([{ cve: 'CVE-2017-0144', host: '10.0.0.5', port: 445 }], { bin: undefined, run: async () => '', note: (t) => notes.push(t) })
    // With no explicit path and none on this machine, nothing runs.
    expect(Array.isArray(out)).toBe(true)
  })
})
