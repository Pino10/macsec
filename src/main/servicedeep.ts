/**
 * Server depth, the part of a network scanner that looks at each open service. Once the open ports
 * are known (and named by Nmap when it is installed), MacSec:
 *
 *   - turns each service banner into a product and version, and matches it to live vulnerability data
 *   - asks data stores that should never be open whether they answer without a password: one harmless
 *     read command each (Redis PING, memcached version, Elasticsearch, CouchDB and Docker's version page)
 *   - looks at every web service behind an open port the way the web checks do: headers, certificate,
 *     firewall, DevOps tools, versions
 *
 * Only reads. Nothing is written to a service, no password is tried, and each answer that proves a
 * problem is repeated once and kept as proof.
 */
import { connect } from 'net'
import { createHash } from 'crypto'
import type { Finding } from '../shared/types'
import type { OpenPort } from './scanners/infra'
import type { Product, Proof } from './seckit/confirm'
import { fid } from './scanners/parse'
import { deepHosts, type DeepOptions } from './recondeep'

export type Talk = (host: string, port: number, send: string | null, ms?: number) => Promise<string>

/** Connects, optionally sends one line, and reads the first answer (up to 8 KB). */
export const tcpTalk: Talk = (host, port, send, ms = 4000) =>
  new Promise((resolve) => {
    let data = ''
    const s = connect({ host, port })
    const done = (): void => {
      s.destroy()
      resolve(data)
    }
    s.setTimeout(ms, done)
    s.on('connect', () => {
      if (send !== null) s.write(send)
    })
    s.on('data', (d) => {
      data += d.toString('latin1')
      if (data.length > 8192) done()
      // A banner or a one-line answer is enough.
      else if (/\r?\n/.test(data) && send !== null && !/^HTTP\//.test(data)) setTimeout(done, 150)
    })
    s.on('error', done)
    s.on('close', done)
  })

// ---------------------------------------------------------------- Products from banners

const PRODUCTS: { re: RegExp; name: string; cpe: [string, string][] }[] = [
  { re: /OpenSSH[_ ](\d+\.\d+(?:p\d+)?)/i, name: 'OpenSSH', cpe: [['openbsd', 'openssh']] },
  { re: /\bnginx\/?\s?(\d+\.\d+\.\d+)/i, name: 'nginx', cpe: [['f5', 'nginx'], ['nginx', 'nginx']] },
  { re: /Apache(?: httpd)?\/?\s?(\d+\.\d+\.\d+)/i, name: 'Apache HTTP Server', cpe: [['apache', 'http_server']] },
  { re: /ProFTPD\s+(\d+\.\d+\.\d+[a-z]?)/i, name: 'ProFTPD', cpe: [['proftpd', 'proftpd']] },
  { re: /vsftpd\s+(\d+\.\d+\.\d+)/i, name: 'vsftpd', cpe: [['vsftpd_project', 'vsftpd'], ['beasts', 'vsftpd']] },
  { re: /Pure-?FTPd\s+(\d+\.\d+\.\d+)/i, name: 'Pure-FTPd', cpe: [['pureftpd', 'pure-ftpd']] },
  { re: /Exim(?: smtpd)?\s+(\d+\.\d+(?:\.\d+)?)/i, name: 'Exim', cpe: [['exim', 'exim']] },
  { re: /Postfix(?: smtpd)?\s+(\d+\.\d+\.\d+)/i, name: 'Postfix', cpe: [['postfix', 'postfix']] },
  { re: /MySQL\s+(\d+\.\d+\.\d+)/i, name: 'MySQL', cpe: [['oracle', 'mysql']] },
  { re: /MariaDB\s+(\d+\.\d+\.\d+)/i, name: 'MariaDB', cpe: [['mariadb', 'mariadb']] },
  { re: /PostgreSQL(?: DB)?\s+(\d+\.\d+(?:\.\d+)?)/i, name: 'PostgreSQL', cpe: [['postgresql', 'postgresql']] },
  { re: /Redis(?: key-value store)?\s+(\d+\.\d+\.\d+)/i, name: 'Redis', cpe: [['redis', 'redis'], ['redislabs', 'redis']] },
  { re: /MongoDB\s+(\d+\.\d+\.\d+)/i, name: 'MongoDB', cpe: [['mongodb', 'mongodb']] },
  { re: /Microsoft IIS(?: httpd)?\s+(\d+\.\d+)/i, name: 'Microsoft IIS', cpe: [['microsoft', 'internet_information_services']] },
  { re: /lighttpd\/?\s?(\d+\.\d+\.\d+)/i, name: 'lighttpd', cpe: [['lighttpd', 'lighttpd']] },
  { re: /Samba(?: smbd)?\s+(\d+\.\d+\.\d+)/i, name: 'Samba', cpe: [['samba', 'samba']] },
  { re: /Dropbear(?: sshd)?\s+(?:sshd\s+)?(?:v)?(20\d\d\.\d+)/i, name: 'Dropbear SSH', cpe: [['dropbear_ssh_project', 'dropbear_ssh']] },
  { re: /Elasticsearch\s+(\d+\.\d+\.\d+)/i, name: 'Elasticsearch', cpe: [['elastic', 'elasticsearch']] },
  { re: /Tomcat\/?\s?(\d+\.\d+\.\d+)/i, name: 'Apache Tomcat', cpe: [['apache', 'tomcat']] }
]

const proofOfBanner = (host: string, port: number, sent: string | null, text: string, shows: string[]): Proof => ({
  request: sent === null ? `TCP connect ${host}:${port}` : `TCP ${host}:${port}, sent ${JSON.stringify(sent.trim().slice(0, 60))}`,
  reproduce: sent === null ? `nc -w 4 ${host} ${port}` : `printf '${sent.replace(/\r/g, '\\r').replace(/\n/g, '\\n')}' | nc -w 4 ${host} ${port}`,
  status: 0,
  bytes: Buffer.byteLength(text),
  sha256: createHash('sha256').update(text).digest('hex'),
  at: new Date().toISOString(),
  shows: shows.slice(0, 8).map((s) => s.slice(0, 200))
})

/** Products that a banner or Nmap's product text states. Nothing is guessed: no version in the text, no product. */
export function productsFrom(text: string, host: string, port: number, sent: string | null = null): Product[] {
  const out: Product[] = []
  for (const p of PRODUCTS) {
    const m = p.re.exec(text)
    if (m) out.push({ name: p.name, version: m[1], cpe: p.cpe, from: `the service on port ${port} says: ${text.replace(/\s+/g, ' ').trim().slice(0, 100)}`, proof: proofOfBanner(host, port, sent, text, [`port ${port} answered: ${text.replace(/\s+/g, ' ').trim().slice(0, 120)}`]) })
  }
  return out
}

// ---------------------------------------------------------------- Data stores that answer without a password

interface Probe {
  id: string
  ports: number[]
  service?: RegExp
  send: string
  ok: (answer: string) => boolean
  title: (p: number) => string
  severity: Finding['severity']
  what: string
  fix: string
}

const HTTP = (path: string, host: string): string => `GET ${path} HTTP/1.0\r\nHost: ${host}\r\nUser-Agent: MacSec\r\nConnection: close\r\n\r\n`

const probes = (host: string): Probe[] => [
  { id: 'redis', ports: [6379], service: /redis/i, send: 'PING\r\n', ok: (a) => /^\+PONG/.test(a), title: (p) => `Redis on port ${p} answers without a password`, severity: 'critical', what: 'It replied +PONG to a plain PING with no sign-in. Anyone who can reach this port can read and change everything in it, and often take over the server.', fix: 'Bind Redis to localhost or a private network, set requirepass (or ACLs), and block the port in the firewall.' },
  { id: 'memcached', ports: [11211], service: /memcache/i, send: 'version\r\n', ok: (a) => /^VERSION \d/.test(a), title: (p) => `Memcached on port ${p} answers without a password`, severity: 'high', what: 'It reported its version to anyone who asked. Memcached has no sign-in at all, and open instances are used to attack other sites and to read cached data.', fix: 'Bind it to localhost or a private network and block the port in the firewall.' },
  { id: 'elasticsearch', ports: [9200], service: /elastic/i, send: HTTP('/', host), ok: (a) => /"cluster_name"\s*:/.test(a) && /"tagline"\s*:\s*"You Know, for Search"/.test(a), title: (p) => `Elasticsearch on port ${p} is open without sign-in`, severity: 'critical', what: 'Its home page answered with its cluster name to a request with no credentials. Open Elasticsearch servers leak whole databases.', fix: 'Turn on security (sign-in and TLS), bind it to a private network and block the port.' },
  { id: 'couchdb', ports: [5984], service: /couch/i, send: HTTP('/', host), ok: (a) => /"couchdb"\s*:\s*"Welcome"/.test(a), title: (p) => `CouchDB on port ${p} is open without sign-in`, severity: 'high', what: 'It answered its welcome message with no credentials. Without an admin password the server can be taken over.', fix: 'Set an admin password, require sign-in and block the port from the internet.' },
  { id: 'docker', ports: [2375], service: /docker/i, send: HTTP('/version', host), ok: (a) => /"ApiVersion"\s*:\s*"/.test(a) && /"Os"\s*:/.test(a), title: (p) => `The Docker API on port ${p} is open without sign-in`, severity: 'critical', what: 'It answered the version page with no credentials. Anyone who can reach it can start containers and take over the host.', fix: 'Never expose the Docker API on a network. Use the local socket, or TLS with client certificates, and block the port.' }
]

export interface ServiceFindings {
  findings: Finding[]
  products: { product: Product; host: string; port: number }[]
}

export async function probeServices(ports: OpenPort[], o: { talk?: Talk; note?: (t: string) => void; cancelled?: () => boolean } = {}): Promise<ServiceFindings> {
  const talk = o.talk ?? tcpTalk
  const out: ServiceFindings = { findings: [], products: [] }
  for (const p of ports) {
    if (o.cancelled?.()) break
    const known = productsFrom(`${p.service ?? ''} ${p.product ?? ''}`, p.host, p.port)
    for (const k of known) out.products.push({ product: k, host: p.host, port: p.port })
    // Banner services speak first: SSH and FTP and SMTP show their version at once.
    if ([21, 22, 25, 110, 143, 587].includes(p.port) || /ssh|ftp|smtp|pop3|imap/i.test(p.service ?? '')) {
      const banner = await talk(p.host, p.port, null)
      if (banner) {
        o.note?.(`${p.host}:${p.port} says ${banner.replace(/\s+/g, ' ').slice(0, 60)}`)
        if (!known.length) for (const k of productsFrom(banner, p.host, p.port)) out.products.push({ product: k, host: p.host, port: p.port })
        if (/^SSH-1\.(5|33|99)?-/.test(banner) && !/^SSH-1\.99-/.test(banner))
          out.findings.push({ id: fid('ssh1', p.host, p.port), tool: 'MacSec', category: 'network', severity: 'high', confidence: 'confirmed', title: `SSH on port ${p.port} still speaks the old protocol 1`, url: `${p.host}:${p.port}`, file: `${p.host}:${p.port}`, cwe: 'CWE-327', description: 'Its banner starts with SSH-1, a protocol with known weaknesses that was replaced long ago.', fix: 'Allow only SSH protocol 2 (Protocol 2 in sshd_config) and update OpenSSH.', proof: proofOfBanner(p.host, p.port, null, banner, [`the banner is ${banner.trim().slice(0, 60)}`]) })
      }
    }
    for (const pr of probes(p.host)) {
      if (!(pr.ports.includes(p.port) || (p.service && pr.service?.test(p.service)))) continue
      const ask = async (): Promise<string> => talk(p.host, p.port, pr.send)
      const a = await ask()
      if (!pr.ok(a)) continue
      const b = await ask()
      if (!pr.ok(b)) continue
      out.findings.push({ id: fid('open-store', pr.id, p.host, p.port), tool: 'MacSec', category: 'network', severity: pr.severity, confidence: 'confirmed', title: pr.title(p.port), url: `${p.host}:${p.port}`, file: `${p.host}:${p.port}`, cwe: 'CWE-306', description: pr.what, fix: pr.fix, proof: proofOfBanner(p.host, p.port, pr.send, a, [`the answer was ${a.replace(/\s+/g, ' ').trim().slice(0, 100)}`, 'no password or token was sent', 'the same answer came twice']) })
      for (const k of productsFrom(a, p.host, p.port, pr.send)) out.products.push({ product: k, host: p.host, port: p.port })
    }
  }
  return out
}

// ---------------------------------------------------------------- Web services behind open ports

const WEB_PORTS = [80, 81, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9443]
const TLS_PORTS = [443, 8443, 9443]

/** The web services among the open ports, as addresses the web checks can read. */
export function webServices(ports: OpenPort[]): { host: string; url: string; status: number }[] {
  return ports
    .filter((p) => WEB_PORTS.includes(p.port) || /http/i.test(p.service ?? ''))
    .map((p) => {
      const tls = TLS_PORTS.includes(p.port) || /ssl|https/i.test(p.service ?? '')
      return { host: `${p.host}:${p.port}`, url: `${tls ? 'https' : 'http'}://${p.host}:${p.port}`, status: 200 }
    })
}

export const deepWeb = (ports: OpenPort[], o: DeepOptions): Promise<Finding[]> => deepHosts(webServices(ports), { ...o, skipDns: true })
