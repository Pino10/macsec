/**
 * Cloud accounts and servers: ScoutSuite and PMapper results, open ports from naabu and the
 * services Nmap names on them, and WPScan's WordPress report. All of these tools only read.
 */
import type { Finding, Severity } from '../../shared/types'
import { fid, sev } from './parse'

// ---------------------------------------------------------------- ScoutSuite

interface ScoutFinding {
  description?: string
  level?: string
  flagged_items?: number
  checked_items?: number
  items?: string[]
  rationale?: string
  remediation?: string
  references?: string[]
  service?: string
}

/** ScoutSuite writes its results as a JavaScript file: "scoutsuite_results =" then JSON. */
export function parseScoutSuite(text: string): Finding[] {
  let data: { services?: Record<string, { findings?: Record<string, ScoutFinding> }>; provider_name?: string }
  try {
    data = JSON.parse(text.slice(text.indexOf('{')))
  } catch {
    return []
  }
  const out: Finding[] = []
  for (const [service, svc] of Object.entries(data.services ?? {})) {
    for (const [key, f] of Object.entries(svc.findings ?? {})) {
      if (!f.flagged_items) continue
      const severity: Severity = f.level === 'danger' ? 'high' : f.level === 'warning' ? 'medium' : 'low'
      const items = (f.items ?? []).map((i) => i.split('.').slice(-3).join('.'))
      out.push({
        id: fid('scout', key),
        tool: 'ScoutSuite',
        category: 'cloud',
        severity,
        title: `${f.description ?? key} (${f.flagged_items} of ${f.checked_items ?? '?'})`,
        file: service,
        description: [f.rationale?.replace(/<[^>]+>/g, ''), items.length ? `Affected: ${items.slice(0, 15).join(', ')}${items.length > 15 ? ` and ${items.length - 15} more` : ''}` : ''].filter(Boolean).join('\n\n'),
        fix: f.remediation?.replace(/<[^>]+>/g, ''),
        url: f.references?.[0]
      })
    }
  }
  return out
}

// ---------------------------------------------------------------- PMapper

export function parsePmapper(text: string): Finding[] {
  let data: { findings?: { title?: string; severity?: string; impact?: string; description?: string; recommendation?: string }[] }
  try {
    data = JSON.parse(text.slice(text.indexOf('{')))
  } catch {
    return []
  }
  return (data.findings ?? []).map((f, i) => ({
    id: fid('pmapper', f.title, i),
    tool: 'PMapper',
    category: 'cloud' as const,
    severity: sev(f.severity),
    title: f.title ?? 'IAM finding',
    description: [f.impact, f.description].filter(Boolean).join('\n\n'),
    fix: f.recommendation
  }))
}

// ---------------------------------------------------------------- Ports

export interface OpenPort {
  host: string
  port: number
  service?: string
  product?: string
}

export function parseNaabu(jsonl: string): OpenPort[] {
  const out: OpenPort[] = []
  for (const line of jsonl.split('\n')) {
    if (!line.trim().startsWith('{')) continue
    try {
      const r = JSON.parse(line) as { host?: string; ip?: string; port?: number | { Port?: number; port?: number } }
      const port = typeof r.port === 'number' ? r.port : (r.port?.Port ?? r.port?.port)
      if (port) out.push({ host: r.host || r.ip || '', port })
    } catch {
      // Progress lines.
    }
  }
  return out.filter((p, i) => out.findIndex((q) => q.port === p.port && q.host === p.host) === i).sort((a, b) => a.port - b.port)
}

/** The service and version Nmap saw on each open port, from its XML report. */
export function parseNmapXml(xml: string): OpenPort[] {
  const host = /<address addr="([^"]+)"/.exec(xml)?.[1] ?? ''
  const out: OpenPort[] = []
  for (const m of xml.matchAll(/<port protocol="tcp" portid="(\d+)">([\s\S]*?)<\/port>/g)) {
    if (!/<state state="open"/.test(m[2])) continue
    const svc = /<service\b([^>]*)>|<service\b([^>]*)\/>/.exec(m[2])
    const a = svc?.[1] ?? svc?.[2] ?? ''
    const get = (k: string): string | undefined => new RegExp(`${k}="([^"]*)"`).exec(a)?.[1]
    out.push({ host, port: Number(m[1]), service: get('name'), product: [get('product'), get('version')].filter(Boolean).join(' ') || undefined })
  }
  return out
}

const RISKY: Record<number, [string, Severity, string]> = {
  21: ['FTP', 'medium', 'FTP sends passwords and files unencrypted.'],
  23: ['Telnet', 'high', 'Telnet sends everything, including passwords, unencrypted.'],
  25: ['SMTP', 'low', 'A mail server is reachable. Make sure it does not relay mail for anyone.'],
  111: ['RPC portmapper', 'medium', 'RPC services can reveal and expose internal services.'],
  135: ['Windows RPC', 'high', 'Windows RPC should never be reachable from the internet.'],
  139: ['NetBIOS', 'high', 'Windows file sharing should never be reachable from the internet.'],
  445: ['SMB', 'high', 'Windows file sharing should never be reachable from the internet.'],
  1433: ['SQL Server', 'high', 'The database can be reached directly.'],
  1521: ['Oracle', 'high', 'The database can be reached directly.'],
  2049: ['NFS', 'high', 'Network file shares can be reached.'],
  2375: ['Docker API (no TLS)', 'critical', 'The unencrypted Docker API gives full control of the server to anyone who reaches it.'],
  2379: ['etcd', 'critical', 'etcd holds cluster secrets and configuration.'],
  3306: ['MySQL', 'high', 'The database can be reached directly.'],
  3389: ['Remote Desktop', 'high', 'Remote Desktop is a common way in for attackers.'],
  5432: ['PostgreSQL', 'high', 'The database can be reached directly.'],
  5900: ['VNC', 'high', 'Remote screen sharing is reachable.'],
  5984: ['CouchDB', 'high', 'The database can be reached directly.'],
  6379: ['Redis', 'critical', 'Redis usually has no password and can be used to take over the server.'],
  8500: ['Consul', 'high', 'Consul can expose configuration and run commands.'],
  9200: ['Elasticsearch', 'high', 'Search data can often be read without signing in.'],
  10250: ['Kubernetes kubelet', 'critical', 'The kubelet API can run commands in containers.'],
  11211: ['Memcached', 'high', 'Cached data can be read, and the server abused for attacks.'],
  27017: ['MongoDB', 'critical', 'MongoDB is often reachable without a password.']
}

/** One finding per open port: risky services by their usual port or the service Nmap named. */
export function portFindings(ports: OpenPort[], local: boolean): Finding[] {
  return ports.map((p) => {
    const byName = Object.entries(RISKY).find(([, [name]]) => p.service && name.toLowerCase().startsWith(p.service.toLowerCase()))
    const risk = RISKY[p.port] ?? byName?.[1]
    const what = p.product ? `${p.service ?? ''} ${p.product}`.trim() : (p.service ?? risk?.[0] ?? 'unknown service')
    // On your own Mac, a database port is normal for development: lower it.
    const severity: Severity = risk ? (local && risk[1] !== 'critical' ? 'low' : local ? 'medium' : risk[1]) : 'info'
    return {
      id: fid('port', p.host, p.port),
      tool: p.product || p.service ? 'Nmap' : 'naabu',
      category: 'network' as const,
      severity,
      title: risk ? `${risk[0]} is open on port ${p.port}` : `Port ${p.port} is open (${what})`,
      url: `${p.host}:${p.port}`,
      description: [risk?.[2], p.product ? `Nmap saw: ${what}.` : ''].filter(Boolean).join(' ') || 'An open port. Check it is meant to be reachable.',
      fix: risk ? 'Close the port in the firewall, or allow only the addresses that need it (a VPN or an allow list). Never expose databases and admin services to the internet.' : undefined
    }
  })
}

// ---------------------------------------------------------------- WPScan

interface WpVuln {
  title?: string
  cvss?: { score?: number | string }
  fixed_in?: string
  references?: { url?: string[]; cve?: string[] }
}
interface WpPart {
  slug?: string
  version?: { number?: string } | null
  outdated?: boolean
  latest_version?: string | null
  vulnerabilities?: WpVuln[]
}

export function parseWpscan(text: string, site: string): Finding[] {
  let d: { version?: { number?: string; status?: string; vulnerabilities?: WpVuln[] } | null; main_theme?: WpPart | null; plugins?: Record<string, WpPart>; themes?: Record<string, WpPart>; interesting_findings?: { to_s?: string; url?: string; type?: string }[]; config_backups?: Record<string, unknown>; db_exports?: Record<string, unknown> }
  try {
    d = JSON.parse(text)
  } catch {
    return []
  }
  const out: Finding[] = []
  const vulns = (what: string, list: WpVuln[] | undefined): void => {
    for (const v of list ?? []) {
      const cve = v.references?.cve?.[0]
      out.push({ id: fid('wp', what, v.title), tool: 'WPScan', category: 'web', severity: v.cvss?.score !== undefined ? sev(v.cvss.score) : 'high', title: `${what}: ${v.title ?? 'known vulnerability'}`, url: site, advisory: cve ? `CVE-${cve}` : undefined, description: v.fixed_in ? `Fixed in ${v.fixed_in}.` : 'No fixed version listed.', fix: v.fixed_in ? `Update to ${v.fixed_in} or later.` : 'Remove it or replace it with a maintained alternative.' })
    }
  }
  if (d.version?.number) {
    vulns(`WordPress ${d.version.number}`, d.version.vulnerabilities)
    if (d.version.status === 'insecure' || d.version.status === 'outdated') out.push({ id: fid('wp', 'core'), tool: 'WPScan', category: 'web', severity: d.version.status === 'insecure' ? 'high' : 'medium', title: `WordPress ${d.version.number} is ${d.version.status}`, url: site, fix: 'Update WordPress from Dashboard, Updates.' })
  }
  const parts: [string, WpPart][] = [...Object.entries(d.plugins ?? {}).map(([k, v]) => [`Plugin ${k}`, v] as [string, WpPart]), ...Object.entries(d.themes ?? {}).map(([k, v]) => [`Theme ${k}`, v] as [string, WpPart]), ...(d.main_theme ? [[`Theme ${d.main_theme.slug}`, d.main_theme] as [string, WpPart]] : [])]
  for (const [name, p] of parts) {
    vulns(`${name} ${p.version?.number ?? ''}`.trim(), p.vulnerabilities)
    if (p.outdated) out.push({ id: fid('wp', name, 'outdated'), tool: 'WPScan', category: 'web', severity: 'low', title: `${name} is out of date (${p.version?.number ?? '?'}, latest ${p.latest_version ?? '?'})`, url: site, fix: 'Update it from Dashboard, Updates.' })
  }
  for (const f of d.interesting_findings ?? []) {
    if (!f.to_s || /^(Headers|robots\.txt found|The external WP-Cron)/i.test(f.to_s)) continue
    out.push({ id: fid('wp', f.to_s), tool: 'WPScan', category: 'web', severity: /debug|backup|upload directory has listing|full path/i.test(f.to_s) ? 'medium' : 'info', title: f.to_s.split('\n')[0].slice(0, 160), url: f.url ?? site })
  }
  for (const url of [...Object.keys(d.config_backups ?? {}), ...Object.keys(d.db_exports ?? {})]) out.push({ id: fid('wp', url), tool: 'WPScan', category: 'web', severity: 'critical', title: 'A configuration or database backup can be downloaded', url, fix: 'Delete the file from the server now, and change the database password and keys it contains.' })
  return out
}
