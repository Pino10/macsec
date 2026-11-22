/**
 * Check ids, like the plugin ids in a commercial scanner: every kind of finding MacSec can make has a
 * short, stable id, so a report can say "check MS-WEB-014 failed" and a re-test can look for the same one.
 * The id comes from what the finding is about, never from the target, so it is the same on every scan.
 */
import { createHash } from 'crypto'
import type { Finding } from '../shared/types'

export interface CheckDef {
  id: string
  re: RegExp
  name: string
  /** OWASP Top 10 (2021) category, for the compliance view. */
  owasp?: string
}

export const CHECKS: CheckDef[] = [
  { id: 'MS-WEB-001', re: /^Hidden page found|^Hidden page exists/i, name: 'Hidden page discovery', owasp: 'A05' },
  { id: 'MS-WEB-002', re: /^Public file found by discovery|^Exposed file|is public$/i, name: 'File that should not be public', owasp: 'A05' },
  { id: 'MS-WEB-003', re: /^Folder lists its files/i, name: 'Directory listing', owasp: 'A05' },
  { id: 'MS-WEB-004', re: /^Hidden parameter/i, name: 'Hidden parameter discovery', owasp: 'A04' },
  { id: 'MS-WEB-005', re: /^Input comes back in the page without escaping/i, name: 'Reflected input (cross-site scripting lead)', owasp: 'A03' },
  { id: 'MS-WEB-006', re: /^Firewall bypass confirmed/i, name: 'Web firewall bypass', owasp: 'A05' },
  { id: 'MS-WEB-007', re: /^Web firewall in front|^Protected by|^No web firewall/i, name: 'Firewall and CDN detection' },
  { id: 'MS-AUTH-001', re: /^Login shows which usernames exist/i, name: 'User enumeration on login', owasp: 'A07' },
  { id: 'MS-AUTH-002', re: /^Password reset shows which emails/i, name: 'User enumeration on password reset', owasp: 'A07' },
  { id: 'MS-AUTH-003', re: /^Login does not slow down/i, name: 'No limit on wrong passwords', owasp: 'A07' },
  { id: 'MS-AUTH-004', re: /^A code form accepts ten wrong codes/i, name: 'No limit on wrong one-time codes', owasp: 'A07' },
  { id: 'MS-AUTHZ-001', re: /^Another account can open/i, name: 'Another account can open a private page', owasp: 'A01' },
  { id: 'MS-AUTHZ-002', re: /^Shows the same content when signed out/i, name: 'Private page open when signed out', owasp: 'A01' },
  { id: 'MS-INJ-001', re: /^A quote in ".*" makes the page show a database error/i, name: 'SQL injection sign (database error)', owasp: 'A03' },
  { id: 'MS-INJ-002', re: /^The server calculates an expression/i, name: 'Server-side template injection', owasp: 'A03' },
  { id: 'MS-INJ-003', re: /^A line break in ".*" is written into a response header/i, name: 'Header injection (CRLF)', owasp: 'A03' },
  { id: 'MS-INJ-004', re: /forms? sends? data and (was|were) not tested/i, name: 'Forms that send data (not tested)', owasp: 'A03' },
  { id: 'MS-LOGIC-001', re: /^Open redirect/i, name: 'Open redirect', owasp: 'A01' },
  { id: 'MS-LOGIC-002', re: /^The site trusts a forwarded host/i, name: 'Host header poisoning', owasp: 'A05' },
  { id: 'MS-LOGIC-003', re: /^The browser sends values the server should decide/i, name: 'Values trusted from the browser', owasp: 'A04' },
  { id: 'MS-LOGIC-004', re: /^A late step opens without the earlier steps/i, name: 'Skipped step in a flow', owasp: 'A04' },
  { id: 'MS-LOGIC-005', re: /^Records are numbered in the address/i, name: 'Guessable record ids', owasp: 'A01' },
  { id: 'MS-JS-001', re: /^Source map public/i, name: 'Public source map', owasp: 'A05' },
  { id: 'MS-JS-002', re: /in the original source|in public JavaScript/i, name: 'Key in front-end code', owasp: 'A02' },
  { id: 'MS-JS-003', re: /^The front end names \d+ routes/i, name: 'Front-end routes', owasp: 'A01' },
  { id: 'MS-JS-004', re: /^Message listeners that never check/i, name: 'postMessage without origin check', owasp: 'A03' },
  { id: 'MS-JS-005', re: /^Internal or development addresses/i, name: 'Internal addresses in scripts', owasp: 'A05' },
  { id: 'MS-JS-006', re: /^Browser functions that turn text into code/i, name: 'Dangerous browser functions', owasp: 'A03' },
  { id: 'MS-INFRA-001', re: /points at .*but the target no longer answers/i, name: 'Dangling CNAME (takeover)', owasp: 'A05' },
  { id: 'MS-INFRA-002', re: /SPF record|no SPF/i, name: 'SPF record', owasp: 'A05' },
  { id: 'MS-INFRA-003', re: /DMARC/i, name: 'DMARC record', owasp: 'A05' },
  { id: 'MS-INFRA-004', re: /no CAA record/i, name: 'CAA record' },
  { id: 'MS-DEVOPS-001', re: /Jenkins/i, name: 'Jenkins exposed', owasp: 'A05' },
  { id: 'MS-DEVOPS-002', re: /Grafana|Prometheus|Kibana|metrics are public/i, name: 'Monitoring tool exposed', owasp: 'A05' },
  { id: 'MS-DEVOPS-003', re: /Elasticsearch|etcd|Consul|RabbitMQ|SonarQube/i, name: 'Data or service tool exposed', owasp: 'A05' },
  { id: 'MS-DEVOPS-004', re: /Kubernetes|Docker|container registry|Traefik|Argo CD|Portainer/i, name: 'Container or cluster tool exposed', owasp: 'A05' },
  { id: 'MS-DEVOPS-005', re: /Terraform|AWS credentials|Docker registry logins|\.netrc|PyPI upload/i, name: 'Infrastructure secrets exposed', owasp: 'A02' },
  { id: 'MS-DEVOPS-006', re: /pipeline|Pipelines|CircleCI|Travis|CodeBuild|GitHub Actions workflow|Serverless config/i, name: 'CI or deploy file exposed', owasp: 'A05' },
  { id: 'MS-DEVOPS-007', re: /\.git (folder|\/config)|public \.git/i, name: 'Git folder exposed', owasp: 'A05' },
  { id: 'MS-CVE-001', re: /matches \d+ known flaws?/i, name: 'Software version with known flaws', owasp: 'A06' },
  { id: 'MS-TLS-001', re: /certificate|TLS 1\.|TLSv1/i, name: 'Certificate and TLS settings', owasp: 'A02' },
  { id: 'MS-HDR-001', re: /Strict-Transport|Content-Security-Policy|X-Frame|X-Content-Type|Referrer-Policy|Permissions-Policy|Cookie ".*" is missing|HTTPS/i, name: 'Security headers and cookies', owasp: 'A05' },
  { id: 'MS-MOB-001', re: /pinning/i, name: 'Certificate pinning', owasp: 'M5' },
  { id: 'MS-MOB-002', re: /signed with|signature scheme|debug certificate/i, name: 'App signing', owasp: 'M7' },
  { id: 'MS-MOB-003', re: /root|jailbr/i, name: 'Root and jailbreak checks', owasp: 'M8' },
  { id: 'MS-MOB-004', re: /storage bucket|Firebase database/i, name: 'Open cloud storage named in an app', owasp: 'M2' }
]

/** The id of the check that makes this kind of finding. Unknown kinds get a stable id from their wording. */
export function checkIdOf(f: Pick<Finding, 'title' | 'tool' | 'category'>): string {
  for (const c of CHECKS) if (c.re.test(f.title)) return c.id
  const shape = `${f.tool}|${f.category}|${f.title.replace(/https?:\/\/\S+|\/\S+|\d+/g, '#').toLowerCase().slice(0, 80)}`
  return `MS-GEN-${createHash('sha1').update(shape).digest('hex').slice(0, 6).toUpperCase()}`
}

export const checkName = (id: string): string => CHECKS.find((c) => c.id === id)?.name ?? 'Scanner rule'
