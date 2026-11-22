/**
 * The setup behind a site, read the way a Nessus or Rapid7 scan reads it:
 *
 *   Protection      which web firewall or CDN answers, and what hosts the site
 *   DNS and mail    SPF, DMARC, CAA, and a CNAME that points at a service nobody owns any more
 *   DevOps          build servers, dashboards, registries, cluster APIs, state files and CI files
 *                   that are reachable from the internet, each recognised by what the answer
 *                   contains (never by the status code alone) and repeated once before it is reported
 *   GitHub          the repository a public .git folder names, and passwords written in its address
 *
 * Plain GET requests through ConfirmClient: this site only, a request cap, a pause between requests,
 * a stop when the server struggles. Nothing is changed, nothing is guessed, no login is tried.
 */
import { promises as dnsp } from 'dns'
import { createHash } from 'crypto'
import type { Finding, Severity } from '../shared/types'
import { ConfirmClient, Stop } from './confirmtests'
import { fid } from './scanners/parse'
import { detectWaf, fileShows, proofOf, type HeaderLike, type Product, type Proof } from './seckit/confirm'
import { takeoverService } from './seckit/recon'

const f = (x: Omit<Finding, 'id' | 'tool' | 'category'>, key: string): Finding => ({ id: fid('posture', x.title, x.url ?? x.file ?? '', key), tool: 'MacSec', category: 'web', ...x })

// ---------------------------------------------------------------- Protection and hosting

const HOSTING: [string, (h: HeaderLike) => string | null][] = [
  ['Amazon S3', (h) => (/^AmazonS3$/i.test(h.get('server') ?? '') ? 'Server header says AmazonS3' : null)],
  ['Amazon (load balancer)', (h) => (/awselb/i.test(h.get('server') ?? '') ? 'Server header says awselb' : null)],
  ['Google Cloud', (h) => (/^(gws|ESF|Google Frontend)$/i.test(h.get('server') ?? '') || h.get('x-cloud-trace-context') ? 'a Google front end answered' : null)],
  ['Microsoft Azure', (h) => (h.get('x-ms-request-id') || h.get('x-azure-ref') ? 'an Azure header is present' : null)],
  ['GitHub Pages', (h) => (h.get('x-github-request-id') ? 'header x-github-request-id is present' : null)],
  ['Fly.io', (h) => (h.get('fly-request-id') ? 'header fly-request-id is present' : null)],
  ['Heroku', (h) => (/heroku/i.test(h.get('via') ?? '') ? 'Via header names Heroku' : null)],
  ['Render', (h) => (h.get('rndr-id') ? 'header rndr-id is present' : null)],
  ['Railway', (h) => (/railway/i.test(h.get('server') ?? '') ? 'Server header says railway' : null)],
  ['DigitalOcean App Platform', (h) => (h.get('x-do-app-origin') ? 'header x-do-app-origin is present' : null)]
]

/** The protection in front of a site and the platform it runs on, from the headers of an ordinary page. */
export function protectionOf(headers: HeaderLike, cookies = ''): { waf: { name: string; shows: string[] }[]; hosting: { name: string; shows: string }[]; server?: string } {
  const hosting: { name: string; shows: string }[] = []
  for (const [name, test] of HOSTING) {
    const s = test(headers)
    if (s) hosting.push({ name, shows: s })
  }
  return { waf: detectWaf(headers, cookies), hosting, server: headers.get('server') ?? undefined }
}

export function protectionFinding(url: string, headers: HeaderLike, cookies: string, status: number, body: string): Finding {
  const p = protectionOf(headers, cookies)
  const names = [...p.waf.map((w) => w.name), ...p.hosting.map((h) => h.name)]
  const shows = [...p.waf.flatMap((w) => w.shows.map((s) => `${w.name}: ${s}`)), ...p.hosting.map((h) => `${h.name}: ${h.shows}`), p.server ? `Server header: ${p.server.slice(0, 60)}` : ''].filter(Boolean)
  return f({
    severity: 'info',
    confidence: 'confirmed',
    title: p.waf.length ? `Protected by ${p.waf.map((w) => w.name).join(' and ')}` : 'No web firewall or CDN was recognised',
    url,
    file: url,
    description: p.waf.length
      ? `${names.join(', ')} answered for this site, so findings on it may be filtered, rate limited or blocked for some requests. A firewall slows attackers but does not fix the code behind it, and the real server may still answer directly if its address is known.${p.server ? ` Server header: ${p.server}.` : ''}`
      : `No known firewall or CDN signature was seen in an ordinary answer. That does not prove there is none: some firewalls only show themselves when they block a request (the optional firewall test in control confirmations checks that).${p.server ? ` Server header: ${p.server}.` : ''}`,
    proof: proofOf({ url, status, headers, body: body.slice(0, 20000), shows: shows.length ? shows : ['none of the known CDN or firewall headers or cookies were present'] })
  }, 'protect')
}

// ---------------------------------------------------------------- DNS and mail

export interface Resolver {
  resolveTxt(h: string): Promise<string[][]>
  resolveCname(h: string): Promise<string[]>
  resolve4(h: string): Promise<string[]>
  resolveCaa?(h: string): Promise<{ critical: number; issue?: string }[]>
  resolveMx(h: string): Promise<{ exchange: string; priority: number }[]>
}

const SECOND = /^(co|com|org|net|gov|ac|edu)\.[a-z]{2}$/
export function rootDomain(host: string): string {
  const parts = host.toLowerCase().split('.')
  if (parts.length <= 2) return host.toLowerCase()
  return SECOND.test(parts.slice(-2).join('.')) ? parts.slice(-3).join('.') : parts.slice(-2).join('.')
}

const dnsProof = (what: string, cmd: string, shows: string[], body = ''): Proof => ({ request: what, reproduce: cmd, status: 0, bytes: Buffer.byteLength(body), sha256: createHash('sha256').update(body).digest('hex'), at: new Date().toISOString(), shows })
const never = async <T>(p: Promise<T>, empty: T): Promise<T> => p.catch(() => empty)

/** DNS and mail settings for a site's own domain, plus a dangling CNAME on the host itself. */
export async function dnsChecks(host: string, r: Resolver = dnsp as unknown as Resolver): Promise<Finding[]> {
  const out: Finding[] = []
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || /^localhost$|\.(test|localhost|local)$/.test(host)) return out
  const root = rootDomain(host)

  const cname = (await never(r.resolveCname(host), [] as string[]))[0]
  if (cname) {
    const service = takeoverService(cname)
    const alive = (await never(r.resolve4(cname), [] as string[])).length > 0
    if (service && !alive) out.push(f({ severity: 'high', confidence: 'possible', title: `${host} points at ${service}, but the target no longer answers`, file: host, cwe: 'CWE-1390', description: `${host} is a CNAME for ${cname}, and ${cname} has no address. If the ${service} resource was deleted, anyone can create it again under the same name and serve content on ${host}. Whether the name can really be claimed depends on the service: check by trying to create it in your own account.`, fix: `Delete the DNS record for ${host}, or create the ${service} resource again so the name is yours.`, proof: dnsProof(`DNS CNAME ${host}`, `dig +short CNAME ${host}; dig +short ${cname}`, [`${host} is a CNAME for ${cname}`, `${cname} has no A record`, `${service} is a service where deleted names can be claimed`]) }, 'cname'))
  }

  const txt = (await never(r.resolveTxt(root), [] as string[][])).map((x) => x.join(''))
  const mx = await never(r.resolveMx(root), [] as { exchange: string; priority: number }[])
  const spf = txt.find((t) => /^v=spf1\b/i.test(t))
  if (mx.length || spf) {
    if (!spf) out.push(f({ severity: 'low', confidence: 'confirmed', title: `${root} has mail servers but no SPF record`, file: root, cwe: 'CWE-290', description: 'Without SPF, anyone can send email that claims to come from this domain and receivers have no way to tell.', fix: 'Publish a TXT record such as "v=spf1 include:<your mail provider> -all".', proof: dnsProof(`DNS TXT ${root}`, `dig +short TXT ${root}`, [`${mx.length} MX records exist`, 'no TXT record starts with v=spf1'], txt.join('\n')) }, 'spf'))
    else if (/(^|\s)\+all\b|\s\?all\b/.test(spf)) out.push(f({ severity: 'medium', confidence: 'confirmed', title: `The SPF record of ${root} allows every sender`, file: root, cwe: 'CWE-290', description: 'The record ends in +all or ?all, so it does not stop anyone from sending as this domain.', fix: 'End the record with -all (or ~all while you test).', proof: dnsProof(`DNS TXT ${root}`, `dig +short TXT ${root}`, [`SPF: ${spf.slice(0, 120)}`], spf) }, 'spf-open'))
    const dmarc = (await never(r.resolveTxt(`_dmarc.${root}`), [] as string[][])).map((x) => x.join('')).find((t) => /^v=DMARC1/i.test(t))
    if (!dmarc) out.push(f({ severity: 'low', confidence: 'confirmed', title: `${root} has no DMARC record`, file: root, cwe: 'CWE-290', description: 'DMARC tells receivers to reject mail that fails SPF and DKIM. Without it, spoofed mail from this domain is usually delivered.', fix: 'Publish _dmarc TXT "v=DMARC1; p=quarantine; rua=mailto:you@example.com", then move to p=reject.', proof: dnsProof(`DNS TXT _dmarc.${root}`, `dig +short TXT _dmarc.${root}`, ['no TXT record at _dmarc starts with v=DMARC1']) }, 'dmarc'))
    else if (/\bp=none\b/i.test(dmarc)) out.push(f({ severity: 'info', confidence: 'confirmed', title: `DMARC on ${root} only watches (p=none)`, file: root, description: 'Spoofed mail is reported but still delivered.', fix: 'Move to p=quarantine, then p=reject, once the reports look clean.', proof: dnsProof(`DNS TXT _dmarc.${root}`, `dig +short TXT _dmarc.${root}`, [`DMARC: ${dmarc.slice(0, 120)}`], dmarc) }, 'dmarc-none'))
  }
  if (r.resolveCaa) {
    const caa = await never(r.resolveCaa(root), [] as { critical: number }[])
    if (!caa.length) out.push(f({ severity: 'info', confidence: 'confirmed', title: `${root} has no CAA record`, file: root, description: 'A CAA record limits which companies may issue certificates for the domain.', fix: 'Publish a CAA record for the authority you use, for example: 0 issue "letsencrypt.org".', proof: dnsProof(`DNS CAA ${root}`, `dig +short CAA ${root}`, ['no CAA record was returned']) }, 'caa'))
  }
  return out
}

// ---------------------------------------------------------------- DevOps and infrastructure

interface Probe {
  path: string
  /** The facts that prove it is what it looks like, or null. Never a status code alone. */
  test: (status: number, body: string, headers: HeaderLike) => string[] | null
  severity: Severity
  title: string
  description: string
  fix: string
  cwe?: string
  /** The answer is a web page (only the Jenkins console). Every other probe refuses an HTML answer. */
  html?: boolean
  /** The software behind it, for the known-flaw check. */
  product?: (body: string, headers: HeaderLike) => Product | null
}

const json = (b: string): unknown => {
  try {
    return JSON.parse(b)
  } catch {
    return null
  }
}
const has = (b: string, ...k: string[]): boolean => k.every((x) => b.includes(x))
const ok = (status: number): boolean => status === 200
const prod = (name: string, cpe: [string, string][], version: string | undefined, from: string): Product | null => (version && /^\d+(\.\d+)*/.test(version) ? { name, version: /^\d+(\.\d+)*/.exec(version)![0], cpe, from } : null)
const CI_TEXT = /(password|secret|token|api[_-]?key|aws_|credentials)\s*[:=]/i

export const PROBES: Probe[] = [
  { path: 'script', html: true, test: (s, b) => (ok(s) && /<title>[^<]*Script Console/i.test(b) && /Groovy/i.test(b) ? ['the page is the Jenkins Script Console', 'it answered without signing in'] : null), severity: 'critical', title: 'The Jenkins Script Console is open without sign-in', description: 'The Script Console runs code on the build server. Anyone who can open it controls the server and every secret the builds use.', fix: 'Require sign-in on Jenkins (Manage Jenkins, Security), and keep it off the public internet.', cwe: 'CWE-306' },
  { path: 'api/json?tree=mode,numExecutors,jobs[name]', test: (s, b, h) => (ok(s) && /"_class":"hudson\.|"_class":"jenkins\./.test(b) ? ['the answer is Jenkins JSON', ...(h.get('x-jenkins') ? [`header x-jenkins: ${h.get('x-jenkins')}`] : [])] : null), severity: 'high', title: 'Jenkins answers its API without sign-in', description: 'Job names, build history and settings can be read by anyone. Job names often show internal projects, customers and environments.', fix: 'Turn off anonymous read access (Manage Jenkins, Security).', cwe: 'CWE-306', product: (_b, h) => prod('Jenkins', [['jenkins', 'jenkins']], h.get('x-jenkins') ?? undefined, `header x-jenkins: ${h.get('x-jenkins')}`) },
  { path: 'api/search', test: (s, b) => (ok(s) && /^\s*\[/.test(b) && /"type"\s*:\s*"dash-(db|folder)"/.test(b) && /"uid"/.test(b) ? ['the answer is a list of Grafana dashboards', 'it answered without signing in'] : null), severity: 'high', title: 'Grafana lists its dashboards without sign-in', description: 'Dashboards show how the systems behind the site run, and often contain data sources and customer figures.', fix: 'Turn off anonymous access in grafana.ini ([auth.anonymous] enabled = false) or restrict it to a viewer role you accept.', cwe: 'CWE-306' },
  { path: 'api/health', test: (s, b) => { const j = json(b) as { database?: string; version?: string } | null; return ok(s) && j && typeof j === 'object' && 'database' in j && 'version' in j ? [`Grafana health answers with version ${j.version}`] : null }, severity: 'low', title: 'Grafana is reachable and states its version', description: 'The version tells an attacker which known flaws to try.', fix: 'Put Grafana behind a login or a VPN, and keep it updated.', product: (b) => prod('Grafana', [['grafana', 'grafana']], (json(b) as { version?: string } | null)?.version, 'Grafana /api/health') },
  { path: 'api/v1/status/buildinfo', test: (s, b) => (ok(s) && /"status"\s*:\s*"success"/.test(b) && /"goVersion"/.test(b) ? ['the answer is Prometheus build information'] : null), severity: 'medium', title: 'Prometheus is open without sign-in', description: 'Prometheus holds every metric of your systems and lets anyone query them, which shows hostnames, services, traffic and sometimes secrets in labels.', fix: 'Put Prometheus behind authentication or a private network.', cwe: 'CWE-306', product: (b) => prod('Prometheus', [['prometheus', 'prometheus']], (json(b) as { data?: { version?: string } } | null)?.data?.version, 'Prometheus buildinfo') },
  { path: 'metrics', test: (s, b, h) => (ok(s) && /^# HELP /m.test(b) && /^# TYPE /m.test(b) && !/html/i.test(h.get('content-type') ?? '') ? ['the answer is metrics in the Prometheus text format'] : null), severity: 'low', title: 'Application metrics are public', description: 'Metrics show internal route names, request counts, versions and sometimes user or tenant names.', fix: 'Serve /metrics only on an internal port or behind authentication.', cwe: 'CWE-200' },
  { path: '', test: (s, b) => (ok(s) && /"cluster_name"/.test(b) && /"tagline"\s*:\s*"You Know, for Search"/.test(b) ? ['the answer is an Elasticsearch node banner', 'it answered without signing in'] : null), severity: 'high', title: 'Elasticsearch is open to the internet without sign-in', description: 'Anyone can read, change and delete the indexes. Open Elasticsearch servers are a common source of data leaks.', fix: 'Turn on security (xpack.security.enabled) and close the port to the internet.', cwe: 'CWE-306', product: (b) => prod('Elasticsearch', [['elastic', 'elasticsearch']], (json(b) as { version?: { number?: string } } | null)?.version?.number, 'the Elasticsearch banner') },
  { path: '_cat/indices', test: (s, b) => (ok(s) && /^(green|yellow|red)\s+(open|close)\s+\S+/m.test(b) ? ['the answer lists Elasticsearch indexes (names not kept)'] : null), severity: 'critical', title: 'Elasticsearch lists its indexes to anyone', description: 'The index list is public, so the data in them can be read.', fix: 'Turn on security and close the port.', cwe: 'CWE-306' },
  { path: 'api/status', test: (s, b) => (ok(s) && /"name"\s*:/.test(b) && /"status"\s*:\s*\{\s*"overall"/.test(b) && /kibana/i.test(b) ? ['the answer is the Kibana status'] : null), severity: 'medium', title: 'Kibana is reachable without sign-in', description: 'Kibana can read every index it is connected to.', fix: 'Turn on security for Kibana and Elasticsearch.', cwe: 'CWE-306', product: (b) => prod('Kibana', [['elastic', 'kibana']], (json(b) as { version?: { number?: string } } | null)?.version?.number, 'Kibana /api/status') },
  { path: 'v1/agent/self', test: (s, b) => (ok(s) && /"Config"/.test(b) && /"NodeName"/.test(b) ? ['the answer is the Consul agent configuration'] : null), severity: 'high', title: 'The Consul agent API is open without a token', description: 'Anyone can read the service list and keys, and with scripts enabled can run commands on the machine.', fix: 'Turn on ACLs with a default of deny, and close the port to the internet.', cwe: 'CWE-306', product: (b) => prod('Consul', [['hashicorp', 'consul']], (json(b) as { Config?: { Version?: string } } | null)?.Config?.Version, 'the Consul agent') },
  { path: 'version', test: (s, b) => (ok(s) && /"etcdserver"/.test(b) ? ['the answer names etcdserver'] : /"gitVersion"/.test(b) && /"goVersion"/.test(b) && ok(s) ? ['the answer is the Kubernetes API server version'] : null), severity: 'medium', title: 'A cluster API answers on the internet (etcd or Kubernetes)', description: 'The control plane of the cluster is reachable. That is a serious exposure even when sign-in is required, because every flaw in it is reachable too.', fix: 'Close the API port to the internet and allow only your network or VPN.', cwe: 'CWE-284', product: (b) => prod('Kubernetes', [['kubernetes', 'kubernetes']], (json(b) as { gitVersion?: string } | null)?.gitVersion?.replace(/^v/, ''), 'the Kubernetes /version') },
  { path: 'api/v1/namespaces', test: (s, b) => (ok(s) && /"kind"\s*:\s*"NamespaceList"/.test(b) ? ['the answer is a Kubernetes namespace list', 'it answered without credentials'] : null), severity: 'critical', title: 'The Kubernetes API answers without credentials', description: 'Anonymous access is allowed. Depending on the roles, anyone can read secrets and run workloads in the cluster.', fix: 'Disable anonymous auth (--anonymous-auth=false) and close the port to the internet.', cwe: 'CWE-306' },
  { path: 'v2/keys/?recursive=true', test: (s, b) => (ok(s) && /"action"\s*:\s*"get"/.test(b) && /"node"/.test(b) ? ['the answer is the etcd key store'] : null), severity: 'critical', title: 'etcd serves its keys without sign-in', description: 'etcd holds cluster state and often secrets.', fix: 'Enable client certificate authentication and close the port.', cwe: 'CWE-306' },
  { path: 'v2/_catalog', test: (s, b) => (ok(s) && /"repositories"\s*:\s*\[/.test(b) ? ['the answer lists container repositories'] : null), severity: 'high', title: 'A container registry lists its images without sign-in', description: 'Anyone can list and pull the images, which often contain source code, configuration and secrets.', fix: 'Require authentication on the registry.', cwe: 'CWE-306' },
  { path: 'containers/json', test: (s, b) => (ok(s) && /^\s*\[/.test(b) && /"Image"\s*:/.test(b) && /"Command"\s*:/.test(b) ? ['the answer is the Docker container list', 'it answered without credentials'] : null), severity: 'critical', title: 'The Docker API is open to the internet', description: 'Whoever reaches this API can start any container on the host, which means full control of the machine.', fix: 'Never expose the Docker socket over plain TCP. Use TLS client certificates or SSH, and close the port.', cwe: 'CWE-306' },
  { path: 'api/rawdata', test: (s, b) => (ok(s) && /"routers"\s*:/.test(b) && /"services"\s*:/.test(b) ? ['the answer is the Traefik configuration'] : null), severity: 'high', title: 'The Traefik dashboard API is public', description: 'It lists every route and backend address, which maps the internal network.', fix: 'Do not expose the Traefik API (api.insecure=false), or protect it with a middleware.', cwe: 'CWE-200' },
  { path: 'api/v1/applications', test: (s, b) => (ok(s) && /"items"\s*:/.test(b) && /"kind"\s*:\s*"Application"/.test(b) ? ['the answer is an Argo CD application list'] : null), severity: 'high', title: 'Argo CD lists its applications without sign-in', description: 'Applications show repositories, clusters and deployment settings.', fix: 'Turn off anonymous access in argocd-cm (users.anonymous.enabled: "false").', cwe: 'CWE-306' },
  { path: 'api/users/admin/check', test: (s, _b, h) => (s === 204 && /portainer|^$/i.test(h.get('server') ?? '') ? ['Portainer answered 204, meaning no admin user has been created yet'] : null), severity: 'critical', title: 'Portainer has no administrator yet: the first visitor becomes admin', description: 'A fresh Portainer asks the first person who opens it to create the admin account. Whoever does that controls every container it manages.', fix: 'Open Portainer yourself now and create the administrator, or take it off the internet until you do.', cwe: 'CWE-1188' },
  { path: 'api/overview', test: (s, b) => (ok(s) && /"rabbitmq_version"/.test(b) ? ['the answer is the RabbitMQ overview'] : null), severity: 'high', title: 'The RabbitMQ management API answers without sign-in', description: 'Queues, users and message rates can be read, and often changed.', fix: 'Change or remove the default guest account and close the management port.', cwe: 'CWE-306', product: (b) => prod('RabbitMQ', [['vmware', 'rabbitmq'], ['pivotal_software', 'rabbitmq']], (json(b) as { rabbitmq_version?: string } | null)?.rabbitmq_version, 'RabbitMQ /api/overview') },
  { path: 'api/server/version', test: (s, b, h) => (ok(s) && /^\d+\.\d+(\.\d+)*(\.\d+)?\s*$/.test(b.trim()) && /text\/plain/i.test(h.get('content-type') ?? '') ? ['the answer is a bare version number in plain text (the SonarQube way)'] : null), severity: 'low', title: 'SonarQube states its version without sign-in', description: 'The version tells an attacker which flaws to try, and an open SonarQube often shows source code.', fix: 'Turn on "Force user authentication".', product: (b) => prod('SonarQube', [['sonarsource', 'sonarqube']], b.trim(), 'SonarQube /api/server/version') },
  { path: 'terraform.tfstate', test: (s, b) => (ok(s) && /"terraform_version"/.test(b) && /"resources"|"modules"/.test(b) ? ['the file is a Terraform state', 'it lists the infrastructure and often contains secrets in plain text'] : null), severity: 'critical', title: 'A Terraform state file is public', description: 'State files describe every resource and usually contain database passwords, keys and tokens in clear text.', fix: 'Remove it from the web root now, rotate every secret in it, and keep state in a private remote backend.', cwe: 'CWE-538' },
  { path: '.terraform/terraform.tfstate', test: (s, b) => (ok(s) && /"terraform_version"|"backend"/.test(b) && /^\s*\{/.test(b) ? ['the file is Terraform state or backend settings'] : null), severity: 'high', title: 'Terraform working files are public', description: 'They name the backend and often the credentials used to reach it.', fix: 'Remove the .terraform folder from the web root.', cwe: 'CWE-538' },
  { path: '.aws/credentials', test: (s, b) => (ok(s) && /^\[[\w.-]+\]\s*$/m.test(b) && /aws_access_key_id\s*=/i.test(b) ? ['the file has an [profile] section with aws_access_key_id (values not kept)'] : null), severity: 'critical', title: 'AWS credentials are public', description: 'The file holds access keys for an AWS account.', fix: 'Delete the file from the web root, deactivate the keys in IAM and create new ones.', cwe: 'CWE-538' },
  { path: '.kube/config', test: (s, b) => (ok(s) && /^apiVersion:\s*v1/m.test(b) && /^clusters:/m.test(b) ? ['the file is a kubeconfig with clusters'] : null), severity: 'critical', title: 'A Kubernetes config file is public', description: 'It names the cluster and usually holds a certificate or token that logs in to it.', fix: 'Delete it from the web root and rotate the credentials it holds.', cwe: 'CWE-538' },
  { path: '.docker/config.json', test: (s, b) => (ok(s) && /"auths"\s*:\s*\{/.test(b) ? ['the file lists container registry logins (values not kept)'] : null), severity: 'critical', title: 'Docker registry logins are public', description: 'The file holds the logins used to push and pull images.', fix: 'Delete it from the web root and rotate the registry credentials.', cwe: 'CWE-538' },
  { path: '.netrc', test: (s, b) => (ok(s) && /^\s*machine\s+\S+/m.test(b) && /\b(login|password)\s+\S+/.test(b) ? ['the file lists machines with logins (values not kept)'] : null), severity: 'critical', title: 'A .netrc file with logins is public', description: 'It holds usernames and passwords for other servers.', fix: 'Delete it from the web root and change the passwords.', cwe: 'CWE-538' },
  { path: '.pypirc', test: (s, b) => (ok(s) && /^\[(distutils|pypi|testpypi)\]/m.test(b) ? ['the file is a PyPI upload config'] : null), severity: 'high', title: 'A PyPI upload config is public', description: 'It may hold the token used to publish packages.', fix: 'Delete it from the web root and revoke the token.', cwe: 'CWE-538' },
  { path: 'Jenkinsfile', test: (s, b) => (ok(s) && /^\s*(pipeline|node)\s*\{/m.test(b) && /\b(stage|steps|agent)\b/.test(b) ? ['the file is a Jenkins pipeline'] : null), severity: 'medium', title: 'A Jenkins pipeline file is public', description: 'It shows how the software is built and deployed, which servers it reaches and which credentials it uses by name.', fix: 'Do not deploy build files to the web root.', cwe: 'CWE-538' },
  { path: '.travis.yml', test: (s, b) => (ok(s) && /^language:\s*\w+/m.test(b) ? ['the file is a Travis CI config'] : null), severity: 'low', title: 'A Travis CI config is public', description: 'It shows build and deploy steps.', fix: 'Do not deploy build files to the web root.', cwe: 'CWE-538' },
  { path: '.circleci/config.yml', test: (s, b) => (ok(s) && /^version:\s*2/m.test(b) && /^(jobs|workflows):/m.test(b) ? ['the file is a CircleCI config'] : null), severity: 'low', title: 'A CircleCI config is public', description: 'It shows build and deploy steps.', fix: 'Do not deploy build files to the web root.', cwe: 'CWE-538' },
  { path: 'azure-pipelines.yml', test: (s, b) => (ok(s) && /^(trigger|pool|stages|steps):/m.test(b) ? ['the file is an Azure Pipelines config'] : null), severity: 'low', title: 'An Azure Pipelines config is public', description: 'It shows build and deploy steps.', fix: 'Do not deploy build files to the web root.', cwe: 'CWE-538' },
  { path: 'bitbucket-pipelines.yml', test: (s, b) => (ok(s) && /^pipelines:/m.test(b) ? ['the file is a Bitbucket Pipelines config'] : null), severity: 'low', title: 'A Bitbucket Pipelines config is public', description: 'It shows build and deploy steps.', fix: 'Do not deploy build files to the web root.', cwe: 'CWE-538' },
  { path: 'buildspec.yml', test: (s, b) => (ok(s) && /^version:\s*0\.2/m.test(b) && /^phases:/m.test(b) ? ['the file is an AWS CodeBuild spec'] : null), severity: 'low', title: 'An AWS CodeBuild spec is public', description: 'It shows build and deploy steps.', fix: 'Do not deploy build files to the web root.', cwe: 'CWE-538' },
  { path: '.github/workflows/main.yml', test: (s, b) => (ok(s) && /^on:|^'on':|^"on":/m.test(b) && /^jobs:/m.test(b) ? ['the file is a GitHub Actions workflow'] : null), severity: 'low', title: 'A GitHub Actions workflow is public on the web server', description: 'Workflows show how the code is built and which secrets they use by name.', fix: 'Do not deploy the .github folder to the web root.', cwe: 'CWE-538' },
  { path: 'serverless.yml', test: (s, b) => (ok(s) && /^service:/m.test(b) && /^provider:/m.test(b) ? ['the file is a Serverless Framework config'] : null), severity: 'low', title: 'A Serverless config is public', description: 'It names the cloud account settings, roles and functions.', fix: 'Do not deploy deployment files to the web root.', cwe: 'CWE-538' },
  { path: 'terraform.tfvars', test: (s, b) => (ok(s) && /^\s*[a-z_]+\s*=\s*"/m.test(b) && !/<html/i.test(b.slice(0, 300)) ? ['the file assigns Terraform variables (values not kept)'] : null), severity: 'high', title: 'Terraform variables are public', description: 'Variable files often hold secrets and account ids.', fix: 'Delete it from the web root and rotate what it holds.', cwe: 'CWE-538' }
]

/** The GitHub (or other host) repository named in a .git/config, and whether a password is written into its address. */
export function gitRemote(config: string): { host: string; repo: string; credential: boolean } | null {
  const m = /^\s*url\s*=\s*(?:https?:\/\/(?:([^/@\s]+)@)?|git@|ssh:\/\/git@)([a-z0-9.-]+)[:/]([\w.\-]+\/[\w.\-]+?)(?:\.git)?\s*$/im.exec(config)
  if (!m) return null
  return { host: m[2].toLowerCase(), repo: m[3], credential: Boolean(m[1] && m[1].includes(':')) || /^\s*url\s*=\s*https?:\/\/(?:gh[pousr]_|github_pat_|glpat-)/im.test(config) }
}

export interface Posture {
  findings: Finding[]
  products: { product: Product; host: string }[]
  stopped?: string
}

/** Probes the DevOps list and the Git remote. Each hit is repeated once; one that does not repeat is dropped. */
export async function devopsChecks(c: ConfirmClient, host: string, o: { probes?: Probe[]; note?: (t: string) => void } = {}): Promise<Posture> {
  const out: Posture = { findings: [], products: [] }
  const list = o.probes ?? PROBES
  try {
    for (const p of list) {
      o.note?.(`DevOps and infrastructure: ${p.path || '/'}`)
      const path = `/${p.path}`
      const r = await c.get(path)
      const answers = (x: typeof r): string[] | null => (!p.html && /html/i.test(x.headers.get('content-type') ?? '') ? null : p.test(x.status, x.body, x.headers))
      const shows = answers(r)
      if (!shows) continue
      const again = await c.get(path)
      if (!answers(again)) continue
      const url = c.resolve(path)
      out.findings.push(f({ severity: p.severity, confidence: 'confirmed', title: p.title, url, file: url, cwe: p.cwe, description: p.description, fix: p.fix, proof: proofOf({ url, status: r.status, headers: r.headers, body: r.body.slice(0, 200000), shows: [...shows, 'the same answer came twice'] }) }, p.path))
      const pr = p.product?.(r.body, r.headers)
      if (pr) out.products.push({ product: { ...pr, proof: proofOf({ url, status: r.status, headers: r.headers, body: r.body.slice(0, 200000), shows: [pr.from] }) }, host })
    }
    // The Git folder names the repository the site was built from.
    const g = await c.get('/.git/config')
    const gs = fileShows('.git/config', g.body)
    if (g.status === 200 && gs) {
      const remote = gitRemote(g.body)
      const url = c.resolve('/.git/config')
      const proof = proofOf({ url, status: g.status, headers: g.headers, body: g.body.slice(0, 20000), shows: [...gs, remote ? `a remote points at ${remote.host}: ${remote.repo}` : 'no remote address'] })
      if (remote?.credential) out.findings.push(f({ severity: 'critical', confidence: 'confirmed', title: `A password or token for ${remote.host} is written in the public .git/config`, url, file: url, cwe: 'CWE-798', description: `The remote address of ${remote.repo} contains a login. Anyone can read it. Anyone who has it can read, and maybe change, the code on ${remote.host}.`, fix: `Revoke that token or password on ${remote.host} now, delete the .git folder from the web root and redeploy.`, proof }, 'gitcred'))
      else if (remote) out.findings.push(f({ severity: 'medium', confidence: 'confirmed', title: `The public .git folder names the code repository: ${remote.host}/${remote.repo}`, url, file: url, cwe: 'CWE-538', description: `The source repository is named in plain sight. If that repository is public or has weak access, the whole code and its history can be read, and its past commits may hold old secrets.`, fix: 'Delete the .git folder from the web root, and check who can read that repository.', proof }, 'gitremote'))
    }
  } catch (e) {
    if (!(e instanceof Stop)) throw e
    out.stopped = e.message
  }
  return out
}
