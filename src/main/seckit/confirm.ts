/**
 * Confirmed recon: every finding carries the proof that it is really there, or says plainly that it
 * is only possible. Shared by Laramac and MacSec (keep the two copies of src/main/seckit the same).
 *
 * Nothing here sends anything. These are the checks that read an answer the site already gave (to an
 * ordinary GET, OPTIONS or a GET with an Origin header) and decide whether it proves the problem:
 *
 *   confirmed  the thing itself was seen: the file answered with its real content, the page lists
 *              its folder, the server returned its own stack trace, the source map downloaded.
 *   possible   the evidence points at it but does not prove it: a version number matches a known
 *              flaw (the vendor may have patched without changing the number), or the server says it
 *              allows a method we did not try.
 *
 * A proof holds the request, what came back (status, size and a SHA-256 of the body so it can be
 * compared later) and "shows": the short facts in the answer that prove it. Shows never contains a
 * secret: for a file with keys in it, only the names of the settings are kept.
 */
import { createHash } from 'crypto'

export type Confidence = 'confirmed' | 'possible'
export type Sev = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface Proof {
  /** The request that was sent, for example "GET https://example.com/.env". */
  request: string
  /** A command a person can paste to repeat it. */
  reproduce: string
  status: number
  contentType?: string
  /** How many bytes of the answer were read. */
  bytes: number
  /** SHA-256 of the part of the answer that was read. */
  sha256: string
  /** When it was seen (ISO time). */
  at: string
  /** What in the answer proves it. Never a secret value. */
  shows: string[]
}

export interface HeaderLike {
  get(name: string): string | null
}

const shell = (s: string): string => `'${s.replace(/'/g, `'\\''`)}'`

export function proofOf(o: { method?: string; url: string; status: number; headers: HeaderLike; body: string; shows: string[]; sent?: Record<string, string> }): Proof {
  const method = o.method ?? 'GET'
  const sent = Object.entries(o.sent ?? {})
  return {
    request: `${method} ${o.url}`,
    reproduce: `curl -sS -i${method === 'GET' ? '' : ` -X ${method}`}${sent.map(([k, v]) => ` -H ${shell(`${k}: ${v}`)}`).join('')} ${shell(o.url)}`,
    status: o.status,
    contentType: o.headers.get('content-type')?.slice(0, 80) ?? undefined,
    bytes: Buffer.byteLength(o.body),
    sha256: createHash('sha256').update(o.body).digest('hex'),
    at: new Date().toISOString(),
    shows: o.shows.slice(0, 12).map((s) => s.slice(0, 200))
  }
}

// ---------------------------------------------------------------- Files that should not be public

/** Names of the settings in a KEY=value file, never the values. */
export const envNames = (body: string): string[] => [...new Set([...body.matchAll(/^\s*(?:export\s+)?([A-Za-z][A-Za-z0-9_.]{1,60})\s*=/gm)].map((m) => m[1]))]
const namesNote = (names: string[]): string => `${names.length} settings, for example ${names.slice(0, 6).join(', ')}`

/**
 * What proves that `body` really is the file at `path` (not a "not found" page that answers 200).
 * Returns the facts, or null when it is not that file. Values are never included.
 */
export function fileShows(path: string, body: string): string[] | null {
  const b = body.slice(0, 6000)
  const html = /<html|<!doctype html/i.test(b.slice(0, 400))
  const p = path.replace(/^\//, '')
  if (p === '.git/HEAD') return /^ref: refs\//.test(b) ? ['starts with "ref: refs/", the way a Git HEAD file does'] : null
  if (p === '.git/config') {
    if (!/^\[core\]/m.test(b) || html) return null
    const shows = ['has a [core] section, the way a Git config does']
    if (/^\s*url\s*=\s*https?:\/\/[^/\s:@]+:[^@\s]+@/m.test(b)) shows.push('a remote address contains a user name and password')
    return shows
  }
  if (p === '.svn/entries') return !html && /^\d{1,2}\s*\n[\s\S]{0,300}\b(dir|file)\b/.test(b) ? ['looks like a Subversion entries file'] : null
  if (p === '.svn/wc.db') return b.startsWith('SQLite format 3') ? ['starts with the SQLite signature of the Subversion database'] : null
  if (p === '.hg/requires') return !html && /^(revlogv1|store|fncache|dotencode|generaldelta)\s*$/m.test(b) ? ['lists Mercurial repository features'] : null
  if (p === '.env' || /^\.env\.[a-z]+$/.test(p)) {
    const names = envNames(b)
    return !html && /^[A-Z][A-Z0-9_]+=/m.test(b) && names.length ? [namesNote(names)] : null
  }
  if (p === '.DS_Store') return b.includes('Bud1') ? ['starts with the .DS_Store signature'] : null
  if (p === 'server-status') return /Apache Server Status/i.test(b) ? ['the page is Apache Server Status'] : null
  if (p === 'server-info') return /Apache Server Information/i.test(b) ? ['the page is Apache Server Information'] : null
  if (p === 'phpinfo.php' || p === 'info.php' || p === 'i.php' || p === 'php.php' || p === 'test.php' || p === '_profiler/phpinfo') return /phpinfo\(\)|PHP Version/i.test(b) ? ['the page prints phpinfo()'] : null
  if (/swagger|openapi|api-docs/.test(p) && !/swagger-ui|\/index\.html$|\.html$/.test(p)) return /"(openapi|swagger)"\s*:/.test(b) ? ['a machine-readable API description with a swagger or openapi version'] : /^\s*(openapi|swagger):/m.test(b) ? ['a YAML API description'] : null
  if (p === 'swagger-ui.html' || p === 'swagger/index.html') return /swagger-ui/i.test(b) ? ['the Swagger UI page'] : null
  if (p === 'graphql' || p === 'graphiql' || p === 'altair') return /graphql|graphiql|altair/i.test(b) && (!html || /graphiql|altair/i.test(b)) ? ['the endpoint answers like GraphQL'] : null
  if (p.startsWith('actuator/heapdump')) return b.startsWith('JAVA PROFILE') ? ['starts with the Java heap dump signature (only the first bytes were read)'] : null
  if (p === 'actuator/env') return /"(activeProfiles|propertySources)"/.test(b) ? ['lists the active profiles and property sources'] : null
  if (p === 'actuator/mappings') return /"(dispatcherServlets|contexts)"/.test(b) ? ['lists the request mappings'] : null
  if (p === 'actuator' || p === 'actuator/health') return /"(_links|status)"\s*:/.test(b) ? ['answers like Spring Boot actuator'] : null
  if (p === 'wp-json/wp/v2/users') return /^\s*\[\s*\{\s*"id"/.test(b) ? ['lists WordPress users with their ids'] : null
  if (p === 'crossdomain.xml') return /<cross-domain-policy/i.test(b) ? ['a Flash cross-domain policy'] : null
  if (p === '.htpasswd') {
    const n = (b.match(/^[^:\s]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|[./0-9A-Za-z]{13}\s*$)/gm) ?? []).length
    return n ? [`${n} lines in user:hash format (hashes not kept)`] : null
  }
  if (p === 'id_rsa' || p === '.ssh/id_rsa') return /-----BEGIN (OPENSSH|RSA|EC|DSA) PRIVATE KEY-----/.test(b) ? ['starts with a private key header (the key itself is not kept)'] : null
  if (p === 'credentials.json' || p === 'secrets.json' || p === 'secrets.yml') {
    const names = [...new Set([...b.matchAll(/"?(client_secret|private_key|api_key|apikey|password|secret|token|access_key)"?\s*[:=]/gi)].map((m) => m[1].toLowerCase()))]
    return !html && names.length ? [`has fields named ${names.join(', ')} (values not kept)`] : null
  }
  if (p === '.npmrc') {
    const names = [...new Set([...b.matchAll(/^\s*(?:\/\/[^\s=]+:)?(_authToken|_auth|_password|registry|always-auth)\s*=/gm)].map((m) => m[1]))]
    return !html && names.length ? [`has settings named ${names.join(', ')} (values not kept)`] : null
  }
  if (p === 'composer.json') return !html && /"(require|name)"\s*:/.test(b) ? ['a PHP composer.json with its dependencies'] : null
  if (p === 'package.json') return !html && /"(dependencies|devDependencies|scripts)"\s*:/.test(b) ? ['a package.json with its dependencies'] : null
  if (p === 'Dockerfile') return !html && /^FROM\s+\S+/m.test(b) ? ['a Dockerfile, starting with FROM'] : null
  if (p === 'docker-compose.yml') return !html && /^services:\s*$/m.test(b) ? ['a Docker Compose file with a services section'] : null
  if (p === '.gitlab-ci.yml') return !html && /^(stages|image|script|variables):/m.test(b) ? ['a GitLab CI file'] : null
  if (p === 'web.config' || p === 'web.config.bak') return /<configuration[\s>]/i.test(b) ? ['an ASP.NET web.config'] : null
  if (p === 'storage/logs/laravel.log') return /^\[\d{4}-\d\d-\d\d[ T][\d:]+[^\]]*\]\s+\w+\.(ERROR|INFO|DEBUG|WARNING|CRITICAL)/m.test(b) ? ['lines in the Laravel log format'] : null
  if (/^wp-config\.php(\.|~)/.test(p) || p === 'wp-config.php~') {
    const names = [...new Set([...b.matchAll(/define\(\s*['"](DB_[A-Z]+|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY)['"]/g)].map((m) => m[1]))]
    return names.length ? [`WordPress settings in plain text: ${names.join(', ')} (values not kept)`] : null
  }
  if (/\.(sql)$/.test(p)) return /^-- (MySQL|MariaDB|PostgreSQL) dump|^CREATE TABLE|^INSERT INTO|^DROP TABLE/m.test(b) ? ['a database dump: SQL statements such as CREATE TABLE'] : null
  if (/\.(zip)$/.test(p)) return b.startsWith('PK\u0003\u0004') ? ['starts with the ZIP signature (only the first bytes were read)'] : null
  if (/\.tar\.gz$/.test(p)) return b.startsWith('\u001f\u008b') || b.charCodeAt(0) === 0x1f ? ['starts with the gzip signature (only the first bytes were read)'] : null
  if (p === 'adminer.php') return /adminer/i.test(b) && /login|server/i.test(b) ? ['the Adminer database login page'] : null
  if (p === 'phpmyadmin/' || p === 'pma/') return /phpMyAdmin/i.test(b) ? ['the phpMyAdmin page'] : null
  if (p === 'telescope') return /Laravel Telescope/i.test(b) ? ['the Laravel Telescope page'] : null
  if (p === 'horizon') return /Laravel Horizon/i.test(b) ? ['the Laravel Horizon page'] : null
  if (p === '_profiler') return /Symfony Profiler/i.test(b) ? ['the Symfony Profiler page'] : null
  if (p === 'elmah.axd') return /Error Log for/i.test(b) ? ['the ELMAH error log page'] : null
  if (p === 'trace.axd') return /Application Trace/i.test(b) ? ['the ASP.NET trace page'] : null
  if (p === 'console') return /Interactive Console|Werkzeug|H2 Console|Jetty/i.test(b) ? ['an interactive console page'] : null
  if (/logs?\/?$|error[_.]log|debug\.log|npm-debug\.log/.test(p)) return !html && /\b(ERROR|WARN|Exception|Traceback|\d{4}-\d\d-\d\d)/.test(b) ? ['lines that look like a log'] : null
  if (/robots|sitemap|security\.txt/.test(p)) return !html || /<urlset|<sitemapindex/.test(b) ? ['a plain text or XML file in the expected format'] : null
  return html ? null : ['answers with a file, not a web page']
}

// ---------------------------------------------------------------- Directory listings

export function dirListing(body: string): { shows: string[] } | null {
  const b = body.slice(0, 60000)
  const marker = /<title>\s*Index of \/|<h1>\s*Index of \/|Directory listing for \/|\[To Parent Directory\]|<title>\s*Directory Listing For/i.test(b)
  if (!marker) return null
  const names = [...new Set([...b.matchAll(/<a href="([^"?#/][^"?#]*)"/gi)].map((m) => decodeURIComponent(m[1]).slice(0, 60)))].filter((n) => !/^(https?:|mailto:|\.\.)/.test(n))
  if (!names.length) return null
  return { shows: [`the page says "Index of" and lists ${names.length} entries`, `for example ${names.slice(0, 6).join(', ')}`] }
}

/** Folders that often list their files when the web server allows it. A fixed short list, nothing guessed. */
export const LISTING_DIRS = ['uploads/', 'files/', 'backup/', 'backups/', 'logs/', 'tmp/', 'assets/', 'static/', 'images/', 'media/', 'storage/', 'old/', 'dev/']

// ---------------------------------------------------------------- A CDN or web firewall in front

const WAFS: { name: string; test: (h: HeaderLike, cookies: string) => string[] }[] = [
  { name: 'Cloudflare', test: (h, c) => [h.get('cf-ray') ? 'header cf-ray is present' : '', /cloudflare/i.test(h.get('server') ?? '') ? 'Server header says cloudflare' : '', /(__cf_bm|cf_clearance)=/.test(c) ? 'a Cloudflare cookie is set' : ''] },
  { name: 'Akamai', test: (h, c) => [h.get('x-akamai-transformed') || h.get('akamai-grn') ? 'an Akamai header is present' : '', /AkamaiGHost/i.test(h.get('server') ?? '') ? 'Server header says AkamaiGHost' : '', /(ak_bmsc|bm_sz)=/.test(c) ? 'an Akamai bot-manager cookie is set' : ''] },
  { name: 'Amazon CloudFront', test: (h) => [h.get('x-amz-cf-id') ? 'header x-amz-cf-id is present' : '', /cloudfront/i.test(h.get('via') ?? '') || /CloudFront/i.test(h.get('server') ?? '') ? 'it says it is served through CloudFront' : ''] },
  { name: 'Imperva', test: (h, c) => [h.get('x-iinfo') ? 'header x-iinfo is present' : '', /imperva/i.test(h.get('x-cdn') ?? '') ? 'header x-cdn says Imperva' : '', /(incap_ses_|visid_incap_)/.test(c) ? 'an Incapsula cookie is set' : ''] },
  { name: 'Sucuri', test: (h) => [h.get('x-sucuri-id') || h.get('x-sucuri-cache') ? 'a Sucuri header is present' : '', /Sucuri/i.test(h.get('server') ?? '') ? 'Server header says Sucuri' : ''] },
  { name: 'F5 BIG-IP', test: (_h, c) => [/BIGipServer[^=]*=/.test(c) ? 'a BIG-IP cookie is set' : '', /\bTS[0-9a-f]{8,}=/.test(c) ? 'an F5 ASM cookie is set' : ''] },
  { name: 'Fastly', test: (h) => [h.get('x-fastly-request-id') || h.get('fastly-debug-digest') ? 'a Fastly header is present' : ''] },
  { name: 'Azure Front Door', test: (h) => [h.get('x-azure-ref') ? 'header x-azure-ref is present' : ''] },
  { name: 'Barracuda', test: (_h, c) => [/barra_counter_session=/.test(c) ? 'a Barracuda cookie is set' : ''] },
  { name: 'ModSecurity', test: (h) => [/mod_security|NOYB/i.test(h.get('server') ?? '') ? 'Server header names ModSecurity' : ''] },
  { name: 'Vercel', test: (h) => [h.get('x-vercel-id') ? 'header x-vercel-id is present' : '', /^Vercel$/i.test(h.get('server') ?? '') ? 'Server header says Vercel' : ''] },
  { name: 'Netlify', test: (h) => [h.get('x-nf-request-id') ? 'header x-nf-request-id is present' : '', /^Netlify$/i.test(h.get('server') ?? '') ? 'Server header says Netlify' : ''] }
]

/** Which CDN or web firewall answered, from the headers and cookies of an ordinary page. */
export function detectWaf(headers: HeaderLike, cookies = ''): { name: string; shows: string[] }[] {
  const out: { name: string; shows: string[] }[] = []
  for (const w of WAFS) {
    const shows = w.test(headers, cookies).filter(Boolean)
    if (shows.length) out.push({ name: w.name, shows })
  }
  return out
}

// ---------------------------------------------------------------- Error pages that give the app away

const ERROR_SIGNS: { stack: string; re: RegExp; shows: string }[] = [
  { stack: 'Laravel', re: /Whoops! There was an error|Illuminate\\(Foundation|Database|Routing)|facade\/ignition|Ignition/i, shows: 'the Laravel debug page (Whoops or Ignition) is shown' },
  { stack: 'Django', re: /You're seeing this error because you have <code>DEBUG = True|Using the URLconf defined in/i, shows: 'the Django debug page is shown (DEBUG = True)' },
  { stack: 'Python', re: /Traceback \(most recent call last\)/, shows: 'a Python traceback is shown' },
  { stack: 'Java', re: /\bat (java|javax|org\.springframework|org\.apache)\.[\w.$]+\(.*\.java:\d+\)|java\.lang\.\w+Exception/, shows: 'a Java stack trace is shown' },
  { stack: 'ASP.NET', re: /Server Error in '[^']*' Application|<b>\s*Exception Details:|Stack Trace:\s*<\/b>/i, shows: 'the ASP.NET error page with a stack trace is shown' },
  { stack: 'PHP', re: /<b>(Fatal error|Warning|Notice|Parse error)<\/b>:.* on line <b>\d+<\/b>|\b(Fatal error|Parse error): .* in \/.* on line \d+/i, shows: 'a PHP error with a file path and line is shown' },
  { stack: 'Ruby on Rails', re: /Action Controller: Exception caught|<title>.*\(ActionController::|Rails\.root:/i, shows: 'the Rails debug page is shown' },
  { stack: 'Node.js', re: /\n\s+at [\w.<>$ ]+ \((\/|[A-Z]:\\)[^)]*\.(js|ts|mjs):\d+:\d+\)/, shows: 'a Node.js stack trace with file paths is shown' },
  { stack: 'Symfony', re: /Symfony\\Component\\|<title>.*Symfony Exception/i, shows: 'the Symfony exception page is shown' }
]

/** Whether the answer to a request for a page that does not exist is the app's own error page with its internals. */
export function errorLeak(status: number, body: string): { stack: string; shows: string[] } | null {
  if (status < 400) return null
  const b = body.slice(0, 200000)
  for (const s of ERROR_SIGNS) if (s.re.test(b)) return { stack: s.stack, shows: [s.shows, `the answer was HTTP ${status}`] }
  return null
}

// ---------------------------------------------------------------- Cross-origin sharing

/** A made-up origin that belongs to nobody (the .example name is reserved). */
export const TEST_ORIGIN = 'https://macsec-origin-check.example'

/** Whether the server answers an unknown origin by allowing it (and its cookies). */
export function corsReflection(origin: string, headers: HeaderLike): { severity: Sev; shows: string[] } | null {
  const allow = headers.get('access-control-allow-origin')
  if (!allow) return null
  const creds = /^true$/i.test(headers.get('access-control-allow-credentials') ?? '')
  if (allow === origin) {
    return creds
      ? { severity: 'high', shows: [`Access-Control-Allow-Origin repeated our made-up origin ${origin}`, 'Access-Control-Allow-Credentials is true, so a page on that origin could read answers meant for a signed-in visitor'] }
      : { severity: 'low', shows: [`Access-Control-Allow-Origin repeated our made-up origin ${origin} (no cookies are allowed)`] }
  }
  if (allow === 'null' && creds) return { severity: 'medium', shows: ['Access-Control-Allow-Origin is "null" and credentials are allowed'] }
  return null
}

/** Methods the server says it allows. Only said, never tried, so this can only be "possible". */
export function advertisedMethods(allow: string | null): string[] {
  if (!allow) return []
  return allow.split(',').map((m) => m.trim().toUpperCase()).filter((m) => ['TRACE', 'TRACK', 'PUT', 'DELETE'].includes(m))
}

// ---------------------------------------------------------------- Versions and known flaws

export interface Product {
  name: string
  version: string
  /** NVD vendor and product names, for the products that go by more than one. */
  cpe: [string, string][]
  /** Where the version was read from, for the proof. */
  from: string
  /** Linux distributions patch without changing the number. */
  distro?: string
  /** The answer the version was read from. */
  proof?: Proof
}

const DISTRO = /\((Ubuntu|Debian|CentOS|Red Hat|RHEL|Fedora|SUSE|Alpine|Amazon)[^)]*\)/i

/** Software versions that the headers and the page itself state. */
export function bannersOf(headers: HeaderLike, html = ''): Product[] {
  const out: Product[] = []
  const server = headers.get('server') ?? ''
  const powered = headers.get('x-powered-by') ?? ''
  const add = (p: Product): void => {
    if (!out.some((o) => o.name === p.name && o.version === p.version)) out.push(p)
  }
  const distro = DISTRO.exec(server)?.[1]
  let m = /\bnginx\/(\d+(?:\.\d+){1,3})/i.exec(server)
  if (m) add({ name: 'nginx', version: m[1], cpe: [['f5', 'nginx'], ['nginx', 'nginx']], from: `Server: ${server.slice(0, 80)}`, distro })
  m = /\bApache\/(\d+(?:\.\d+){1,3})/i.exec(server)
  if (m) add({ name: 'Apache HTTP Server', version: m[1], cpe: [['apache', 'http_server']], from: `Server: ${server.slice(0, 80)}`, distro })
  m = /Apache[- ]Tomcat\/(\d+(?:\.\d+){1,3})/i.exec(server)
  if (m) add({ name: 'Apache Tomcat', version: m[1], cpe: [['apache', 'tomcat']], from: `Server: ${server.slice(0, 80)}`, distro })
  m = /Microsoft-IIS\/(\d+(?:\.\d+)?)/i.exec(server)
  if (m) add({ name: 'Microsoft IIS', version: m[1], cpe: [['microsoft', 'internet_information_services']], from: `Server: ${server.slice(0, 80)}` })
  m = /OpenSSL\/(\d+\.\d+\.\d+[a-z]?)/i.exec(server)
  if (m) add({ name: 'OpenSSL', version: m[1], cpe: [['openssl', 'openssl']], from: `Server: ${server.slice(0, 80)}`, distro })
  m = /\bPHP\/(\d+(?:\.\d+){1,3})/i.exec(powered) ?? /\bPHP\/(\d+(?:\.\d+){1,3})/i.exec(server)
  if (m) add({ name: 'PHP', version: m[1], cpe: [['php', 'php']], from: `X-Powered-By: ${powered.slice(0, 80)}`, distro: DISTRO.exec(powered)?.[1] ?? distro })
  m = /<meta[^>]+name=["']generator["'][^>]+content=["']WordPress (\d+\.\d+(?:\.\d+)?)["']/i.exec(html.slice(0, 40000))
  if (m) add({ name: 'WordPress', version: m[1], cpe: [['wordpress', 'wordpress']], from: `the page's generator tag says WordPress ${m[1]}` })
  return out
}

const LIBS: { name: string; re: RegExp; file?: RegExp; cpe: [string, string][] }[] = [
  { name: 'jQuery', re: /jQuery(?: JavaScript Library)? v(\d+\.\d+\.\d+)/, file: /jquery[-.](\d+\.\d+\.\d+)(?:\.min)?\.js/i, cpe: [['jquery', 'jquery']] },
  { name: 'Bootstrap', re: /Bootstrap v(\d+\.\d+\.\d+)/, file: /bootstrap[-.](\d+\.\d+\.\d+)(?:\.min)?\.js/i, cpe: [['getbootstrap', 'bootstrap'], ['twitter', 'bootstrap']] },
  { name: 'Moment.js', re: /moment\.js[\s\S]{0,60}version\s*:\s*(\d+\.\d+\.\d+)/i, cpe: [['momentjs', 'moment']] },
  { name: 'AngularJS', re: /AngularJS v(\d+\.\d+\.\d+)/, cpe: [['angularjs', 'angular.js'], ['google', 'angularjs']] },
  { name: 'Vue.js', re: /Vue\.js v(\d+\.\d+\.\d+)/, cpe: [['vuejs', 'vue'], ['vuejs', 'vue.js']] }
]

/** Library versions a script states in its own banner comment or file name. */
export function libsIn(url: string, js: string): Product[] {
  const out: Product[] = []
  const head = js.slice(0, 3000)
  for (const l of LIBS) {
    const fromHead = l.re.exec(head)?.[1]
    const fromName = l.file?.exec(url.split('?')[0])?.[1]
    const version = fromHead ?? fromName
    if (version) out.push({ name: l.name, version, cpe: l.cpe, from: fromHead ? `the banner comment in ${url.split('?')[0]}` : `the file name ${url.split('?')[0].split('/').pop()}` })
  }
  return out
}

/** Compares two versions such as 1.2.10, 2.4.49 or 1.1.1k. Returns <0, 0 or >0. */
export function compareVersions(a: string, b: string): number {
  const parts = (v: string): number[] => {
    const m = /^(\d+(?:\.\d+)*)([a-z])?/i.exec(v.trim())
    if (!m) return []
    const nums = m[1].split('.').map(Number)
    if (m[2]) nums.push(m[2].toLowerCase().charCodeAt(0) - 96)
    return nums
  }
  const x = parts(a)
  const y = parts(b)
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0)
    if (d) return d
  }
  return 0
}

export interface CveMatch {
  id: string
  score?: number
  summary: string
  /** On CISA's list of flaws that are being exploited. */
  kev: boolean
  /** Also depends on something else (an operating system, a setting) we cannot see. */
  conditional: boolean
}

interface NvdMatch {
  vulnerable?: boolean
  criteria?: string
  versionStartIncluding?: string
  versionStartExcluding?: string
  versionEndIncluding?: string
  versionEndExcluding?: string
}
interface NvdCve {
  cve?: {
    id?: string
    cisaExploitAdd?: string
    descriptions?: { lang?: string; value?: string }[]
    metrics?: Record<string, { cvssData?: { baseScore?: number } }[]>
    configurations?: { operator?: string; nodes?: { cpeMatch?: NvdMatch[] }[] }[]
  }
}

/**
 * The flaws in an NVD answer that really cover this product and version. NVD's own search is wide,
 * so every entry is checked again here: it must name the same product and give a version range
 * with at least one bound that contains this version (or name this exact version). A product name
 * alone never matches.
 */
export function matchNvd(json: string, product: Pick<Product, 'cpe' | 'version'>): CveMatch[] {
  let data: { vulnerabilities?: NvdCve[] }
  try {
    data = JSON.parse(json) as { vulnerabilities?: NvdCve[] }
  } catch {
    return []
  }
  const out: CveMatch[] = []
  for (const v of data.vulnerabilities ?? []) {
    const c = v.cve
    if (!c?.id) continue
    let hit = false
    let conditional = false
    for (const conf of c.configurations ?? []) {
      for (const node of conf.nodes ?? []) {
        for (const m of node.cpeMatch ?? []) {
          if (m.vulnerable === false || !m.criteria) continue
          const [, , , vendor, prod, ver] = m.criteria.split(':')
          if (!product.cpe.some(([pv, pp]) => pv === vendor && pp === prod)) continue
          const bounded = m.versionStartIncluding || m.versionStartExcluding || m.versionEndIncluding || m.versionEndExcluding
          let ok: boolean
          if (ver && ver !== '*' && ver !== '-') ok = compareVersions(ver, product.version) === 0
          else if (!bounded) ok = false
          else {
            ok = true
            if (m.versionStartIncluding && compareVersions(product.version, m.versionStartIncluding) < 0) ok = false
            if (m.versionStartExcluding && compareVersions(product.version, m.versionStartExcluding) <= 0) ok = false
            if (m.versionEndIncluding && compareVersions(product.version, m.versionEndIncluding) > 0) ok = false
            if (m.versionEndExcluding && compareVersions(product.version, m.versionEndExcluding) >= 0) ok = false
          }
          if (ok) {
            hit = true
            if ((conf.operator === 'AND') || (conf.nodes ?? []).length > 1) conditional = true
          }
        }
      }
    }
    if (!hit) continue
    const metrics = c.metrics ?? {}
    const score = (metrics.cvssMetricV31 ?? metrics.cvssMetricV40 ?? metrics.cvssMetricV30 ?? metrics.cvssMetricV2 ?? [])[0]?.cvssData?.baseScore
    out.push({ id: c.id, score, summary: (c.descriptions?.find((d) => d.lang === 'en')?.value ?? '').slice(0, 200), kev: Boolean(c.cisaExploitAdd), conditional })
  }
  return out.sort((a, b) => Number(b.kev) - Number(a.kev) || (b.score ?? 0) - (a.score ?? 0) || a.id.localeCompare(b.id))
}

/** How serious a version match is. It never says "critical": the version alone does not prove the flaw. */
export function versionSeverity(matches: CveMatch[]): Sev {
  if (!matches.length) return 'info'
  if (matches.some((m) => m.kev && !m.conditional)) return 'high'
  const top = Math.max(...matches.map((m) => m.score ?? 0))
  return top >= 7 ? 'medium' : 'low'
}

/** The NVD address that asks for the flaws whose affected range covers one product's version. */
export const nvdUrl = (cpe: [string, string], version: string): string =>
  `https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=${encodeURIComponent(`cpe:2.3:a:${cpe[0]}:${cpe[1]}`)}&versionStart=${encodeURIComponent(version)}&versionStartType=including&versionEnd=${encodeURIComponent(version)}&versionEndType=including&resultsPerPage=200`
