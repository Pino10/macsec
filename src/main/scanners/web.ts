/**
 * Reading web scanners' output, plus MacSec's own read-only checks: security headers, cookies,
 * and files that should never be public.
 */
import type { Finding, Severity } from '../../shared/types'
import { fid, sev } from './parse'

const json = <T>(t: string): T | null => {
  try {
    return JSON.parse(t) as T
  } catch {
    return null
  }
}
const lines = <T>(t: string): T[] =>
  t
    .split('\n')
    .map((l) => json<T>(l.trim()))
    .filter((x): x is T => !!x)

const w = (tool: string, f: Omit<Finding, 'id' | 'tool' | 'category'>, category: Finding['category'] = 'web'): Finding => ({ id: fid(tool, f.url, f.title, f.advisory), tool, category, ...f })

// ---------------------------------------------------------------- Nuclei

export function parseNuclei(jsonl: string): Finding[] {
  type R = {
    'template-id': string
    info: { name: string; severity: string; description?: string; remediation?: string; reference?: string[] | null; classification?: { 'cwe-id'?: string[] | null; 'cve-id'?: string[] | null } }
    'matched-at'?: string
    host?: string
    'extracted-results'?: string[]
    'matcher-name'?: string
  }
  return lines<R>(jsonl)
    .filter((r) => r['template-id'] && r.info)
    .map((r) =>
      w('Nuclei', {
        severity: sev(r.info.severity === 'unknown' ? 'info' : r.info.severity),
        title: `${r.info.name}${r['matcher-name'] ? ` (${r['matcher-name']})` : ''}`,
        url: r['matched-at'] ?? r.host,
        file: r['matched-at'] ?? r.host,
        cwe: r.info.classification?.['cwe-id']?.[0]?.toUpperCase(),
        advisory: r.info.classification?.['cve-id']?.[0]?.toUpperCase() ?? r['template-id'],
        description: [r.info.description?.trim(), r['extracted-results']?.length ? `Found: ${r['extracted-results'].slice(0, 5).join(', ')}` : ''].filter(Boolean).join('\n'),
        fix: r.info.remediation?.trim()
      })
    )
}

// ---------------------------------------------------------------- httpx and Katana

export interface Fingerprint {
  url: string
  status?: number
  title?: string
  server?: string
  tech: string[]
}

export function parseHttpx(jsonl: string): Fingerprint[] {
  type R = { url: string; status_code?: number; title?: string; webserver?: string; tech?: string[] }
  return lines<R>(jsonl).map((r) => ({ url: r.url, status: r.status_code, title: r.title, server: r.webserver, tech: r.tech ?? [] }))
}

/** Every URL Katana found, de-duplicated, same host only. */
export function parseKatana(jsonl: string, host: string): string[] {
  type R = { request?: { endpoint?: string; method?: string } }
  const out = new Set<string>()
  for (const r of lines<R>(jsonl)) {
    const u = r.request?.endpoint
    if (!u) continue
    try {
      if (new URL(u).host === host) out.add(u.split('#')[0])
    } catch {
      // Not a URL.
    }
  }
  return [...out]
}

// ---------------------------------------------------------------- Exposed files

/** How much a reachable path matters, from its name. */
export function pathSeverity(path: string, status: number): Severity {
  const p = path.toLowerCase()
  if (status === 404) return 'info'
  const open = status >= 200 && status < 300
  if (/(^|\/)\.(git|svn|hg)(\/|$)|\.env($|\.)|wp-config\.php\.(bak|old|save|orig)|\.(sql|sql\.gz|bak|backup|dump|old|orig|swp|tar\.gz|zip)$|id_rsa|\.htpasswd|credentials|secrets?\.(json|ya?ml)/.test(p)) return open ? 'critical' : 'medium'
  if (/phpinfo|server-status|server-info|actuator|debug|_profiler|telescope|horizon|elmah|trace\.axd|console|adminer|phpmyadmin|\.ds_store|config\.(php|json|ya?ml)\b/.test(p)) return open ? 'high' : 'low'
  if (/admin|login|dashboard|manage|swagger|api-docs|openapi|graphql|graphiql|composer\.(json|lock)|package(-lock)?\.json|\.well-known/.test(p)) return open ? 'low' : 'info'
  return 'info'
}

// ---------------------------------------------------------------- Headers and cookies

/** MacSec's own check of one response's security headers and cookies. */
export function checkHeaders(url: string, headers: Headers, setCookies: string[]): Finding[] {
  const out: Finding[] = []
  const https = url.startsWith('https://')
  const h = (n: string): string | null => headers.get(n)
  const add = (severity: Severity, title: string, fix: string, cwe?: string, description?: string): void => {
    out.push(w('MacSec', { severity, title, url, file: url, cwe, fix, description }, 'web'))
  }
  if (https && !h('strict-transport-security')) add('medium', 'No Strict-Transport-Security header', 'Send Strict-Transport-Security: max-age=31536000; includeSubDomains so browsers always use HTTPS.', 'CWE-319')
  const csp = h('content-security-policy')
  if (!csp) add('medium', 'No Content-Security-Policy', 'Add a Content-Security-Policy. Start with default-src \'self\' and loosen it only where needed. It is the strongest defence against cross-site scripting.', 'CWE-693')
  else if (/unsafe-inline|unsafe-eval|\*/.test(csp)) add('low', 'Content-Security-Policy allows unsafe sources', 'Remove \'unsafe-inline\', \'unsafe-eval\' and wildcards; use nonces or hashes for inline scripts.', 'CWE-693', `Current policy: ${csp.slice(0, 300)}`)
  if (!h('x-frame-options') && !/frame-ancestors/.test(csp ?? '')) add('medium', 'Page can be framed by other sites (clickjacking)', 'Add frame-ancestors \'self\' to the Content-Security-Policy, or X-Frame-Options: DENY.', 'CWE-1021')
  if (h('x-content-type-options')?.toLowerCase() !== 'nosniff') add('low', 'No X-Content-Type-Options: nosniff', 'Send X-Content-Type-Options: nosniff.', 'CWE-693')
  if (!h('referrer-policy')) add('low', 'No Referrer-Policy', 'Send Referrer-Policy: strict-origin-when-cross-origin.')
  const server = [h('server'), h('x-powered-by'), h('x-aspnet-version'), h('x-generator')].filter((v): v is string => !!v && /\d/.test(v))
  if (server.length) add('low', 'Server reveals software versions', 'Hide version numbers (Apache: ServerTokens Prod; Nginx: server_tokens off; PHP: expose_php = Off).', 'CWE-200', `Headers say: ${server.join(', ')}`)
  const acao = h('access-control-allow-origin')
  if (acao === '*' && h('access-control-allow-credentials') === 'true') add('high', 'Any site may read responses with the visitor’s cookies (CORS)', 'Allow only your own origins, never * together with credentials.', 'CWE-942')
  for (const c of setCookies) {
    const name = c.split('=')[0].trim()
    const flags = c.toLowerCase()
    const sessionLike = /sess|auth|token|remember|jwt|sid|laravel|xsrf|csrf/i.test(name)
    const missing = [https && !/;\s*secure/.test(flags) ? 'Secure' : '', !/;\s*httponly/.test(flags) && !/xsrf|csrf/i.test(name) ? 'HttpOnly' : '', !/;\s*samesite=/.test(flags) ? 'SameSite' : ''].filter(Boolean)
    if (missing.length) add(sessionLike ? 'medium' : 'low', `Cookie "${name}" is missing ${missing.join(', ')}`, `Set ${missing.join(', ')} on this cookie.`, 'CWE-614')
  }
  return out
}

/** A small list of paths that should never be public, used when no wordlist is added. */
export const SENSITIVE_PATHS = [
  // The most dangerous first: Quick mode checks only the start of this list.
  '.env', '.git/HEAD', '.git/config', 'phpinfo.php', 'info.php', '.env.local', '.env.production', '.env.backup', '.env.bak', '.env.old',
  'storage/logs/laravel.log', 'wp-config.php.bak', 'wp-config.php.old', 'wp-config.php~', 'wp-content/debug.log', 'backup.sql', 'db.sql', 'database.sql', 'dump.sql', 'backup.zip',
  '.svn/entries', '.hg/requires', '.DS_Store', '.htpasswd', 'id_rsa', '.ssh/id_rsa', 'credentials.json', 'secrets.json', 'secrets.yml', 'config.json',
  'server-status', 'server-info', 'actuator/env', 'actuator/heapdump', 'actuator', '_profiler', '_profiler/phpinfo', 'telescope', 'horizon', 'adminer.php',
  'phpmyadmin/', 'elmah.axd', 'trace.axd', 'debug.log', 'error_log',
  'test.php', 'i.php', 'php.php', 'site.zip', 'www.zip', 'web.zip', 'backup.tar.gz', 'data.sql', 'users.sql', 'wp-config.php.save', 'wp-config.php.orig',
  'config.php.bak', 'configuration.php.bak', 'settings.php.bak', 'config.yml', 'config.yaml', 'appsettings.json', 'appsettings.Development.json', 'web.config', 'web.config.bak', '.npmrc',
  'composer.json', 'composer.lock', 'package.json', 'package-lock.json', 'yarn.lock', 'Gemfile.lock', 'requirements.txt', 'Dockerfile', 'docker-compose.yml', '.gitlab-ci.yml',
  'actuator/health', 'actuator/mappings', 'status', 'health', 'metrics', 'debug', 'trace', 'console', 'pma/', 'cpanel',
  'admin', 'administrator', 'login', 'wp-admin/', 'wp-login.php', 'user/login', 'dashboard', 'manage',
  'api', 'api/v1', 'api/docs', 'api-docs', 'swagger', 'swagger.json', 'swagger-ui.html', 'swagger/index.html', 'openapi.json', 'openapi.yaml', 'v2/api-docs', 'v3/api-docs', 'graphql', 'graphiql', 'altair',
  'logs/', 'log/', 'error.log', 'npm-debug.log', 'uploads/', 'tmp/', 'temp/', 'cache/', 'old/', 'bak/', 'backup/', 'dev/', 'staging/',
  'crossdomain.xml', 'clientaccesspolicy.xml', '.well-known/security.txt', 'readme.html', 'CHANGELOG.md'
]
