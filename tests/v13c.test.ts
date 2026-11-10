import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
import { advertisedMethods, bannersOf, compareVersions, corsReflection, detectWaf, dirListing, errorLeak, fileShows, libsIn, matchNvd, nvdUrl, proofOf, TEST_ORIGIN, versionSeverity } from '../src/main/seckit/confirm'
import { exposureReal } from '../src/main/seckit/recon'

const h = (o: Record<string, string>): { get: (n: string) => string | null } => ({ get: (n) => o[n.toLowerCase()] ?? null })

describe('proof: what is kept and what is not', () => {
  it('records the request, a fingerprint and the facts, and the command to repeat it', () => {
    const body = 'ref: refs/heads/main\n'
    const p = proofOf({ url: 'https://shop.example.com/.git/HEAD', status: 200, headers: h({ 'content-type': 'text/plain' }), body, shows: ['starts with "ref: refs/"'], sent: { Range: 'bytes=0-65535' } })
    expect(p.request).toBe('GET https://shop.example.com/.git/HEAD')
    expect(p.status).toBe(200)
    expect(p.bytes).toBe(body.length)
    expect(p.sha256).toMatch(/^[0-9a-f]{64}$/)
    expect(p.reproduce).toBe(`curl -sS -i -H 'Range: bytes=0-65535' 'https://shop.example.com/.git/HEAD'`)
  })
  it('quotes addresses safely in the command', () => {
    const p = proofOf({ url: "https://x.example/a'b", status: 200, headers: h({}), body: '', shows: [] })
    expect(p.reproduce).toBe(`curl -sS -i 'https://x.example/a'\\''b'`)
  })
})

describe('files: only the real file counts, and secret values are never kept', () => {
  const env = 'APP_NAME=Shop\nAPP_KEY=base64:K7f3n2Q9vXr5Lm8TqWz1Yc4HdJ6bNpA0sEuG3iOxRtU=\nDB_PASSWORD=hunter2hunter2hunter2\nSTRIPE_SECRET=sk_live_51H8abcdefghijklmnop\n'
  it('names the settings in a .env and nothing else', () => {
    const shows = fileShows('.env', env)!
    expect(shows.join(' ')).toContain('APP_KEY')
    expect(shows.join(' ')).toContain('DB_PASSWORD')
    expect(shows.join(' ')).not.toMatch(/hunter2|sk_live|K7f3n2Q9/)
  })
  it('does not accept a web page that answers 200 for every path', () => {
    const page = '<!doctype html><html><head><title>Shop</title></head><body>Welcome</body></html>'
    for (const p of ['.env', '.git/HEAD', '.git/config', 'backup.sql', 'composer.json', 'Dockerfile', 'id_rsa']) expect(fileShows(p, page)).toBeNull()
  })
  it('recognises real files', () => {
    expect(fileShows('.git/config', '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://ci:ghp_abcdefghijklmn12345@github.com/acme/shop.git\n')?.join(' ')).toContain('contains a user name and password')
    expect(fileShows('.git/config', '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://ci:ghp_abcdefghijklmn12345@github.com/acme/shop.git\n')?.join(' ')).not.toContain('ghp_')
    expect(fileShows('backup.sql', '-- MySQL dump 10.13  Distrib 8.0.34\nCREATE TABLE `users` (')).not.toBeNull()
    expect(fileShows('wp-config.php.bak', "define( 'DB_NAME', 'wp' );\ndefine( 'DB_PASSWORD', 'secret-value-here' );")?.join(' ')).not.toContain('secret-value-here')
    expect(fileShows('id_rsa', '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk')?.join(' ')).not.toContain('b3BlbnNz')
    expect(fileShows('actuator/heapdump', 'JAVA PROFILE 1.0.2\u0000')).not.toBeNull()
    expect(fileShows('backup.zip', 'PK\u0003\u0004\u0014\u0000')).not.toBeNull()
    expect(fileShows('storage/logs/laravel.log', '[2026-11-02 10:14:55] production.ERROR: SQLSTATE[HY000]')).not.toBeNull()
  })
  it('keeps the old rules of exposureReal', () => {
    expect(exposureReal('.git/HEAD', 200, 'ref: refs/heads/main', null)).toBe(true)
    expect(exposureReal('.git/HEAD', 404, 'ref: refs/heads/main', null)).toBe(false)
    expect(exposureReal('.env', 200, env, { status: 200, length: env.length + 10 })).toBe(false)
    expect(exposureReal('robots.txt', 200, 'User-agent: *\nDisallow: /admin', null)).toBe(true)
  })
})

describe('folder listings', () => {
  const apache = '<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1><pre><a href="?C=N;O=D">Name</a><hr><a href="/">Parent Directory</a>\n<a href="invoice-2024.pdf">invoice-2024.pdf</a>\n<a href="photo.jpg">photo.jpg</a></pre></body></html>'
  it('recognises an Apache listing and names the files', () => {
    const l = dirListing(apache)!
    expect(l.shows.join(' ')).toContain('invoice-2024.pdf')
  })
  it('ignores an ordinary page and an empty listing', () => {
    expect(dirListing('<html><title>Uploads</title><body>Upload your file</body></html>')).toBeNull()
    expect(dirListing('<html><title>Index of /x</title><body><h1>Index of /x</h1></body></html>')).toBeNull()
  })
})

describe('CDN and web firewall, from the headers', () => {
  it('names Cloudflare from its headers and cookie', () => {
    const w = detectWaf(h({ server: 'cloudflare', 'cf-ray': '8a1b2c3d4e5f-AMS' }), '__cf_bm=abc; path=/')
    expect(w.map((x) => x.name)).toEqual(['Cloudflare'])
    expect(w[0].shows.length).toBe(3)
  })
  it('sees nothing when there is nothing', () => {
    expect(detectWaf(h({ server: 'nginx' }), '')).toEqual([])
  })
})

describe('error pages that give the app away', () => {
  it('recognises the Laravel debug page and a Python traceback', () => {
    expect(errorLeak(404, '<title>Whoops! There was an error.</title><div>Illuminate\\Database\\QueryException</div>')?.stack).toBe('Laravel')
    expect(errorLeak(500, 'Traceback (most recent call last):\n  File "/srv/app/views.py", line 12, in index')?.stack).toBe('Python')
    expect(errorLeak(500, "<h1>Server Error in '/' Application.</h1><b>Stack Trace:</b>")?.stack).toBe('ASP.NET')
  })
  it('ignores a plain not-found page and anything that is not an error', () => {
    expect(errorLeak(404, '<html><body><h1>Not Found</h1><p>The requested URL was not found.</p></body></html>')).toBeNull()
    expect(errorLeak(200, 'Traceback (most recent call last):')).toBeNull()
  })
})

describe('cross-origin sharing', () => {
  it('is high when our made-up origin is repeated and cookies are allowed', () => {
    const r = corsReflection(TEST_ORIGIN, h({ 'access-control-allow-origin': TEST_ORIGIN, 'access-control-allow-credentials': 'true' }))
    expect(r?.severity).toBe('high')
  })
  it('is low without cookies, and nothing for a fixed origin or a wildcard', () => {
    expect(corsReflection(TEST_ORIGIN, h({ 'access-control-allow-origin': TEST_ORIGIN }))?.severity).toBe('low')
    expect(corsReflection(TEST_ORIGIN, h({ 'access-control-allow-origin': 'https://app.example.com', 'access-control-allow-credentials': 'true' }))).toBeNull()
    expect(corsReflection(TEST_ORIGIN, h({ 'access-control-allow-origin': '*' }))).toBeNull()
    expect(corsReflection(TEST_ORIGIN, h({}))).toBeNull()
  })
  it('reports only the risky methods a server says it allows', () => {
    expect(advertisedMethods('GET, HEAD, OPTIONS, TRACE, DELETE')).toEqual(['TRACE', 'DELETE'])
    expect(advertisedMethods('GET, POST, HEAD')).toEqual([])
    expect(advertisedMethods(null)).toEqual([])
  })
})

describe('versions', () => {
  it('compares versions, including letters', () => {
    expect(compareVersions('1.18.0', '1.20.1')).toBeLessThan(0)
    expect(compareVersions('2.4.49', '2.4.9')).toBeGreaterThan(0)
    expect(compareVersions('1.1.1k', '1.1.1')).toBeGreaterThan(0)
    expect(compareVersions('1.2', '1.2.0')).toBe(0)
  })
  it('reads versions the server states, and notes a distribution that patches quietly', () => {
    const p = bannersOf(h({ server: 'Apache/2.4.41 (Ubuntu)', 'x-powered-by': 'PHP/7.4.3' }), '<meta name="generator" content="WordPress 6.2.1" />')
    expect(p.map((x) => `${x.name} ${x.version}`)).toEqual(['Apache HTTP Server 2.4.41', 'PHP 7.4.3', 'WordPress 6.2.1'])
    expect(p[0].distro).toBe('Ubuntu')
    expect(bannersOf(h({ server: 'nginx' }), '')).toEqual([])
    expect(bannersOf(h({ server: 'Apache-Coyote/1.1' }), '')).toEqual([])
  })
  it('reads library versions from a script banner or file name', () => {
    expect(libsIn('https://x.example/js/jquery.min.js', '/*! jQuery v3.4.1 | (c) JS Foundation */').map((x) => `${x.name} ${x.version}`)).toEqual(['jQuery 3.4.1'])
    expect(libsIn('https://x.example/js/bootstrap-3.3.7.min.js', 'var a=1').map((x) => `${x.name} ${x.version}`)).toEqual(['Bootstrap 3.3.7'])
    expect(libsIn('https://x.example/app.js', 'console.log(1)')).toEqual([])
  })
  it('matches only the same product with a version range that holds the version', () => {
    const fx = readFileSync(join(__dirname, 'fixtures', 'nvd-nginx.json'), 'utf8')
    const nginx = { cpe: [['f5', 'nginx'], ['nginx', 'nginx']] as [string, string][], version: '1.18.0' }
    const m = matchNvd(fx, nginx)
    expect(m.map((x) => x.id)).toEqual(['CVE-2021-23017', 'CVE-2022-41741'])
    expect(m[0].kev).toBe(true)
    expect(m[0].score).toBe(8.1)
    expect(matchNvd(fx, { ...nginx, version: '1.22.0' }).map((x) => x.id)).toEqual(['CVE-2022-41741'])
    expect(matchNvd(fx, { ...nginx, version: '1.24.0' })).toEqual([])
    expect(matchNvd('not json', nginx)).toEqual([])
  })
  it('never calls a version match critical, and rates an exploited flaw highest', () => {
    expect(versionSeverity([])).toBe('info')
    expect(versionSeverity([{ id: 'a', score: 9.8, summary: '', kev: false, conditional: false }])).toBe('medium')
    expect(versionSeverity([{ id: 'a', score: 5, summary: '', kev: true, conditional: false }])).toBe('high')
    expect(versionSeverity([{ id: 'a', score: 5, summary: '', kev: false, conditional: false }])).toBe('low')
  })
  it('asks the vulnerability database for one product and the range around one version', () => {
    const u = new URL(nvdUrl(['f5', 'nginx'], '1.18.0'))
    expect(u.hostname).toBe('services.nvd.nist.gov')
    expect(u.searchParams.get('virtualMatchString')).toBe('cpe:2.3:a:f5:nginx')
    expect(u.searchParams.get('versionStart')).toBe('1.18.0')
  })
})
