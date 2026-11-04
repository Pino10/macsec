/**
 * The toolbox: every scanner MacSec uses, installed into ~/MacSec/tools and nowhere else.
 *
 * Release tools are downloaded from their official GitHub releases, checked against the checksum
 * file their authors publish, and unpacked into tools/bin. Python tools (Semgrep, Bandit...) are
 * installed by uv into tools/python, with uv's own Python, so nothing touches the Mac's Python.
 * Every tool then runs with a private home folder (tools/home), so caches, databases and
 * templates stay inside MacSec too.
 */
import { execFile } from 'child_process'
import { chmodSync, copyFileSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'fs'
import { join } from 'path'
import type { ToolCategory, ToolInfo } from '../shared/types'
import { dirs } from './paths'
import { USER_AGENT, downloadFile, extract, removeQuarantine, sha256File } from './download'
import { log } from './logs'

type Base = { id: string; name: string; category: ToolCategory; purpose: string; homepage: string; languages?: string[]; versionArgs?: string[] }
export type ToolDef =
  | (Base & { method: 'release'; repo: string; binaries: string[] })
  | (Base & { method: 'python'; pkg: string; binaries: string[]; with?: string[] })
  | (Base & { method: 'app'; apps: string[] })

export const CATALOG: ToolDef[] = [
  // Runtime for the Python tools.
  { id: 'uv', name: 'uv', category: 'runtime', method: 'release', repo: 'astral-sh/uv', binaries: ['uv'], purpose: 'Installs the Python-based scanners with their own Python, inside MacSec.', homepage: 'https://docs.astral.sh/uv/' },

  // Code
  { id: 'semgrep', name: 'Semgrep', category: 'code', method: 'python', pkg: 'semgrep', binaries: ['semgrep'], purpose: 'Finds risky code patterns in 30+ languages: injection, unsafe input, weak crypto, OWASP Top 10.', homepage: 'https://semgrep.dev' },
  { id: 'bearer', name: 'Bearer', category: 'code', method: 'release', repo: 'Bearer/bearer', binaries: ['bearer'], languages: ['JavaScript', 'TypeScript', 'Ruby', 'Java', 'PHP', 'Go', 'Python'], purpose: 'Follows sensitive data (passwords, personal data) through the code and flags where it leaks.', homepage: 'https://docs.bearer.com', versionArgs: ['version'] },
  { id: 'bandit', name: 'Bandit', category: 'code', method: 'python', pkg: 'bandit', with: ['bandit[sarif]'], binaries: ['bandit'], languages: ['Python'], purpose: 'Python security checks: shell injection, unsafe deserialization, weak hashing.', homepage: 'https://bandit.readthedocs.io' },
  { id: 'zizmor', name: 'zizmor', category: 'code', method: 'python', pkg: 'zizmor', binaries: ['zizmor'], purpose: 'GitHub Actions workflows: script injection, pull_request_target misuse, unpinned actions, leaked credentials. Runs offline.', homepage: 'https://docs.zizmor.sh' },
  { id: 'hadolint', name: 'Hadolint', category: 'code', method: 'release', repo: 'hadolint/hadolint', binaries: ['hadolint'], purpose: 'Dockerfiles: running as root, unpinned images, secrets in layers, risky shell steps.', homepage: 'https://github.com/hadolint/hadolint', versionArgs: ['--version'] },
  { id: 'gosec', name: 'gosec', category: 'code', method: 'release', repo: 'securego/gosec', binaries: ['gosec'], languages: ['Go'], purpose: 'Go security checks: SQL injection, file paths, TLS settings, unhandled errors.', homepage: 'https://securego.io', versionArgs: ['-version'] },

  // Secrets
  { id: 'gitleaks', name: 'Gitleaks', category: 'secrets', method: 'release', repo: 'gitleaks/gitleaks', binaries: ['gitleaks'], purpose: 'Finds passwords and API keys in files and in the whole Git history.', homepage: 'https://gitleaks.io', versionArgs: ['version'] },
  { id: 'trufflehog', name: 'TruffleHog', category: 'secrets', method: 'release', repo: 'trufflesecurity/trufflehog', binaries: ['trufflehog'], purpose: 'Recognises 800+ kinds of keys and tokens, including in Git history.', homepage: 'https://trufflesecurity.com/trufflehog' },

  // Dependencies and configuration
  { id: 'osv-scanner', name: 'OSV-Scanner', category: 'deps', method: 'release', repo: 'google/osv-scanner', binaries: ['osv-scanner'], purpose: 'Checks every package your project uses against Google’s open vulnerability database.', homepage: 'https://google.github.io/osv-scanner/' },
  { id: 'trivy', name: 'Trivy', category: 'deps', method: 'release', repo: 'aquasecurity/trivy', binaries: ['trivy'], purpose: 'Known vulnerabilities in packages, plus risky settings in Docker, Kubernetes and Terraform files.', homepage: 'https://trivy.dev', versionArgs: ['version'] },

  // Web
  { id: 'nuclei', name: 'Nuclei', category: 'web', method: 'release', repo: 'projectdiscovery/nuclei', binaries: ['nuclei'], purpose: 'Runs thousands of community checks for known problems against a site.', homepage: 'https://docs.projectdiscovery.io/tools/nuclei', versionArgs: ['-version'] },
  { id: 'katana', name: 'Katana', category: 'web', method: 'release', repo: 'projectdiscovery/katana', binaries: ['katana'], purpose: 'Crawls a site to find every page, form and endpoint before scanning.', homepage: 'https://docs.projectdiscovery.io/tools/katana', versionArgs: ['-version'] },
  { id: 'wpscan', name: 'WPScan', category: 'web', method: 'app', apps: brew('wpscan'), purpose: 'WordPress: the version, plugins and themes, and known problems in them. Used in web scans of WordPress sites when installed (brew install wpscanteam/tap/wpscan).', homepage: 'https://wpscan.com' },
  { id: 'subfinder', name: 'subfinder', category: 'web', method: 'release', repo: 'projectdiscovery/subfinder', binaries: ['subfinder'], purpose: 'Finds subdomains from public sources, for recon. Passive: it never contacts the target.', homepage: 'https://docs.projectdiscovery.io/tools/subfinder', versionArgs: ['-version'] },
  { id: 'httpx', name: 'httpx', category: 'web', method: 'release', repo: 'projectdiscovery/httpx', binaries: ['httpx'], purpose: 'Checks which addresses answer and what they run (server, framework, title).', homepage: 'https://docs.projectdiscovery.io/tools/httpx', versionArgs: ['-version'] },

  // Mobile apps
  { id: 'mobsfscan', name: 'mobsfscan', category: 'mobile', method: 'python', pkg: 'mobsfscan', binaries: ['mobsfscan'], languages: ['Java', 'Kotlin', 'Swift', 'Objective-C'], purpose: 'MobSF’s rules for Android and iOS source: insecure storage, weak crypto, WebView and network settings.', homepage: 'https://github.com/MobSF/mobsfscan' },
  { id: 'androguard', name: 'Androguard', category: 'mobile', method: 'python', pkg: 'androguard', binaries: ['androguard'], purpose: 'Reads a built Android app (.apk): its manifest, permissions and exported parts.', homepage: 'https://github.com/androguard/androguard' },

  // Cloud accounts (read-only)
  { id: 'scoutsuite', name: 'ScoutSuite', category: 'cloud', method: 'python', pkg: 'scoutsuite', binaries: ['scout'], purpose: 'Audits the settings of an Azure or AWS account against best practice. Only reads.', homepage: 'https://github.com/nccgroup/ScoutSuite' },
  { id: 'azure-cli', name: 'Azure CLI', category: 'cloud', method: 'python', pkg: 'azure-cli', binaries: ['az'], purpose: 'Signs in to Azure for the cloud audit. Its sign-in stays inside MacSec.', homepage: 'https://learn.microsoft.com/cli/azure/' },
  { id: 'awscli', name: 'AWS CLI', category: 'cloud', method: 'python', pkg: 'awscli', binaries: ['aws'], purpose: 'Reads your AWS profile for the cloud audit.', homepage: 'https://aws.amazon.com/cli/' },
  { id: 'cloudfox', name: 'CloudFox', category: 'cloud', method: 'release', repo: 'BishopFox/cloudfox', binaries: ['cloudfox'], purpose: 'Maps what an account can reach: roles, public storage, endpoints and secrets stores.', homepage: 'https://github.com/BishopFox/cloudfox', versionArgs: ['--version'] },
  { id: 'pmapper', name: 'PMapper', category: 'cloud', method: 'python', pkg: 'principalmapper', binaries: ['pmapper'], purpose: 'Finds AWS users and roles that could give themselves more access.', homepage: 'https://github.com/nccgroup/PMapper' },
  { id: 'gcloud', name: 'Google Cloud CLI', category: 'cloud', method: 'app', apps: [...brew('gcloud'), '/opt/homebrew/share/google-cloud-sdk/bin/gcloud', '/usr/local/share/google-cloud-sdk/bin/gcloud'], purpose: 'Detected when installed, for your own Google Cloud checks.', homepage: 'https://cloud.google.com/sdk/docs/install' },

  // Servers and ports (your own hosts)
  { id: 'naabu', name: 'naabu', category: 'network', method: 'release', repo: 'projectdiscovery/naabu', binaries: ['naabu'], purpose: 'Lists the open ports on a server you own, with plain connection checks.', homepage: 'https://docs.projectdiscovery.io/tools/naabu', versionArgs: ['-version'] },
  { id: 'nmap', name: 'Nmap', category: 'network', method: 'app', apps: brew('nmap'), purpose: 'Names the service and version on each open port. Used by the server audit when installed (brew install nmap). MacSec never runs its scripts.', homepage: 'https://nmap.org/download' },

  // Deeper analysis you open yourself
  { id: 'radare2', name: 'radare2', category: 'optional', method: 'app', apps: brew('r2'), purpose: 'Reverse engineering of app binaries, for when you want to look inside by hand.', homepage: 'https://rada.re' },
  { id: 'ghidra', name: 'Ghidra', category: 'optional', method: 'app', apps: [...brew('ghidraRun'), '/Applications/Ghidra.app'], purpose: 'The NSA’s free decompiler, for reading compiled apps by hand.', homepage: 'https://ghidra-sre.org' },
]

/** Where Homebrew puts a command, on Apple silicon and Intel Macs. */
function brew(bin: string): string[] {
  return [`/opt/homebrew/bin/${bin}`, `/usr/local/bin/${bin}`]
}

/** The path of a tool you installed yourself (Nmap, WPScan), if it is there. */
export function appPath(id: string): string | null {
  const t = toolDef(id)
  return t?.method === 'app' ? (t.apps.find((a) => existsSync(a)) ?? null) : null
}

export const toolDef = (id: string): ToolDef | undefined => CATALOG.find((t) => t.id === id)
export const toolPath = (bin: string): string => join(dirs.bin(), bin)

/** Environment every tool runs with: its caches and settings stay inside ~/MacSec/tools/home. */
/** Proxy and certificate settings a company network needs, passed through unchanged. */
const PASS = ['HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'no_proxy', 'ALL_PROXY', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE', 'NODE_EXTRA_CA_CERTS', 'GIT_SSL_CAINFO']

export function toolEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  const home = dirs.toolHome()
  const passed = Object.fromEntries(PASS.filter((k) => process.env[k]).map((k) => [k, process.env[k] as string]))
  return {
    ...passed,
    PATH: `${dirs.bin()}:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin`,
    HOME: home,
    XDG_CONFIG_HOME: join(home, '.config'),
    XDG_CACHE_HOME: join(home, '.cache'),
    XDG_DATA_HOME: join(home, '.local', 'share'),
    TMPDIR: join(home, 'tmp'),
    LANG: 'en_US.UTF-8',
    NO_COLOR: '1',
    TERM: 'dumb',
    // No phoning home from scanners.
    SEMGREP_SEND_METRICS: 'off',
    SEMGREP_ENABLE_VERSION_CHECK: '0',
    DO_NOT_TRACK: '1',
    BEARER_DISABLE_VERSION_CHECK: 'true',
    BEARER_DISABLE_DEFAULT_RULES: 'false',
    TRIVY_CACHE_DIR: join(home, '.cache', 'trivy'),
    PDCP_API_KEY: '',
    DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD: '',
    GIT_TERMINAL_PROMPT: '0',
    ...extra
  }
}

/** uv keeps its Pythons, tools and cache inside ~/MacSec/tools/python. */
function uvEnv(): NodeJS.ProcessEnv {
  const py = dirs.python()
  return toolEnv({
    UV_TOOL_DIR: join(py, 'tools'),
    UV_TOOL_BIN_DIR: dirs.bin(),
    UV_PYTHON_INSTALL_DIR: join(py, 'pythons'),
    UV_CACHE_DIR: join(py, 'cache'),
    UV_PYTHON_PREFERENCE: 'only-managed',
    UV_NO_MODIFY_PATH: '1'
  })
}

// ---------------------------------------------------------------- Picking the right download

export interface Asset {
  name: string
  url: string
}

const OS = /(darwin|macos|mac_?os|apple-darwin|osx)/i
const ARM = /(arm64|aarch64)/i
const X64 = /(amd64|x86_64|x64|64bit|64-bit)/i
const NOT_BINARY = /(\.(sha256|sha512|sig|asc|pem|sbom|spdx|json|txt|deb|rpm|apk|pkg|dmg|msi|intoto|jsonl)$|sbom|spdx|\.bundle$|checksums?)/i

/** The archive for this Mac, from a release's files. Prefers .tar.gz, then .zip, then a bare binary. */
export function pickAsset(assets: Asset[], arch: 'arm64' | 'x64' = process.arch === 'arm64' ? 'arm64' : 'x64'): Asset | null {
  const mine = assets.filter((a) => OS.test(a.name) && !NOT_BINARY.test(a.name) && (arch === 'arm64' ? ARM.test(a.name) : X64.test(a.name) && !ARM.test(a.name)))
  const rank = (n: string): number => (/\.(tar\.gz|tgz)$/i.test(n) ? 0 : /\.zip$/i.test(n) ? 1 : /\.tar\.(xz|bz2)$/i.test(n) ? 2 : /\.\w{2,4}$/.test(n) && !/_\d+$/.test(n) ? 4 : 3)
  return mine.sort((a, b) => rank(a.name) - rank(b.name))[0] ?? null
}

/** The checksum file that covers an asset: a shared list, or one file per asset. */
export function pickChecksum(assets: Asset[], asset: Asset): Asset | null {
  return (
    assets.find((a) => a.name === `${asset.name}.sha256`) ??
    assets.find((a) => /(checksums?|sha256sums?)(\.txt)?$/i.test(a.name) && !/\.(sig|pem|asc)$/i.test(a.name)) ??
    null
  )
}

/** Reads "hash  name" lines (or a bare hash for per-file checksums). */
export function hashFor(text: string, name: string): string | null {
  for (const line of text.split('\n')) {
    const m = /^([a-f0-9]{64})\s+\*?(.+)$/i.exec(line.trim())
    if (m && m[2].trim().split('/').pop() === name) return m[1].toLowerCase()
  }
  const lines = text.trim().split('\n')
  if (lines.length === 1) {
    const only = /^([a-f0-9]{64})\b/i.exec(lines[0].trim())
    if (only) return only[1].toLowerCase()
  }
  return null
}

async function latestRelease(repo: string): Promise<{ tag: string; assets: Asset[] }> {
  const res = await fetch(`https://api.github.com/repos/${repo}/releases/latest`, { headers: { 'User-Agent': USER_AGENT, Accept: 'application/vnd.github+json' }, signal: AbortSignal.timeout(30000) })
  if (res.status === 403 || res.status === 429) throw new Error('GitHub is limiting downloads for a moment. Try again in a few minutes.')
  if (!res.ok) throw new Error(`GitHub answered ${res.status} for ${repo}.`)
  const j = (await res.json()) as { tag_name: string; assets: { name: string; browser_download_url: string }[] }
  return { tag: j.tag_name, assets: j.assets.map((a) => ({ name: a.name, url: a.browser_download_url })) }
}

function findFile(dir: string, name: string, depth = 0): string | null {
  if (depth > 5) return null
  for (const f of readdirSync(dir)) {
    const p = join(dir, f)
    const st = lstatSync(p)
    if (st.isFile() && f === name) return p
    if (st.isDirectory()) {
      const hit = findFile(p, name, depth + 1)
      if (hit) return hit
    }
  }
  return null
}

function run(cmd: string, args: string[], env: NodeJS.ProcessEnv, timeout = 15 * 60 * 1000): Promise<string> {
  return new Promise((resolve, reject) =>
    execFile(cmd, args, { env, timeout, maxBuffer: 16 * 1024 * 1024 }, (err, out, stderr) =>
      err ? reject(new Error(String(stderr || err.message).trim().split('\n').slice(-3).join(' '))) : resolve(`${out}${stderr}`)
    )
  )
}

// ---------------------------------------------------------------- Versions and updates

const versionsFile = (): string => join(dirs.tools(), 'versions.json')
function installedTags(): Record<string, string> {
  try {
    return JSON.parse(readFileSync(versionsFile(), 'utf8')) as Record<string, string>
  } catch {
    return {}
  }
}
function recordTag(id: string, tag: string | null): void {
  const all = installedTags()
  if (tag) all[id] = tag.replace(/^v/, '')
  else delete all[id]
  writeFileSync(versionsFile(), JSON.stringify(all, null, 2))
}

/** Newest versions seen, so the Tools page can offer updates. Kept in tools/latest.json. */
const latestFile = (): string => join(dirs.tools(), 'latest.json')
function latestSeen(): { at: number; v: Record<string, string> } {
  try {
    return JSON.parse(readFileSync(latestFile(), 'utf8')) as { at: number; v: Record<string, string> }
  } catch {
    return { at: 0, v: {} }
  }
}

export function newer(a: string, b: string): boolean {
  const pa = a.replace(/^v/, '').split(/[.-]/).map((x) => parseInt(x, 10) || 0)
  const pb = b.replace(/^v/, '').split(/[.-]/).map((x) => parseInt(x, 10) || 0)
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) > (pb[i] ?? 0)
  return false
}

/** Asks GitHub and PyPI for each installed tool's newest version. */
export async function checkUpdates(): Promise<void> {
  const v: Record<string, string> = {}
  await Promise.allSettled(
    CATALOG.filter((t) => t.method !== 'app' && isInstalled(t)).map(async (t) => {
      if (t.method === 'release') v[t.id] = (await latestRelease(t.repo)).tag.replace(/^v/, '')
      else if (t.method === 'python') {
        const r = await fetch(`https://pypi.org/pypi/${t.pkg}/json`, { headers: { 'User-Agent': USER_AGENT }, signal: AbortSignal.timeout(15000) })
        if (r.ok) v[t.id] = ((await r.json()) as { info: { version: string } }).info.version
      }
    })
  )
  writeFileSync(latestFile(), JSON.stringify({ at: Date.now(), v }, null, 2))
}

/** Checks at most once a day. */
export async function checkUpdatesDaily(): Promise<string[]> {
  if (Date.now() - latestSeen().at > 24 * 3600 * 1000) await checkUpdates().catch(() => undefined)
  return (await listTools()).filter((t) => t.updateAvailable).map((t) => t.name)
}

async function installRelease(t: Extract<ToolDef, { method: 'release' }>, update: (p: number | null, l?: string) => void): Promise<void> {
  const rel = await latestRelease(t.repo)
  const asset = pickAsset(rel.assets)
  if (!asset) throw new Error(`${t.name} has no download for this Mac in its latest release.`)
  const archive = join(dirs.downloads(), asset.name)
  await downloadFile(asset.url, archive, (p) => update(p, `Downloading ${t.name}`))
  const sums = pickChecksum(rel.assets, asset)
  if (sums) {
    const text = await (await fetch(sums.url, { headers: { 'User-Agent': USER_AGENT } })).text()
    const want = hashFor(text, asset.name)
    if (!want || (await sha256File(archive)) !== want) {
      rmSync(archive, { force: true })
      throw new Error(`The ${t.name} download did not match its published checksum and was deleted.`)
    }
  } else {
    log('warn', `${t.name} publishes no checksum; installed from GitHub over HTTPS without one.`)
  }
  const staging = `${archive}-x`
  rmSync(staging, { recursive: true, force: true })
  mkdirSync(staging, { recursive: true })
  if (/\.(tar\.gz|tgz|zip|tar\.xz|tar\.bz2|tar)$/i.test(asset.name)) await extract(archive, staging)
  else copyFileSync(archive, join(staging, t.binaries[0]))
  for (const b of t.binaries) {
    const found = findFile(staging, b)
    if (!found) throw new Error(`${b} was not in the ${t.name} download.`)
    rmSync(toolPath(b), { force: true })
    copyFileSync(found, toolPath(b))
    chmodSync(toolPath(b), 0o755)
    await removeQuarantine(toolPath(b))
  }
  rmSync(staging, { recursive: true, force: true })
  rmSync(archive, { force: true })
  recordTag(t.id, rel.tag)
}

async function installPython(t: Extract<ToolDef, { method: 'python' }>, update: (p: number | null, l?: string) => void): Promise<void> {
  if (!existsSync(toolPath('uv'))) await installTool('uv', update)
  update(null, `Installing ${t.name}`)
  const spec = t.with?.[0] ?? t.pkg
  // --force reinstalls with the newest release, which is also how an update happens.
  await run(toolPath('uv'), ['tool', 'install', '--force', '--upgrade', '--python', '3.12', spec], uvEnv())
}

export async function installTool(id: string, update: (p: number | null, l?: string) => void): Promise<void> {
  const t = toolDef(id)
  if (!t) throw new Error(`Unknown tool ${id}.`)
  if (t.method === 'app') throw new Error(`${t.name} is an app you install yourself from ${t.homepage}.`)
  mkdirSync(dirs.bin(), { recursive: true })
  mkdirSync(join(dirs.toolHome(), 'tmp'), { recursive: true })
  if (t.method === 'release') await installRelease(t, update)
  else await installPython(t, update)
  versions.delete(t.id)
  log('info', `Installed ${t.name}${(await toolVersion(t)) ? ` ${await toolVersion(t)}` : ''}`)
}

export async function removeTool(id: string): Promise<void> {
  const t = toolDef(id)
  if (!t || t.method === 'app') return
  if (t.method === 'python' && existsSync(toolPath('uv'))) await run(toolPath('uv'), ['tool', 'uninstall', t.pkg], uvEnv()).catch(() => undefined)
  for (const b of t.binaries) rmSync(toolPath(b), { force: true })
  recordTag(t.id, null)
  versions.delete(t.id)
  log('info', `Removed ${t.name}`)
}

export function isInstalled(t: ToolDef): boolean {
  if (t.method === 'app') return t.apps.some((a) => existsSync(a))
  return t.binaries.every((b) => existsSync(toolPath(b)))
}

const versions = new Map<string, string | null>()
export function toolVersion(t: ToolDef): Promise<string | null> {
  if (!isInstalled(t) || t.method === 'app') return Promise.resolve(null)
  return new Promise((resolve) =>
    execFile(toolPath(t.binaries[0]), t.versionArgs ?? ['--version'], { env: toolEnv(), timeout: 20000 }, (_e, out, err) => {
      const v = /v?(\d+\.\d+(?:\.\d+)?)/.exec(`${out}\n${err}`)?.[1] ?? null
      versions.set(t.id, v)
      resolve(v)
    })
  )
}

export async function listTools(): Promise<ToolInfo[]> {
  const latest = latestSeen().v
  const tags = installedTags()
  return Promise.all(
    CATALOG.map(async (t) => {
      const version = versions.get(t.id) ?? (await toolVersion(t)) ?? tags[t.id] ?? null
      const have = tags[t.id] ?? version
      return {
      id: t.id,
      name: t.name,
      category: t.category,
      purpose: t.purpose,
      homepage: t.homepage,
      method: t.method,
      languages: t.languages ?? [],
      installed: isInstalled(t),
      version,
      latest: latest[t.id] ?? null,
      updateAvailable: isInstalled(t) && !!have && !!latest[t.id] && newer(latest[t.id], have)
      }
    })
  )
}

/** Refreshes the scanners' own databases and rules (Trivy's vulnerability database, Nuclei templates). */
export async function updateToolData(update: (p: number | null, l?: string) => void): Promise<void> {
  if (existsSync(toolPath('trivy'))) {
    update(null, 'Updating Trivy’s vulnerability database')
    await run(toolPath('trivy'), ['image', '--download-db-only', '--quiet'], toolEnv()).catch((e) => log('warn', `Trivy database: ${(e as Error).message}`))
  }
  if (existsSync(toolPath('nuclei'))) {
    update(null, 'Updating Nuclei templates')
    await run(toolPath('nuclei'), ['-update-templates', '-ud', nucleiTemplatesDir(), '-silent'], toolEnv()).catch((e) => log('warn', `Nuclei templates: ${(e as Error).message}`))
  }
}

export const nucleiTemplatesDir = (): string => join(dirs.tools(), 'nuclei-templates')
