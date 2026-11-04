/**
 * Which scanners run on a project, and how. Quick runs the fast, high-signal checks; Standard
 * adds the broad rule sets; Deep also reads the whole Git history and the noisier audit rules.
 */
import { existsSync, readdirSync, statSync } from 'fs'
import { extname, join } from 'path'
import type { Finding, ReviewDepth } from '../../shared/types'
import { dirs } from '../paths'
import { parseBandit, parseBearer, parseGitleaks, parseGosec, parseHadolint, parseZizmor, parseGrype, parseSyftLicences, parseCheckov, parseOsv, parseSemgrep, parseTrivy, parseTrufflehog } from './parse'

export const SKIP_DIRS = new Set(['node_modules', 'vendor', '.git', 'dist', 'build', '.next', '.nuxt', '.svelte-kit', '.output', 'target', 'bin', 'obj', '.venv', 'venv', '__pycache__', '.idea', '.vscode', 'coverage', 'Pods', 'DerivedData', '.turbo', '.cache', 'storage', 'bower_components'])

const LANG: Record<string, string> = {
  '.php': 'PHP', '.js': 'JavaScript', '.jsx': 'JavaScript', '.mjs': 'JavaScript', '.cjs': 'JavaScript', '.ts': 'TypeScript', '.tsx': 'TypeScript', '.vue': 'JavaScript', '.svelte': 'JavaScript',
  '.py': 'Python', '.go': 'Go', '.rb': 'Ruby', '.java': 'Java', '.kt': 'Kotlin', '.cs': 'C#', '.swift': 'Swift', '.rs': 'Rust', '.c': 'C', '.cpp': 'C++', '.h': 'C', '.scala': 'Scala',
  '.sol': 'Solidity', '.tf': 'Terraform', '.yaml': 'YAML', '.yml': 'YAML', '.sh': 'Shell', '.dart': 'Dart', '.ex': 'Elixir'
}

export interface ProjectStats {
  files: number
  languages: string[]
  git: boolean
  manifests: string[]
}

/** Counts source files per language, skipping dependencies and build output. */
export function projectStats(root: string): ProjectStats {
  const counts = new Map<string, number>()
  const manifests = new Set<string>()
  let files = 0
  const walk = (dir: string, depth: number): void => {
    if (depth > 12 || files > 60000) return
    let names: string[]
    try {
      names = readdirSync(dir)
    } catch {
      return
    }
    for (const n of names) {
      const p = join(dir, n)
      let st
      try {
        st = statSync(p)
      } catch {
        continue
      }
      if (st.isDirectory()) {
        if (!SKIP_DIRS.has(n) && !n.startsWith('.')) walk(p, depth + 1)
      } else {
        files++
        if (/^(composer\.lock|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|requirements\.txt|poetry\.lock|uv\.lock|go\.sum|Cargo\.lock|Gemfile\.lock|pom\.xml|build\.gradle|packages\.lock\.json|Dockerfile|docker-compose\.ya?ml)$/.test(n)) manifests.add(n)
        const l = LANG[extname(n).toLowerCase()]
        if (l && l !== 'YAML') counts.set(l, (counts.get(l) ?? 0) + 1)
      }
    }
  }
  walk(root, 0)
  return {
    files,
    languages: [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([l]) => l),
    git: existsSync(join(root, '.git')),
    manifests: [...manifests]
  }
}

/** Whether a project holds infrastructure as code worth Checkov's time. */
export function hasIac(root: string, stats: ProjectStats): boolean {
  if (stats.languages.includes('Terraform') || stats.manifests.some((m) => /Dockerfile|docker-compose/.test(m))) return true
  for (const p of ['.github/workflows', 'azure-pipelines.yml', 'k8s', 'kubernetes', 'helm', 'charts', 'infra', 'bicep', 'deploy']) if (existsSync(join(root, p))) return true
  return false
}

/** Dockerfiles in a project, as paths relative to it (Dockerfile, Containerfile, *.Dockerfile). */
export function findDockerfiles(root: string): string[] {
  const out: string[] = []
  const walk = (dir: string, depth: number): void => {
    if (depth > 6 || out.length >= 30) return
    let names: string[] = []
    try {
      names = readdirSync(dir)
    } catch {
      return
    }
    for (const n of names) {
      const p = join(dir, n)
      let st
      try {
        st = statSync(p)
      } catch {
        continue
      }
      if (st.isDirectory()) {
        if (!SKIP_DIRS.has(n) && !n.startsWith('.')) walk(p, depth + 1)
      } else if (/^(Dockerfile|Containerfile)(\..+)?$|\.(Dockerfile|dockerfile)$/.test(n)) out.push(p.slice(root.length + 1))
    }
  }
  walk(root, 0)
  return out
}

export interface ScannerRun {
  id: string
  tool: string
  label: string
  bin: string
  args: string[]
  /** Working folder; the project unless said otherwise. */
  cwd?: string
  /** The tool writes its report here; otherwise stdout is the report. */
  output?: string
  parse: (text: string, root: string) => Finding[]
  timeoutMs: number
  /** Run again with these when the first run fails (a rule pack that moved, say). */
  retryArgs?: string[]
}

const EXCLUDES = [...SKIP_DIRS].filter((d) => d !== '.git')

/** The scanners for one project, in the order they run. */
export function planScanners(root: string, stats: ProjectStats, depth: ReviewDepth, out: string): ScannerRun[] {
  const runs: ScannerRun[] = []
  const has = (l: string): boolean => stats.languages.includes(l)
  const min = 60 * 1000

  // Semgrep: registry rule packs (free, no login), plus your own rules from extensions.
  const packs = ['p/default', 'p/owasp-top-ten', 'p/cwe-top-25']
  if (depth !== 'quick') packs.push('p/secure-defaults', ...(has('PHP') ? ['p/php', 'p/phpcs-security-audit'] : []), ...(has('JavaScript') || has('TypeScript') ? ['p/javascript', 'p/typescript', 'p/react', 'p/nodejsscan'] : []), ...(has('Python') ? ['p/python', 'p/django', 'p/flask'] : []), ...(has('Go') ? ['p/golang'] : []), ...(has('Java') || has('Kotlin') ? ['p/java'] : []), ...(has('Ruby') ? ['p/ruby'] : []), ...(has('C#') ? ['p/csharp'] : []), ...(has('Terraform') ? ['p/terraform'] : []), 'p/docker', 'p/sql-injection', 'p/xss', 'p/command-injection', 'p/jwt', 'p/insecure-transport')
  if (depth === 'deep') packs.push('p/security-audit', 'p/gitleaks')
  const custom = join(dirs.extensions(), 'semgrep-rules')
  const hasCustom = existsSync(custom) && readdirSync(custom).some((f) => /\.ya?ml$/.test(f))
  runs.push({
    id: 'semgrep',
    tool: 'Semgrep',
    label: `Semgrep: ${packs.length} rule sets${hasCustom ? ' and your rules' : ''}`,
    bin: 'semgrep',
    args: ['scan', ...packs.flatMap((p) => ['--config', p]), ...(hasCustom ? ['--config', custom] : []), '--json', '--output', join(out, 'semgrep.json'), '--metrics', 'off', '--disable-version-check', '--timeout', '45', '--max-target-bytes', '2000000', '--jobs', '4', ...EXCLUDES.flatMap((d) => ['--exclude', d]), '.'],
    output: join(out, 'semgrep.json'),
    parse: parseSemgrep,
    timeoutMs: (depth === 'deep' ? 60 : 30) * min,
    retryArgs: ['scan', '--config', 'p/default', '--json', '--output', join(out, 'semgrep.json'), '--metrics', 'off', '--disable-version-check', ...EXCLUDES.flatMap((d) => ['--exclude', d]), '.']
  })

  if (depth !== 'quick' && ['JavaScript', 'TypeScript', 'Ruby', 'Java', 'PHP', 'Go', 'Python'].some(has)) {
    runs.push({
      id: 'bearer',
      tool: 'Bearer',
      label: 'Bearer: where sensitive data flows',
      bin: 'bearer',
      args: ['scan', '.', '--format', 'json', '--output', join(out, 'bearer.json'), '--quiet', '--exit-code', '0', '--skip-path', EXCLUDES.join(','), '--disable-version-check'],
      output: join(out, 'bearer.json'),
      parse: parseBearer,
      timeoutMs: 30 * min
    })
  }
  if (has('Python')) {
    runs.push({ id: 'bandit', tool: 'Bandit', label: 'Bandit: Python checks', bin: 'bandit', args: ['-r', '.', '-f', 'json', '-o', join(out, 'bandit.json'), '-q', '--exit-zero', '-x', EXCLUDES.map((d) => `./${d}`).join(',')], output: join(out, 'bandit.json'), parse: parseBandit, timeoutMs: 15 * min })
  }
  if (has('Go')) {
    runs.push({ id: 'gosec', tool: 'gosec', label: 'gosec: Go checks', bin: 'gosec', args: ['-fmt', 'json', '-out', join(out, 'gosec.json'), '-no-fail', '-quiet', './...'], output: join(out, 'gosec.json'), parse: parseGosec, timeoutMs: 15 * min })
  }

  // What the project is made of (SBOM, kept with the session for export), and licences worth knowing.
  if (depth !== 'quick') {
    runs.push({ id: 'syft', tool: 'Syft', label: 'Syft: every package and its licence (SBOM)', bin: 'syft', args: ['scan', 'dir:.', '-o', `cyclonedx-json=${join(out, 'sbom.cdx.json')}`, '-q'], output: join(out, 'sbom.cdx.json'), parse: parseSyftLicences, timeoutMs: 15 * min })
  }
  if (depth === 'deep') {
    runs.push({ id: 'grype', tool: 'Grype', label: 'Grype: a second opinion on package flaws', bin: 'grype', args: ['dir:.', '-o', 'json', '--file', join(out, 'grype.json'), '-q'], output: join(out, 'grype.json'), parse: parseGrype, timeoutMs: 20 * min })
  }
  if (hasIac(root, stats)) {
    runs.push({ id: 'checkov', tool: 'Checkov', label: 'Checkov: infrastructure as code', bin: 'checkov', args: ['-d', '.', '-o', 'json', '--quiet', '--compact', '--skip-download', '--framework', 'terraform', 'bicep', 'arm', 'kubernetes', 'helm', 'cloudformation', 'dockerfile', 'github_actions', 'azure_pipelines'], parse: parseCheckov, timeoutMs: 15 * min })
  }

  // CI workflows and Dockerfiles: their own checks, offline.
  if (existsSync(join(root, '.github', 'workflows'))) {
    runs.push({ id: 'zizmor', tool: 'zizmor', label: 'zizmor: GitHub Actions workflows', bin: 'zizmor', args: ['--offline', '--format', 'json', '--no-exit-codes', '.'], parse: parseZizmor, timeoutMs: 5 * min })
  }
  const dockerfiles = findDockerfiles(root)
  if (dockerfiles.length) {
    runs.push({ id: 'hadolint', tool: 'Hadolint', label: `Hadolint: ${dockerfiles.length} Dockerfile${dockerfiles.length === 1 ? '' : 's'}`, bin: 'hadolint', args: ['-f', 'json', '--no-fail', ...dockerfiles], parse: parseHadolint, timeoutMs: 5 * min })
  }

  // Secrets: the files now, and in Deep, every commit.
  const history = depth === 'deep' && stats.git
  runs.push({
    id: 'gitleaks',
    tool: 'Gitleaks',
    label: history ? 'Gitleaks: keys in files and the whole Git history' : 'Gitleaks: keys and passwords in files',
    bin: 'gitleaks',
    args: [history ? 'git' : 'dir', '.', '--report-format', 'json', '--report-path', join(out, 'gitleaks.json'), '--no-banner', '--redact', '--exit-code', '0', '--log-level', 'error'],
    output: join(out, 'gitleaks.json'),
    parse: parseGitleaks,
    timeoutMs: 20 * min
  })
  if (depth !== 'quick') {
    runs.push({
      id: 'trufflehog',
      tool: 'TruffleHog',
      label: history ? 'TruffleHog: 800+ key types, with history' : 'TruffleHog: 800+ key types',
      bin: 'trufflehog',
      // No verification: checking a key would send it to its provider.
      args: [...(history ? ['git', `file://${root}`] : ['filesystem', '.']), '--json', '--no-update', '--no-verification', '--log-level=-1'],
      parse: parseTrufflehog,
      timeoutMs: 20 * min
    })
  }

  // Dependencies: two databases see different advisories, duplicates are merged later.
  runs.push({ id: 'osv-scanner', tool: 'OSV-Scanner', label: 'OSV-Scanner: known flaws in packages', bin: 'osv-scanner', args: ['scan', 'source', '-r', '--format', 'json', '--output', join(out, 'osv.json'), '.'], output: join(out, 'osv.json'), parse: parseOsv, timeoutMs: 15 * min })
  if (depth !== 'quick') {
    runs.push({ id: 'trivy', tool: 'Trivy', label: 'Trivy: packages, Docker and infrastructure files', bin: 'trivy', args: ['fs', '--scanners', 'vuln,misconfig', '--format', 'json', '--output', join(out, 'trivy.json'), '--quiet', '--skip-dirs', 'node_modules', '--skip-dirs', 'vendor', '.'], output: join(out, 'trivy.json'), parse: parseTrivy, timeoutMs: 20 * min })
  }
  return runs
}
