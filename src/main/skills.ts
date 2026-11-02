/**
 * Skills for Claude Code. MacSec ships its own security plugin (written into
 * ~/MacSec/tools/claude-plugin) and loads it, plus your own skills from
 * ~/MacSec/extensions/claude, for MacSec's reviews only, with --plugin-dir. Nothing is
 * installed into your normal Claude Code setup.
 */
import { existsSync, mkdirSync, readdirSync, writeFileSync } from 'fs'
import { join } from 'path'
import { dirs } from './paths'

export const builtinPluginDir = (): string => join(dirs.tools(), 'claude-plugin')
export const userPluginDir = (): string => join(dirs.extensions(), 'claude')

const SKILLS: Record<string, { description: string; body: string }> = {
  'security-code-review': {
    description: 'Methodical security code review of a whole project: entry points, trust boundaries, authentication, authorization, injection, data exposure. Use for any security review MacSec asks for.',
    body: `# Security code review

Work like a senior application security engineer. Read code, do not guess.

## 1. Map the project
- Framework and language; where routes are declared (routes/*.php, app.get(...), @app.route, urls.py, controllers, handlers, GraphQL resolvers, RPC, CLI commands, queue jobs, webhooks, cron).
- Trust boundaries: what comes from users (request params, headers, cookies, uploaded files, webhooks, third-party callbacks) and where it goes (database, shell, filesystem, HTML, other services).
- How sign-in works (sessions, JWT, API keys, OAuth) and where it is enforced (middleware, guards, decorators, policies).

## 2. Check each entry point
For every route that reads or changes data:
1. Is sign-in required? Find the middleware or guard actually applied, not the one you expect.
2. Is the user allowed to touch THIS record? Look for ids from the request used in queries without an ownership or policy check (IDOR, CWE-639).
3. Mass assignment: request data passed whole into create/update (CWE-915).
4. Input reaching a dangerous sink: raw SQL, shell, eval, templates, file paths, redirects, outbound URLs (SSRF), deserialization, XML parsers.
5. Output: unescaped user data in HTML, JSON with sensitive fields, verbose errors.

## 3. Cross-cutting
- Passwords: strong hashing (bcrypt/argon2), reset tokens random and expiring, rate limits on login, reset and OTP.
- Sessions and cookies: Secure, HttpOnly, SameSite; session id rotated at login; logout invalidates.
- CSRF on state-changing forms; CORS only for known origins.
- Crypto: no home-made crypto, no ECB, no static IVs, no MD5/SHA1 for passwords, keys not in code.
- Configuration: debug off in production, secrets in environment, safe defaults.
- File uploads: type and size checked, stored outside the web root, names not trusted.
- Logging: no secrets or personal data in logs.

## 4. Framework notes
- **Laravel**: \`$request->all()\` into \`create()\` without \`$fillable\`; \`DB::raw\`, \`whereRaw\`, \`selectRaw\` with input; \`{!! !!}\`; routes without \`auth\` middleware; \`Gate\`/\`Policy\` missing on show/update/delete; \`APP_DEBUG=true\`.
- **Symfony / PHP**: \`$_GET\`/\`$_POST\` into \`mysqli_query\`, \`exec\`, \`include\`; \`unserialize\` on input.
- **Node / Express / Next.js**: \`req.query\` into SQL strings, \`child_process\`, \`eval\`; \`dangerouslySetInnerHTML\`; API routes without session checks; \`cors({ origin: true, credentials: true })\`; prototype pollution via merge.
- **Python (Django, Flask, FastAPI)**: \`raw()\`, \`extra()\`, f-strings in SQL; \`|safe\`, \`mark_safe\`; \`pickle\`, \`yaml.load\`; views without \`login_required\`/\`Depends\`; \`DEBUG = True\`.
- **Go**: \`fmt.Sprintf\` into SQL; \`exec.Command\` with input; missing auth middleware on routers.
- **.NET / Java**: string-built queries, \`[AllowAnonymous]\` where it should not be, insecure deserializers.

## 5. Judge scanner results
For each scanner finding: open the file, follow the data. Confirm only when untrusted data really reaches the sink, or the secret is real (not an example, test or placeholder). Explain your reason in one sentence.

Use the security-report skill for the write-up.`
  },
  'secrets-triage': {
    description: 'Decide whether a key or password found in code is real, how serious it is, and how to rotate it. Use for any secret finding.',
    body: `# Secrets triage

1. **Real or not?** Placeholders (\`your-key-here\`, \`xxxx\`, \`changeme\`), test fixtures, documented example keys and public keys are not secrets. Live-looking prefixes are: \`sk_live_\`, \`AKIA\`, \`ghp_\`, \`github_pat_\`, \`xoxb-\`, \`AIza\`, private keys, connection strings with passwords, Azure AD client secrets (40 characters, often with \`~\`).
2. **Where?** In a file now, or only in Git history (still exposed: history is cloned with the repository).
3. **Severity:** production credentials for cloud, payment, identity (Azure AD, Okta, Auth0) or databases: critical. Third-party APIs with billing: high. Test-mode keys: medium.
4. **Fix, in this order:** revoke and replace the key at the provider (Azure portal > App registrations > Certificates & secrets; AWS IAM; Stripe dashboard; GitHub settings), then move it to environment variables or a secret store (Azure Key Vault, AWS Secrets Manager, Laravel .env), then remove it from history only if needed (git filter-repo) and force everyone to re-clone.
5. Never print the full value: show the first 4 characters only.`
  },
  'dependency-triage': {
    description: 'Decide whether a vulnerable package actually affects the project and how to upgrade safely. Use for package advisories from OSV-Scanner or Trivy.',
    body: `# Dependency triage

1. Is the package a direct dependency (composer.json, package.json, requirements, go.mod) or pulled in by another one?
2. Is the vulnerable function or feature used? Search the code for it. Unused paths lower the risk, they do not remove it.
3. Is it reachable from user input or the network?
4. Fix: the smallest upgrade that includes the fix (patch or minor first). For a dependency of a dependency, upgrade the parent or use an override/resolution. Mention breaking changes in major upgrades.
5. Rate: reachable remote code execution or auth bypass: critical; reachable data exposure or injection: high; denial of service or unreachable: medium or low.`
  },
  'security-report': {
    description: 'How MacSec security reports are written: tailored, with evidence, severity reasoning, impact, fixed code and verification. Use when writing any review report.',
    body: `# Security report

The reader owns this code and wants to fix it today.

- Start with an executive summary: the state in 3 to 5 sentences and the single most urgent fix.
- A risk overview table: severity, finding, where, status.
- Each finding: **Where** (file:line), **Evidence** (the exact code, secrets masked after 4 characters), **Why it is rated** this severity *for this project*, **Impact** in plain words (no working exploit), **Fix** with corrected code, **How to verify**.
- Severity: critical = remote takeover, auth bypass, live production secrets, data of all users; high = one user's data exposed or changed by another, injection reachable by signed-in users; medium = needs unusual conditions or exposes limited information; low = hardening.
- Be specific: name the route, the function, the variable. No generic advice that would fit any project.
- Say what you could not check.`
  }
}

/** Writes the built-in plugin (refreshed every start) and creates your own skills folder. */
export function ensureSkills(): void {
  const root = builtinPluginDir()
  mkdirSync(join(root, '.claude-plugin'), { recursive: true })
  writeFileSync(join(root, '.claude-plugin', 'plugin.json'), JSON.stringify({ name: 'macsec-security', version: '1.0.0', description: 'MacSec security review skills: methodology, secrets, dependencies and report writing.' }, null, 2))
  for (const [name, s] of Object.entries(SKILLS)) {
    mkdirSync(join(root, 'skills', name), { recursive: true })
    writeFileSync(join(root, 'skills', name, 'SKILL.md'), `---\nname: ${name}\ndescription: ${s.description}\n---\n\n${s.body}\n`)
  }
  const mine = userPluginDir()
  if (!existsSync(join(mine, '.claude-plugin', 'plugin.json'))) {
    mkdirSync(join(mine, '.claude-plugin'), { recursive: true })
    mkdirSync(join(mine, 'skills'), { recursive: true })
    writeFileSync(join(mine, '.claude-plugin', 'plugin.json'), JSON.stringify({ name: 'my-security-skills', version: '1.0.0', description: 'Your own skills for MacSec reviews.' }, null, 2))
    writeFileSync(join(mine, 'skills', 'README.md'), 'Put each skill in its own folder here, with a SKILL.md inside (name and description at the top).\nMacSec loads them into every Claude Code review.\n')
  }
}

export function listSkills(): { name: string; mine: boolean }[] {
  const read = (d: string, mine: boolean): { name: string; mine: boolean }[] => {
    try {
      return readdirSync(join(d, 'skills'))
        .filter((n) => existsSync(join(d, 'skills', n, 'SKILL.md')))
        .map((name) => ({ name, mine }))
    } catch {
      return []
    }
  }
  return [...read(builtinPluginDir(), false), ...read(userPluginDir(), true)]
}

export function pluginArgs(): string[] {
  const out: string[] = []
  if (existsSync(join(builtinPluginDir(), '.claude-plugin'))) out.push('--plugin-dir', builtinPluginDir())
  if (listSkills().some((s) => s.mine)) out.push('--plugin-dir', userPluginDir())
  return out
}
