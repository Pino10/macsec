/**
 * Security skills for Claude Code, shared by Laramac and MacSec (keep the two copies of
 * src/main/seckit the same). Each app writes them as a plugin and loads it for its own reviews with
 * --plugin-dir; "Install for Claude" copies them into ~/.claude/skills so Claude Code in Terminal and
 * in the Claude desktop app can use them too.
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'fs'
import { homedir } from 'os'
import { join } from 'path'

export const SKILLS: Record<string, { description: string; body: string }> = {
  'security-code-review': {
    description: 'Methodical security code review of a whole project: entry points, trust boundaries, authentication, authorization, injection, data exposure. Use for any security code review.',
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
    description: 'How security reports are written: tailored, with evidence, severity reasoning, impact, fixed code and verification. Use when writing any review report.',
    body: `# Security report

The reader owns this code and wants to fix it today.

- Start with an executive summary: the state in 3 to 5 sentences and the single most urgent fix.
- A risk overview table: severity, finding, where, status.
- Each finding: **Where** (file:line), **Evidence** (the exact code, secrets masked after 4 characters), **Why it is rated** this severity *for this project*, **Impact** in plain words (no working exploit), **Fix** with corrected code, **How to verify**.
- Severity: critical = remote takeover, auth bypass, live production secrets, data of all users; high = one user's data exposed or changed by another, injection reachable by signed-in users; medium = needs unusual conditions or exposes limited information; low = hardening.
- Be specific: name the route, the function, the variable. No generic advice that would fit any project.
- Say what you could not check.`
  },
  'recon-methodology': {
    description: 'How to map a domain’s attack surface without attacking it: subdomains, live hosts, technologies, archived URLs, JavaScript, exposed files. Use for any recon of a site you are authorised to assess.',
    body: `# Recon methodology (read-only)

Goal: a map a careful manual tester can work from. Never attack: no fuzzing, no password guessing, no exploitation, no requests that change data. Stay inside the authorised domain.

## 1. Names
- Certificate transparency (crt.sh), passive DNS sources (subfinder), and hosts seen in the Wayback Machine.
- Group them: production, staging/dev/test, admin and tools (Jenkins, Grafana, GitLab, Kibana), mail and VPN, third-party (CNAMEs to SaaS).
- CNAMEs to cloud services that no longer resolve are possible **subdomain takeovers**: report, do not claim.

## 2. What answers
- Status, title, server, framework. A login page on a "dev" host is a lead; a default page on a forgotten host is a lead.
- Note WAF/CDN (Cloudflare, CloudFront, Azure Front Door): the origin may be reachable directly.

## 3. History
- Archived URLs show old endpoints, parameters and files (\`.bak\`, \`.sql\`, \`.env\`, \`/admin\`, \`/api/v1\`). Old ≠ gone: check politely whether they still answer.
- Parameter names are where input enters: list them for manual testing (ids, redirect, url, file, callback, template, query).

## 4. JavaScript (use js-recon)
## 5. Exposed files
A short list only, one GET each: \`.git/HEAD\`, \`.env\`, server-status, phpinfo, API descriptions, actuator. Confirm by content, not status code (soft 404s answer 200).

## 6. Prioritise
Rank leads by: reachable without sign-in > admin or internal function > handles money or personal data > old or unmaintained. Use attack-surface-report for the write-up.`
  },
  'js-recon': {
    description: 'Reading a site’s public JavaScript for what it reveals: source maps, API endpoints, internal hosts, feature flags and keys. Use whenever JavaScript files or source maps are part of a recon.',
    body: `# JavaScript recon

1. **Source maps.** Look for \`//# sourceMappingURL=\`, a \`SourceMap\` header, or \`file.js.map\` next to the bundle. A public map rebuilds the original source: list the interesting files (\`src/api/*\`, \`admin\`, \`config\`, \`auth\`) and read them for routes, roles and business rules.
2. **Endpoints.** Strings like \`/api/...\`, \`/v1/...\`, \`/graphql\`, \`/internal/...\`, full URLs to other hosts. Note which need a role (\`isAdmin\`, \`role === 'staff'\`): the server must check that too.
3. **Keys.** Classify each: meant to be public (Supabase anon key, Firebase web config, Google Maps key with referrer limits, Stripe publishable key) or a real secret (Stripe \`sk_live_\`, AWS \`AKIA\`, GitHub tokens, private keys, database URLs). Public keys still matter: check the rules behind them (Supabase Row Level Security, Firebase rules).
4. **Feature flags and hidden routes.** Disabled features often still have working server endpoints.
5. **Third parties.** Analytics, payment, auth providers: who receives the users' data.
Never print a secret in full: first four characters only.`
  },
  'attack-surface-report': {
    description: 'Writing up a recon: an attack surface map and prioritised leads for manual testing, with what to check and how to fix. Use when summarising any recon.',
    body: `# Attack surface report

- **Executive summary**: the shape of the surface and the one thing to look at first.
- **Map**: a table of hosts with what each is and why it matters, most interesting first.
- **Leads**: each with Where, What the recon shows (the evidence), Why it is interesting, What to check by hand (read-only, or with Burp Suite under authorisation), and the Fix if it is confirmed.
- Severity is about what the lead could lead to if confirmed: exposed secrets, takeovers and .env/.git exposures are high or critical; source maps and staging hosts are medium or low unless they reveal something worse.
- Mark what is noise and why. Never include exploit code.`
  },
  'local-model-review': {
    description: 'How to review code well with a smaller local model: work file by file, stay concrete, never guess. Use when the reviewer runs on LM Studio, Ollama or another local server.',
    body: `# Reviewing with a local model

- Read one area at a time: routes first, then the controllers they call, then data access. Keep notes short.
- Only report what you can point to: a file, a line, the variable. If unsure, say "to check" instead of reporting.
- Prefer the scanners' findings as a starting list: confirm or reject each with the code in front of you.
- Keep the report format exactly as asked, so it can be read by the app.`
  }
}

const skillFile = (name: string, s: { description: string; body: string }): string => `---\nname: ${name}\ndescription: ${s.description}\n---\n\n${s.body}\n`

/** Writes the plugin a review loads with --plugin-dir. */
export function writePlugin(root: string, plugin: string, description: string): void {
  mkdirSync(join(root, '.claude-plugin'), { recursive: true })
  writeFileSync(join(root, '.claude-plugin', 'plugin.json'), JSON.stringify({ name: plugin, version: '1.1.0', description, license: 'MIT' }, null, 2))
  writeFileSync(join(root, 'README.md'), `# ${plugin}\n\n${description}\n\nSkills: ${Object.keys(SKILLS).join(', ')}. They describe how to review code for security, triage secrets and dependencies, do read-only recon of a site, read its JavaScript and write the reports.\n`)
  for (const [name, s] of Object.entries(SKILLS)) {
    mkdirSync(join(root, 'skills', name), { recursive: true })
    writeFileSync(join(root, 'skills', name, 'SKILL.md'), skillFile(name, s))
  }
}

/** The skills folder Claude Code (Terminal and the desktop app) reads for your own skills. */
export const claudeSkillsDir = (): string => join(homedir(), '.claude', 'skills')

/** Copies the skills into ~/.claude/skills as prefix-name, so every Claude Code session can use them. */
export function installForClaude(prefix: string): string[] {
  const dir = claudeSkillsDir()
  mkdirSync(dir, { recursive: true })
  const done: string[] = []
  for (const [name, s] of Object.entries(SKILLS)) {
    const id = `${prefix}-${name}`
    mkdirSync(join(dir, id), { recursive: true })
    writeFileSync(join(dir, id, 'SKILL.md'), skillFile(id, s))
    done.push(id)
  }
  return done
}

export function removeFromClaude(prefix: string): void {
  for (const name of Object.keys(SKILLS)) rmSync(join(claudeSkillsDir(), `${prefix}-${name}`), { recursive: true, force: true })
}

export const installedForClaude = (prefix: string): boolean => Object.keys(SKILLS).every((n) => existsSync(join(claudeSkillsDir(), `${prefix}-${n}`, 'SKILL.md')))

/** Your own skills in a folder (each in its own folder with a SKILL.md): their names. */
export function skillNames(dir: string): string[] {
  try {
    return readdirSync(dir).filter((n) => existsSync(join(dir, n, 'SKILL.md')))
  } catch {
    return []
  }
}

/** The text of the given skills, for models that cannot load skills themselves. */
export function skillText(names: string[], extraDirs: string[] = []): string {
  const parts: string[] = []
  for (const n of names) if (SKILLS[n]) parts.push(SKILLS[n].body)
  for (const d of extraDirs) for (const n of skillNames(d)) parts.push(readFileSync(join(d, n, 'SKILL.md'), 'utf8').replace(/^---[\s\S]*?---\n/, ''))
  return parts.join('\n\n---\n\n')
}

