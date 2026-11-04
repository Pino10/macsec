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
  'review-vectors': {
    description: 'The index of every security review vector, by area, so nothing is skipped. Use at the start of any code review to plan which vector skills apply to this stack.',
    body: `# Review vectors: the plan

Pick the areas this project has, then work through the matching skill for each. Write "not applicable" for areas that do not exist, so the reader knows they were considered.

| Area | Skill | Look at when the project has… |
| --- | --- | --- |
| Access control, injection, data exposure | security-code-review | always |
| APIs (REST, GraphQL, webhooks) | api-security-review | routes that return JSON, GraphQL, webhooks |
| Sign-in, sessions, tokens, OAuth | auth-session-review | login, JWT, OAuth/OIDC, password reset, MFA |
| Injection of every kind | injection-catalog | any input reaching SQL, shell, templates, files, XML, URLs |
| Browser side | client-side-review | HTML, React/Vue/Angular, postMessage, CSP |
| Business logic and races | business-logic-review | money, credits, coupons, stock, multi-step flows |
| Config, containers, CI | infra-config-review | Dockerfile, compose, GitHub Actions, Azure Pipelines, Terraform, nginx/Apache |
| Supply chain | supply-chain-review | package.json, composer.json, requirements, lockfiles, CI actions |
| Personal data | privacy-data-review | users, emails, payments, health or location data |
| Backend as a service | cloud-baas-review | Supabase, Firebase, S3, Azure Storage, Cosmos DB |
| AI features | ai-app-review | calls to an LLM, RAG, agents, tools |
| Desktop apps | electron-review | Electron, Tauri |
| Secrets | secrets-triage | any key, token or password in files or history |
| Packages with advisories | dependency-triage | scanner results for packages |

Every finding needs a file and line. Rank by what an attacker can reach without signing in first.`
  },
  'api-security-review': {
    description: 'API security review against the OWASP API Security Top 10 (2023), plus GraphQL and webhooks. Use whenever a project exposes JSON APIs, GraphQL or receives webhooks.',
    body: `# API security review

Go route by route. For each, write down: method, path, who may call it, which record it touches.

1. **Broken object level authorization (API1).** An id, slug or UUID from the path, query or body loads a record. Is the query scoped to the caller (\`where user_id = me\`, policy, tenant id)? UUIDs are not access control.
2. **Broken authentication (API2).** Endpoints missing the auth middleware; tokens accepted after logout; API keys in query strings; no rate limit on login, OTP, reset.
3. **Broken object property level authorization (API3).** Responses that serialise the whole model (password hashes, tokens, internal flags, other users' emails); request bodies that can set \`role\`, \`is_admin\`, \`balance\`, \`owner_id\`, \`verified\` (mass assignment).
4. **Unrestricted resource consumption (API4).** No pagination limit (\`per_page=100000\`), unbounded uploads, expensive search or export without limits, no timeouts on outbound calls, SMS or email sending without a cap (cost).
5. **Broken function level authorization (API5).** Admin routes reachable by normal users; checks done in the UI only; HTTP method swaps (GET allowed where POST is checked).
6. **Sensitive business flows (API6).** Sign-up, checkout, voting, reservations without anti-automation.
7. **SSRF (API7).** User-supplied URLs fetched by the server (webhooks, image import, PDF rendering, link previews) without an allowlist; redirects followed into 169.254.169.254, localhost or private ranges.
8. **Security misconfiguration (API8).** Verbose errors and stack traces, permissive CORS with credentials, missing security headers, debug routes (Telescope, Horizon, /actuator, Swagger UI) in production.
9. **Inventory (API9).** Old versions (/v1 next to /v2) still live with weaker checks; test and staging routes.
10. **Unsafe consumption of APIs (API10).** Data from third-party APIs trusted without validation; TLS checks off.

## GraphQL
Introspection on in production; no depth, complexity or alias limits; batching that bypasses rate limits; resolvers that skip the auth checks the REST routes have; field-level authorization on sensitive fields.

## Webhooks
Signature verified with a constant-time compare over the raw body (Stripe, GitHub, Azure Event Grid); timestamp checked to stop replays; idempotency on event ids.`
  },
  'auth-session-review': {
    description: 'Review of sign-in, sessions, JWT, OAuth 2 and OpenID Connect, password reset, MFA and account recovery. Use whenever a project authenticates users or services.',
    body: `# Authentication and sessions

## Passwords and accounts
- Hashing: bcrypt, argon2id or scrypt with a sensible cost. Not MD5, SHA-1, SHA-256 alone, or reversible encryption.
- Login, reset and OTP endpoints are rate limited per account and per IP. Error messages do not reveal whether an account exists (compare the sign-up, login and reset responses and their timing).
- Password reset: tokens random (not derived from time or user id), single use, expiring within an hour, invalidated after a password change; the reset link host does not come from the Host header (host header poisoning).
- MFA: the second step cannot be skipped by calling the next endpoint directly; OTP codes have attempt limits; recovery codes are hashed.

## Sessions and cookies
- Session id rotated at login and privilege change (fixation); logout destroys the server-side session; idle and absolute timeouts.
- Cookies: Secure, HttpOnly, SameSite=Lax or Strict; no tokens in localStorage for apps that can use cookies.
- CSRF protection on every state-changing request that uses cookies.

## JWT
- The algorithm is fixed by the server: no \`alg: none\`, no HS256 accepted for an RS256 key (key confusion).
- Signature verified before claims are read; \`exp\`, \`nbf\`, \`iss\`, \`aud\` checked; short lifetimes with refresh tokens that rotate and can be revoked.
- \`kid\` and \`jku\` headers are not used to fetch keys from attacker-controlled places.
- No sensitive data in the payload (it is only encoded).

## OAuth 2 and OpenID Connect
- \`state\` checked (CSRF); PKCE for public clients; \`redirect_uri\` matched exactly, not by prefix or regex.
- The ID token's \`nonce\`, \`aud\` and signature verified; accounts are linked by a verified email or the provider's subject id, never an unverified email (account takeover).
- Implicit flow not used; client secrets not in front-end code.

## Service-to-service
API keys and client secrets come from the environment or a vault, are scoped, and can be rotated. Internal endpoints still check who calls them.`
  },
  'injection-catalog': {
    description: 'Every kind of injection with the sinks to search for per language: SQL, NoSQL, command, template (SSTI), XXE, path traversal, deserialization, SSRF, open redirect, CRLF, LDAP, XPath, ReDoS and prototype pollution. Use whenever input reaches an interpreter, a file or a URL.',
    body: `# Injection catalog

For each sink below, follow the data back to a request. Confirm only when untrusted input reaches it without the safe API.

- **SQL:** string-built queries; Laravel \`whereRaw\`, \`DB::raw\`, \`orderBy($request->sort)\` (column names cannot be bound: allowlist them); Eloquent \`->where($request->all())\`; Node template literals into \`query()\`; Sequelize \`literal\`; Prisma \`$queryRawUnsafe\`; Python f-strings in \`execute\`, Django \`extra()\`/\`raw()\`; Go \`fmt.Sprintf\` into \`db.Query\`.
- **NoSQL:** MongoDB filters built from JSON bodies (\`{ "password": { "$ne": null } }\`), \`$where\`, \`mapReduce\` with input; Firestore rules relying on client fields.
- **Command:** \`exec\`, \`shell_exec\`, \`system\`, \`passthru\`, backticks, \`proc_open\`; Node \`child_process.exec\` and \`spawn(..., { shell: true })\`; Python \`os.system\`, \`subprocess(..., shell=True)\`; arguments starting with \`-\` (argument injection into git, curl, tar, ffmpeg).
- **Template (SSTI):** user input used as a template, not as data: Twig \`createTemplate\`, Blade \`Blade::render($input)\`, Jinja2 \`Template(input)\` or \`render_template_string\`, EJS/Pug/Handlebars compiled from input, Go \`template.New().Parse(input)\`.
- **XXE:** XML parsed with external entities on: PHP \`libxml_disable_entity_loader\` missing on old PHP, \`LIBXML_NOENT\`; Java DocumentBuilder defaults; Python \`lxml\` with \`resolve_entities\`; SVG and DOCX uploads parsed on the server.
- **Path traversal and zip slip:** file names from input joined to paths (\`../\`), \`include\`/\`require\` with input, \`res.sendFile\` with a user path, archive entries extracted without checking the final path stays inside the folder; nginx \`alias\` without a trailing slash.
- **Deserialization:** PHP \`unserialize\` and \`phar://\` paths; Python \`pickle\`, \`yaml.load\` without SafeLoader; Java \`ObjectInputStream\`; .NET \`BinaryFormatter\`, \`TypeNameHandling.All\`; Node \`node-serialize\`.
- **SSRF:** server-side fetches of user URLs (\`file_get_contents\`, Guzzle, \`fetch\`, \`requests\`, \`curl\`); check scheme and resolved IP after redirects; cloud metadata (169.254.169.254, fd00:ec2::254, metadata.google.internal); DNS rebinding.
- **Open redirect:** \`redirect($request->next)\`, \`res.redirect(req.query.url)\`; allow only relative paths or known hosts.
- **Header and log injection:** CRLF in values put into headers or logs; user data in \`Location\`.
- **LDAP and XPath:** filters and expressions built by concatenation.
- **ReDoS:** user input matched by regexes with nested quantifiers (\`(a+)+\`), or user-supplied regexes.
- **Prototype pollution (JavaScript):** deep merge or \`set(obj, path, value)\` with keys from input (\`__proto__\`, \`constructor.prototype\`), then a gadget (options objects, template engines).
- **Mass assignment:** whole request bodies into create/update (Laravel \`$guarded = []\`, Mongoose, Rails, Django ModelForm \`fields = '__all__'\`).
- **File upload:** extension and MIME checked on the server, file stored outside the web root or served with a safe Content-Type and \`Content-Disposition: attachment\`, images re-encoded, size limits, no SVG/HTML served inline from the main domain.`
  },
  'client-side-review': {
    description: 'Browser-side security: XSS sinks per framework, DOM XSS, postMessage, CSP, CORS, clickjacking, tokens in storage, and secrets that leak into front-end bundles. Use for any project with a web front end.',
    body: `# Client-side review

- **XSS sinks:** React \`dangerouslySetInnerHTML\`, Vue \`v-html\`, Angular \`bypassSecurityTrust*\`, Svelte \`{@html}\`, Blade \`{!! !!}\`, Twig \`|raw\`, Jinja \`|safe\`, \`innerHTML\`, \`outerHTML\`, \`insertAdjacentHTML\`, \`document.write\`, jQuery \`.html()\`. Is the value sanitised (DOMPurify) or trusted?
- **DOM XSS:** \`location\`, \`location.hash\`, \`document.referrer\`, \`window.name\` flowing into sinks; \`href\`/\`src\` set from input without blocking \`javascript:\` URLs; \`eval\`, \`new Function\`, \`setTimeout(string)\`.
- **postMessage:** listeners that do not check \`event.origin\` exactly; \`postMessage(data, '*')\` with sensitive data.
- **CSP:** present, without \`unsafe-inline\`/\`unsafe-eval\` for scripts, with \`frame-ancestors\` (or X-Frame-Options) against clickjacking, \`object-src 'none'\`, \`base-uri 'self'\`.
- **CORS:** \`Access-Control-Allow-Origin\` reflecting any origin together with \`Allow-Credentials: true\`; \`null\` origin allowed; regexes that match \`evil-example.com\`.
- **Tokens:** access tokens in localStorage are readable by any XSS; prefer HttpOnly cookies.
- **Secrets in bundles:** server keys exposed through \`NEXT_PUBLIC_\`, \`VITE_\`, \`PUBLIC_\`, \`REACT_APP_\`, \`NUXT_PUBLIC_\` variables or imported server modules; Next.js server actions and route handlers that trust client-sent ids; source maps published in production.
- **Third-party scripts:** loaded without Subresource Integrity from CDNs; tag managers with broad access.
- **Links:** \`target="_blank"\` to untrusted sites without \`rel="noopener"\` (old browsers).`
  },
  'business-logic-review': {
    description: 'Business logic flaws scanners cannot find: race conditions, double spending, price and quantity tampering, skipped steps, limits and idempotency. Use when a project handles money, credits, stock, coupons, votes or multi-step flows.',
    body: `# Business logic review

- **Trust:** prices, totals, discounts, currency, quantity and shipping must come from the server, never the request. Negative and zero quantities, huge numbers, decimals where integers are expected.
- **Races (TOCTOU):** "check then act" without a lock or transaction: redeeming a coupon, withdrawing a balance, booking the last seat, inviting past a seat limit. Look for \`SELECT\` then \`UPDATE\` without \`FOR UPDATE\`, a unique constraint or an atomic increment.
- **Idempotency:** payment and order endpoints accept the same request twice (double charge); webhook events processed twice.
- **Workflow:** steps can be skipped by calling a later endpoint directly (pay → confirm, verify email → use feature); state machines enforce allowed transitions on the server.
- **Limits:** trials, free credits and referral bonuses that reset by creating new accounts; per-account limits enforced only in the UI.
- **Rounding and currency:** floats for money; rounding that can be repeated for profit.
- **Multi-tenant:** every query filtered by tenant; background jobs and exports keep the tenant.
- **Time:** expiry compared in the client's time zone; tokens valid forever.

Report each with the exact steps a normal user could take and the business impact, without exploit code.`
  },
  'infra-config-review': {
    description: 'Configuration review of Dockerfiles, docker-compose, GitHub Actions, Azure Pipelines, Kubernetes, Terraform/Bicep, nginx/Apache and framework settings. Use when a project contains any deployment or CI files.',
    body: `# Infrastructure and CI configuration

## Containers
- Dockerfile: runs as root (no \`USER\`), \`latest\` tags, secrets in \`ARG\`/\`ENV\` or copied files (they stay in layers), \`curl | sh\`, \`ADD\` from URLs, no \`.dockerignore\` (\`.env\`, \`.git\` copied in).
- docker-compose: databases and admin tools published on 0.0.0.0, default passwords, privileged containers, the Docker socket mounted.

## CI/CD
- GitHub Actions: \`pull_request_target\` or \`workflow_run\` that checks out and runs untrusted code; \`\${{ github.event.* }}\` (titles, branch names, bodies) inside \`run:\` (script injection: pass through env instead); actions not pinned to a commit SHA; \`permissions\` not restricted (default write); secrets printed or passed to forks; self-hosted runners on public repos.
- Azure Pipelines: secrets as plain variables, \`System.AccessToken\` exposed to scripts from forks, service connections with broad scope, templates from unprotected branches.

## Cloud and Kubernetes
- Terraform/Bicep/ARM: storage public, security groups or NSGs open to 0.0.0.0/0 on SSH/RDP/databases, encryption off, logging off, wildcard IAM (\`*:*\`), Key Vault without purge protection.
- Kubernetes: \`privileged: true\`, \`hostPath\`, \`runAsRoot\`, no resource limits, secrets in plain manifests, dashboards exposed.

## Web servers and frameworks
- nginx/Apache: \`autoindex on\`, \`alias\` without a trailing slash (off-by-slash traversal), \`.git\`/\`.env\` served, missing HSTS and security headers, \`server_tokens\` on.
- Laravel \`APP_DEBUG=true\`, Django \`DEBUG=True\`/\`ALLOWED_HOSTS=['*']\`, Express without \`helmet\`, Next.js \`images.remotePatterns\` allowing any host (SSRF via the image optimiser), Spring actuator endpoints public.`
  },
  'supply-chain-review': {
    description: 'Supply chain risks: lockfiles, install scripts, typosquatting, dependency confusion, unpinned CI actions, abandoned packages. Use with any project that installs packages.',
    body: `# Supply chain review

- **Lockfiles** committed (package-lock.json, pnpm-lock.yaml, yarn.lock, composer.lock, poetry.lock, uv.lock, go.sum) and used in CI (\`npm ci\`, \`composer install\`).
- **Install scripts:** \`preinstall\`/\`postinstall\` in dependencies run code at install; \`composer.json\` scripts; consider \`--ignore-scripts\` in CI where possible.
- **Names:** packages one letter away from popular ones (typosquats); internal-looking names without a scope that could be claimed on the public registry (dependency confusion); registries configured in \`.npmrc\`/\`composer.json\` over http.
- **Versions:** \`*\`, \`latest\` or very wide ranges; git dependencies on branches instead of tags or commits.
- **Health:** abandoned packages (Composer marks them), very low download counts for critical roles, maintainers changed recently.
- **CI:** third-party actions and orbs pinned to SHAs; tokens with least privilege; artifacts signed or checksummed.
- **Vendored code:** copied libraries (minified jQuery, Bootstrap) with known vulnerable versions: check the version banner.`
  },
  'privacy-data-review': {
    description: 'Personal data handling: what is collected, where it flows, logs, retention, encryption, deletion and third parties (GDPR-minded). Use when a project stores data about people.',
    body: `# Privacy and personal data

- **Inventory:** list the personal data fields (names, emails, phone, address, IP, location, payment, health, ids, photos) and where they are stored.
- **Exposure:** API responses and exports returning more fields than the screen needs; search and list endpoints that enumerate users; personal data in URLs (they end up in logs and Referer headers).
- **Logs and errors:** request bodies, tokens, passwords, card numbers or emails written to logs, Sentry or analytics.
- **Storage:** sensitive fields encrypted at rest where it matters; backups protected; test fixtures not copied from production.
- **Retention and deletion:** a way to delete an account that really removes or anonymises its data, including files and third-party copies.
- **Third parties:** analytics, chat widgets, error trackers and AI APIs receiving personal data; data sent outside the region.
- **Consent:** tracking only after consent where the law needs it.`
  },
  'cloud-baas-review': {
    description: 'Backend-as-a-service security: Supabase row level security, Firebase rules, storage buckets, service keys in clients, Azure Storage SAS and Cosmos DB keys. Use when a project uses Supabase, Firebase, S3, Azure Storage or similar.',
    body: `# Supabase, Firebase and cloud storage

## Supabase
- Every table in the exposed schema has **row level security enabled** (look in migrations for \`enable row level security\`). A table without it is readable and writable by anyone with the anon key.
- Policies are not \`using (true)\` / \`with check (true)\` for user data; they compare \`auth.uid()\` to the owner column; update policies have \`with check\` too.
- The \`service_role\` key is never in front-end code or \`NEXT_PUBLIC_\`/\`VITE_\` variables (it bypasses RLS).
- Storage buckets: public only for public files; storage policies per folder.
- \`security definer\` functions check the caller themselves.

## Firebase
- Firestore and Realtime Database rules are not \`allow read, write: if true\` or \`if request.auth != null\` for everything (any signed-in user can read everyone's data); rules check \`request.auth.uid == resource.data.owner\`; field validation on writes.
- Storage rules similar; App Check considered for abuse.
- Admin SDK credentials (service account JSON) never in the client or the repository.

## AWS, Azure and Google storage
- S3 buckets and Azure Blob containers not public unless meant to be; Azure SAS tokens short-lived, with least permissions, not committed; Cosmos DB and storage account keys not in code (use managed identity); signed URLs short-lived.`
  },
  'ai-app-review': {
    description: 'Security of features built on LLMs, following the OWASP Top 10 for LLM applications: prompt injection, tool permissions, output handling, data leaks, cost. Use when a project calls an AI model, does RAG or runs agents.',
    body: `# AI feature review

- **Prompt injection:** untrusted text (web pages, emails, documents, user messages, RAG chunks) reaches a model that can take actions or see private data. Does the design assume the model will obey the system prompt? It will not always.
- **Tools and agents:** each tool has the least privilege it needs; dangerous actions (send, pay, delete, run code) need human confirmation; tool arguments are validated like any user input.
- **Output handling:** model output inserted into HTML (XSS), SQL, shell, file paths, URLs or code execution without validation.
- **Data leakage:** system prompts with secrets; RAG that retrieves documents the current user may not see (filter by permission before retrieval); conversation history shared across users; logs of prompts with personal data.
- **Keys:** provider API keys only on the server; per-user rate limits and spending caps (denial of wallet).
- **Supply chain:** models and embeddings from trusted sources; \`trust_remote_code\` off; pickled model files not loaded from untrusted places.`
  },
  'electron-review': {
    description: 'Electron and Tauri desktop app security: webPreferences, IPC, preload, navigation, shell.openExternal, updates. Use when a project is an Electron or Tauri app.',
    body: `# Electron and Tauri review

- **webPreferences:** \`contextIsolation: true\`, \`nodeIntegration: false\`, \`sandbox: true\`, \`webSecurity: true\`, no \`allowRunningInsecureContent\`, no \`enableRemoteModule\`.
- **Preload:** exposes a small, typed API through \`contextBridge\`, never \`ipcRenderer\` itself or generic "invoke anything" helpers.
- **IPC handlers:** validate every argument in the main process (paths inside allowed folders, ids from known lists); the renderer is untrusted.
- **Navigation:** \`will-navigate\` and \`setWindowOpenHandler\` deny unexpected origins; remote content is not loaded into privileged windows.
- **shell.openExternal:** only http(s) URLs (no \`file:\`, \`smb:\`, custom schemes from input).
- **Commands:** \`child_process\` with argument arrays, never shell strings with user text.
- **Updates:** signed, over HTTPS, checked against a signature or checksum.
- **Secrets:** stored with \`safeStorage\`/Keychain, not in plain JSON; not logged.
- **Tauri:** allowlist and capabilities minimal; \`dangerousRemoteDomainIpcAccess\` unused; CSP set.`
  },
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

