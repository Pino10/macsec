/** Everything the window and the main process say to each other. */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

// ---------------------------------------------------------------- Tools

export type ToolCategory = 'code' | 'secrets' | 'deps' | 'web' | 'api' | 'mobile' | 'cloud' | 'network' | 'optional' | 'runtime'

export interface ToolInfo {
  id: string
  name: string
  category: ToolCategory
  /** One line on what it does, for non-experts. */
  purpose: string
  homepage: string
  installed: boolean
  version: string | null
  /** Newest version published, when known. */
  latest: string | null
  updateAvailable: boolean
  /** Installed through another tool (uv), or an app you install yourself (Burp, ZAP). */
  method: 'release' | 'python' | 'app'
  /** Languages or stacks it is used for; empty means all. */
  languages: string[]
}

// ---------------------------------------------------------------- Projects

export type SourceKind = 'local' | 'github' | 'azure' | 'path'

export interface LocalProject {
  name: string
  path: string
  /** Main languages, most files first. */
  languages: string[]
  git: boolean
  /** Its Laramac address, such as http://shop.test. */
  url?: string
}

export interface RemoteRepo {
  /** owner/name for GitHub, project/name for Azure DevOps. */
  name: string
  url: string
  private: boolean
  description?: string
  language?: string
  updatedAt?: string
  project?: string
  defaultBranch?: string
}

export interface AzureProject {
  name: string
  description?: string
  repos: RemoteRepo[]
}

export interface Accounts {
  github: { connected: boolean; login: string | null }
  azure: { connected: boolean; org: string | null }
}

export type ReviewSource =
  | { kind: 'local'; path: string }
  | { kind: 'github'; repo: string }
  | { kind: 'azure'; url: string }

// ---------------------------------------------------------------- Sessions and findings

export type FindingCategory = 'code' | 'secret' | 'dependency' | 'config' | 'ai' | 'web' | 'api' | 'mobile' | 'cloud' | 'network' | 'binary' | 'recon'

export interface Finding {
  id: string
  tool: string
  category: FindingCategory
  severity: Severity
  title: string
  file?: string
  line?: number
  /** e.g. CWE-89 */
  cwe?: string
  /** e.g. CVE-2024-1234 or GHSA-... */
  advisory?: string
  description?: string
  fix?: string
  snippet?: string
  /** AI's view after reading the code: real, likely false positive, or not checked. */
  verdict?: 'confirmed' | 'false-positive' | 'unreviewed'
  url?: string
  /** Confirmed: the problem itself was seen. Possible: the evidence points at it but does not prove it. */
  confidence?: 'confirmed' | 'possible'
  /** The request, the size and fingerprint of the answer, and what in it proves the finding. */
  proof?: { request: string; reproduce: string; status: number; contentType?: string; bytes: number; sha256: string; at: string; shows: string[] }
  /** Live count of known flaws for a software version (NVD), with CISA's exploited list and EPSS. */
  cves?: { count: number; kev: number; topEpss: number; top: { id: string; score?: number; kev: boolean; epss?: number }[] }
  /** How far this is proven, in the words a report uses. Worked out when the test finishes. */
  exploit?: { state: 'proven' | 'known-exploited' | 'likely' | 'unproven'; label: string; why: string; risk: number }
  /** The id of the check that makes this kind of finding, stable across scans. */
  checkId?: string
  /** The last re-test of this one finding. */
  retest?: { at: string; state: 'still' | 'changed' | 'gone' | 'unreachable' | 'unsupported'; detail: string }
  /** The lines around the problem, with secrets masked. */
  context?: { start: number; lines: string[]; at: number }
  /** The AI's explanation: why it has this severity. */
  why?: string
  /** What could happen if it is left. */
  impact?: string
  /** A corrected version of the code. */
  fixCode?: string
  /** How to check the fix worked. */
  verify?: string
  /** The AI's reason for its verdict on a scanner finding. */
  aiNote?: string
  /** What you decided: fixed, accepted risk, or not a problem. It then stops counting. */
  triage?: 'fixed' | 'accepted' | 'not-a-problem'
  triagedAt?: string
}

export type Reviewer = 'none' | 'claude' | 'claude-local' | 'claude-free' | 'codex' | 'gemini' | 'model'

/** How much a scan covers. Every mode only reads: nothing is changed, fuzzed or attacked. */
export type ScanMode = 'quick' | 'standard' | 'thorough'

export interface LocalSite {
  name: string
  url: string
}

export interface WebScanRequest {
  target: { kind: 'local'; name: string } | { kind: 'url'; url: string }
  mode: ScanMode
  /** You own the target or have written permission to test it. */
  authorized: boolean
  /** Extra request headers for scanning behind a login, one "Name: value" per line. */
  headers?: string
  /** Control confirmations: active checks that prove a problem is real (see CLAUDE.md for the rules). */
  confirm?: ConfirmOptions
  /** White box: the site's source folder. MacSec reads it, maps its routes and parameters, and tests them live. */
  codePath?: string
  /** Walk the person's web checklist item by item (needs an AI reviewer for the items a scan cannot test). */
  checklist?: boolean
  reviewer: Reviewer
}

export interface ConfirmOptions {
  /** Hidden pages and hidden parameters. */
  fuzz: boolean
  /** Login: limits on wrong guesses, and whether usernames can be told apart. */
  auth: boolean
  /** Compare what two accounts can open. Needs the second account's headers. */
  authz: boolean
  /** Which web firewall answers, what it blocks, and whether a harmless marker gets past it. */
  waf: boolean
  /** Injection tests on every parameter and every GET form, with harmless markers. */
  inject?: boolean
  /** Business logic: open redirects, host header poisoning, code limits, trusted fields, skipped steps. */
  logic?: boolean
  /** Where the sign-in form is, when it is not at an obvious address. */
  loginUrl?: string
  /** A real user of this site (yours). Used for two wrong-password tries, to see if the login reveals who exists. */
  knownUser?: string
  /** Also try the "forgot password" form, which sends one reset email to knownUser. */
  allowReset?: boolean
  /** Account A's email or username, so a page that shows it to account B proves the leak. */
  identityA?: string
  /** The second account's cookie or token, one "Name: value" per line. */
  headersB?: string
}

export interface ApiSpecInfo {
  id: string
  name: string
  format: 'postman' | 'openapi' | 'swagger' | 'har'
  baseUrl: string
  endpoints: { method: string; url: string; name?: string }[]
}

export interface ApiAuth {
  kind: 'none' | 'bearer' | 'header'
  value?: string
  /** For kind header: the header name, e.g. X-API-Key. */
  header?: string
}

export interface ApiScanRequest {
  spec: string
  baseUrl: string
  auth: ApiAuth
  mode: ScanMode
  authorized: boolean
  reviewer: Reviewer
}



export type ReviewDepth = 'quick' | 'standard' | 'deep'
export type ReviewFocus = 'security' | 'bugs' | 'all'

export type DeepEngine = 'cloudflare' | 'anthropic' | 'both'
export type DeepReviewerKind = 'claude' | 'claude-local' | 'claude-free' | 'claude-desktop'

export interface DeepPlanRequest {
  engine: DeepEngine
  reviewer: DeepReviewerKind
}

export interface DeepPlanLine {
  label: string
  text: string
}

export interface PackUpdateInfo {
  id: string
  current: string | null
  latest: string | null
  available: boolean
  checkedAt: string | null
  changes: string | null
  error?: string
}

export interface ReviewRequest {
  source: ReviewSource
  reviewer: Reviewer
  /** A deep audit (Cloudflare's and Anthropic's security reviews) in place of the standard AI review. */
  deep?: { engine: DeepEngine }
  depth: ReviewDepth
  focus: ReviewFocus
  /** Keep the downloaded code after the review, to fix it. Remote sources only. */
  keepCode: boolean
  /** Tool ids to skip. */
  skip?: string[]
  /** Skills for a Claude Code review (ids from review:skill-plan). Empty: the ones that fit. */
  skills?: string[]
}

export interface SessionStep {
  id: string
  label: string
  status: 'waiting' | 'running' | 'done' | 'skipped' | 'failed'
  detail?: string
  findings?: number
  ms?: number
  /** When this step started, so the window can show a running clock. */
  startedAt?: string
  /** 0 to 100 when the tool reports it. */
  progress?: number
  /** The latest line the tool printed. */
  lastLine?: string
}

export type SessionKind = 'code-review' | 'web-scan' | 'api-scan' | 'mobile-scan' | 'recon' | 'audit'

export type AuditRequest =
  | { kind: 'full'; path: string; site: string; reviewer: Reviewer; depth: ReviewDepth; authorized: boolean }
  | { kind: 'portfolio' }
  | { kind: 'changes'; path: string }
  | { kind: 'cloud'; provider: 'azure' | 'aws'; reviewer: Reviewer }
  /** `host` names the check; `hosts` is every server in it (one, a list, or a small network). */
  | { kind: 'server'; host: string; hosts?: string[]; ports: 'top100' | 'top1000'; reviewer: Reviewer; authorized: boolean; /** Ask Metasploit's check command (never exploit) about matched known flaws. Needs Metasploit already installed. */ msf?: boolean }

/** A mobile app: its source folder, or a built .apk or .ipa file. */
export interface ReconDeltaInfo {
  since: { session: string; at: string }
  newHosts: string[]
  goneHosts: string[]
  newEndpoints: string[]
  newFindings: { id: string; title: string; severity: string }[]
  fixedFindings: { id: string; title: string; severity: string }[]
}

export interface ReconRequest {
  target: string
  depth: 'passive' | 'standard' | 'deep'
  reviewer: Reviewer
  authorized: boolean
}

export interface MobileScanRequest {
  path: string
  reviewer: Reviewer
  /** Live test on a phone or emulator (Android .apk only). See CLAUDE.md for the rules. */
  live?: { serial: string; confirmed: boolean }
  /** Ask each cloud address found in a built app once, read only, whether anyone can read it. */
  online?: boolean
}

export interface AndroidDevice {
  serial: string
  state: string
  model: string
  kind: 'emulator' | 'phone'
}

export interface LiveSetupInfo {
  adb: string | null
  emulator: boolean
  /** Whether Android's command line tools are present, which MacSec needs to build a test phone. */
  canCreate: boolean
  devices: AndroidDevice[]
  avds: string[]
}

/** A tool that was in the T3MP3ST pack but MacSec does not install or run, because it attacks. */
export interface OptionalTool {
  name: string
  what: string
  homepage: string
  installed: boolean
}

export interface SessionInfo {
  id: string
  kind: SessionKind
  mode?: ScanMode
  title: string
  target: string
  createdAt: string
  finishedAt?: string
  status: 'running' | 'done' | 'failed' | 'cancelled'
  reviewer?: Reviewer
  depth?: ReviewDepth
  counts: Record<Severity, number>
  steps: SessionStep[]
  /** Where the code is, while it exists: the project itself, or a private copy. */
  codePath?: string
  codeKept?: boolean
  /** For audits: the sessions it ran. */
  children?: string[]
  /** The Claude Code session that did the review, to continue it. */
  claudeSession?: string
  /** The skills a Claude Code review loaded. */
  skills?: string[]
  error?: string
  languages?: string[]
  files?: number
}

/** The JavaScript map a scan builds: what the site's scripts name. */
export interface JsMapInfo {
  scripts: { url: string; bytes: number; endpoints: string[]; routes: string[]; graphql: string[]; envVars: string[]; sourceMap?: { url: string; files: number; recovered: number } }[]
  endpoints: string[]
  routes: string[]
  graphql: string[]
  envVars: string[]
  hosts: string[]
  refs: { firebase: string[]; s3: string[]; gcs: string[] }
  /** Whether original source was rebuilt into the session folder. */
  sources: boolean
}

export interface SessionDetail extends SessionInfo {
  findings: Finding[]
  /** The AI reviewer's written report (markdown). */
  aiReport?: string
  /** The test plan for what to try by hand (markdown), built from the site's own pages. */
  plan?: string
}

// ---------------------------------------------------------------- AI

export type ModelApi = 'openai' | 'anthropic'

export interface ModelServer {
  id: string
  name: string
  baseUrl: string
  api: ModelApi
  hasKey: boolean
}

export interface ModelServerInput {
  id?: string
  name: string
  baseUrl: string
  api: ModelApi
  key?: string
}

export interface LocalLlm {
  /** Set for servers you saved. */
  id?: string
  /** LM Studio, Ollama, vMLX (:8000), or the name you gave it. */
  provider: string
  toolId?: 'ollama' | 'lmstudio' | 'vmlx' | 'omlx'
  baseUrl: string
  api: ModelApi
  /** Chat models only, loaded ones first. */
  models: string[]
  loaded: string[]
  /** Not on this Mac: prompts leave it. */
  remote: boolean
  saved: boolean
  online?: boolean
}

export interface LlmTest {
  ok: boolean
  reply?: string
  error?: string
  ms: number
}

export interface ChatMessage {
  role: 'system' | 'user' | 'assistant'
  content: string
}

export interface AgentInfo {
  id: 'claude' | 'codex' | 'gemini' | 'burp' | 'lmstudio'
  name: string
  installed: boolean
  path: string | null
  /** The desktop app, when there is one (Claude, Codex, LM Studio, Burp). */
  app: string | null
  version: string | null
  /** What it is used for in MacSec. */
  role: string
}

// ---------------------------------------------------------------- App

export interface AppSettings {
  /** Laramac's www folder by default. */
  wwwPath: string
  llm: { baseUrl: string; model: string }
  /** Free LLM API's address and model. Its key is a secret, in the Keychain. */
  freellm?: { baseUrl: string; model: string }
  /** 'auto' (the first editor found), an editor id from seckit/editors.ts, or 'custom' (editorApp). */
  editor?: string
  editorApp?: string | null
  /** Default reviewer for new reviews. */
  reviewer: Reviewer
  notifications: boolean
  /** How Claude Code signs in: your normal account, or an Anthropic API key from the Keychain. */
  claudeAuth: 'account' | 'key'
  /** Let AI tools use MacSec through its MCP server on 127.0.0.1. Off by default. */
  mcpEnabled?: boolean
  /** Slack, Teams, Discord or other webhook. The address is in the Keychain. */
  webhook?: { kind: 'slack' | 'teams' | 'discord' | 'generic'; events: 'errors' | 'all' }
  /** Skill packs you removed: they are not added back by themselves. */
  packsDeclined?: string[]
  /** Dark (the default), light, or follow the Mac. */
  look?: 'dark' | 'light' | 'auto'
  /** The colour of buttons and highlights. */
  accent?: 'ion' | 'violet' | 'green' | 'amber' | 'rose'
  textSize?: 'normal' | 'large'
  /** Findings explained in everyday words first, with the technical detail folded away. */
  explainSimply?: boolean
  /** The first-run welcome was answered. */
  welcomed?: boolean
  /** Whether the person agreed to download the skill packs. Unset until they are asked. */
  packsAsk?: 'yes' | 'no'
  /** The newest skill pack version already announced, so each update is announced once. */
  packsNotified?: Record<string, string>
}

export interface FreeLlmInfo {
  baseUrl: string
  model: string
  hasKey: boolean
  claudeCode: boolean
  models: string[]
  ok: boolean | null
  note: string
}

export interface IntegrationsInfo {
  webhook: { kind: 'slack' | 'teams' | 'discord' | 'generic'; events: 'errors' | 'all'; saved: boolean } | null
  raycastDir: string
  raycastInstalled: boolean
  cli: string
  shortcuts: { title: string; command: string }[]
  mcp: { enabled: boolean; running: boolean; url: string; command: string; error: string | null }
}

export interface SkillPackInfo {
  id: string
  name: string
  repo: string
  license: string
  about: string
  installed: boolean
  commit: string | null
  at: string | null
  loaded: string[]
}

export interface CheckupResult {
  at: string
  macos: string
  score: number
  checks: { id: string; title: string; status: 'ok' | 'warn' | 'bad' | 'info'; detail: string; fix?: string; group?: string }[]
  loginItems: { plist: string; label: string; program: string | null; where: string; signer: string | null; status: 'ok' | 'warn' | 'bad' | 'info'; note: string }[]
  ports: { command: string; pid: number; address: string; port: number; everyone: boolean }[]
  sshKeys: { file: string; kind: string; protectedByPassphrase: boolean | null; permissionsOk: boolean }[]
  extensions: { browser: string; id: string; name: string; version: string; risky: string[] }[]
}

export interface SessionCompare {
  previous: { id: string; at: string } | null
  added: Finding[]
  fixed: Finding[]
  still: number
}

export interface ReleaseNote {
  version: string
  notes: string
  publishedAt: string
  url: string
}

export interface UpdateStatus {
  current: string
  update: UpdateInfo | null
  checkedAt: number | null
  error: string | null
}

export interface UpdateInfo {
  version: string
  current: string
  notes: string
  publishedAt: string
  url: string
}

export interface AppInfo {
  version: string
  root: string
  material: 'liquid-glass' | 'vibrancy' | 'none'
}

export interface JobInfo {
  id: string
  label: string
  percent: number | null
  status: 'running' | 'done' | 'error'
  error?: string
}

export interface LogLine {
  at: string
  session?: string
  level: 'info' | 'warn' | 'error'
  text: string
  /** Live tool output, not kept in the log file. */
  live?: boolean
}

export interface Channels {
  'app:info': { args: []; result: AppInfo }
  'app:open-folder': { args: ['root' | 'tools' | 'sessions' | 'extensions']; result: void }
  'app:open-external': { args: [string]; result: void }
  'settings:get': { args: []; result: AppSettings }
  'settings:set': { args: [Partial<AppSettings>]; result: AppSettings }
  'settings:choose-www': { args: []; result: AppSettings | null }

  'tools:list': { args: []; result: ToolInfo[] }
  'tools:install': { args: [string[]]; result: ToolInfo[] }
  'tools:remove': { args: [string]; result: ToolInfo[] }
  'tools:update-data': { args: []; result: void }
  'tools:check-updates': { args: []; result: ToolInfo[] }

  'projects:local': { args: []; result: LocalProject[] }
  'projects:import': { args: []; result: LocalProject[] | null }
  'projects:pick': { args: []; result: LocalProject | null }
  'accounts:get': { args: []; result: Accounts }
  'accounts:github': { args: [string | null]; result: Accounts }
  'accounts:azure': { args: [string | null, string | null]; result: Accounts }
  'github:repos': { args: []; result: RemoteRepo[] }
  'azure:projects': { args: [string]; result: AzureProject[] }

  'review:start': { args: [ReviewRequest]; result: SessionInfo }
  'review:deep-plan': { args: [DeepPlanRequest]; result: DeepPlanLine[] }
  'review:deep-handoff': { args: [{ engine: DeepEngine; path: string }]; result: { copied: boolean; opened: boolean } }
  'packs:updates': { args: []; result: PackUpdateInfo[] }
  'packs:check-updates': { args: []; result: PackUpdateInfo[] }
  'desktop:status': { args: []; result: { app: boolean; connected: boolean; path: string } }
  'desktop:connect': { args: []; result: { connected: boolean; path: string } }
  'review:skill-plan': { args: [string | null]; result: SkillPlan }
  'watch:get': { args: []; result: WatchInfo }
  'watch:set': { args: [{ packages?: boolean; retest?: boolean; window?: Partial<WatchWindow> }]; result: WatchInfo }
  'watch:check-now': { args: []; result: WatchInfo }
  'web:sites': { args: []; result: LocalSite[] }
  'web:start': { args: [WebScanRequest]; result: SessionInfo }
  'burp:open': { args: []; result: void }
  'web:login': { args: [string]; result: { cookie: string; count: number } | null }
  'audit:start': { args: [AuditRequest]; result: SessionInfo }
  'api:load-spec': { args: []; result: ApiSpecInfo | null }
  'api:start': { args: [ApiScanRequest]; result: SessionInfo }
  /** Picks an app's source folder or a built .apk / .ipa file. */
  'mobile:pick': { args: ['folder' | 'file']; result: string | null }
  'mobile:start': { args: [MobileScanRequest]; result: SessionInfo }
  'mobile:live-setup': { args: []; result: LiveSetupInfo }
  'mobile:avd-start': { args: [string]; result: LiveSetupInfo }
  'mobile:avd-create': { args: []; result: LiveSetupInfo }
  'cloud:status': { args: []; result: { azure: string | null; aws: string | null } }
  'cloud:azure-login': { args: []; result: { azure: string | null; aws: string | null } }
  'tools:optional': { args: []; result: OptionalTool[] }
  'sessions:rerun': { args: [string]; result: SessionInfo }
  'sessions:rerun-latest': { args: []; result: SessionInfo[] }
  'findings:retest': { args: [string, string]; result: SessionDetail }
  'findings:ticket': { args: [string, string, 'markdown' | 'jira']; result: string }
  'findings:github-issue': { args: [string, string, string]; result: { url: string; number: number } }
  'assets:list': { args: []; result: AssetInfo[] }
  'sessions:fixplan': { args: [string]; result: FixPlan }
  'sessions:pause': { args: [string, boolean]; result: boolean }
  'sessions:pdf-executive': { args: [string]; result: string | null }
  'sessions:checklist': { args: [string]; result: ChecklistData }
  'sessions:checklist-set': { args: [string, string, 'done' | 'problem' | 'na' | null, string?]; result: ChecklistData }
  'web:pick-code': { args: []; result: string | null }
  'findings:triage': { args: [string, string, 'fixed' | 'accepted' | 'not-a-problem' | null]; result: SessionDetail }
  'app:check-update': { args: []; result: UpdateInfo | null }
  'app:install-update': { args: []; result: void }
  'app:update-status': { args: []; result: UpdateStatus }
  'app:changelog': { args: []; result: ReleaseNote[] }
  'recon:start': { args: [ReconRequest]; result: SessionInfo }
  'recon:data': { args: [string]; result: { hosts: { host: string; ips: string[]; cname?: string; live?: { url: string; status: number; title?: string; tech: string[] }; sources: string[] }[]; js: { url: string; bytes: number; sourceMap?: { url: string; files: number; sample: string[] }; endpoints: string[]; secrets: { kind: string; masked: string }[] }[]; endpoints: string[]; params: string[]; urls: number; pages?: ReconPage[]; delta?: ReconDeltaInfo; jsmap?: JsMapInfo } | null }
  'sessions:open-sources': { args: [string]; result: boolean }
  'ai:claude-skills': { args: [boolean | null]; result: { installed: boolean } }
  'sessions:list': { args: []; result: SessionInfo[] }
  'overview:top': { args: []; result: import('./insights').TopFinding[] }
  'sessions:get': { args: [string]; result: SessionDetail }
  'sessions:owasp': { args: [string]; result: OwaspChecklistInfo }
  'sessions:compare': { args: [string]; result: SessionCompare }
  'sessions:export': { args: [string, 'sarif' | 'defectdojo' | 'cyclonedx' | 'json']; result: string | null }
  'projects:save-hook': { args: [string]; result: string | null }
  'projects:save-ci': { args: [string, 'github' | 'azure']; result: string | null }
  'checkup:run': { args: []; result: CheckupResult }
  'checkup:last': { args: []; result: CheckupResult | null }
  'docker:images': { args: []; result: { running: boolean; images: { ref: string; size: string; created: string }[] } }
  'docker:scan': { args: [string]; result: Finding[] }
  'packs:list': { args: []; result: SkillPackInfo[] }
  'packs:asked': { args: []; result: 'yes' | 'no' | null }
  'packs:answer': { args: [boolean]; result: SkillPackInfo[] }
  'packs:install': { args: [string]; result: SkillPackInfo[] }
  'packs:remove': { args: [string]; result: SkillPackInfo[] }
  'editors:list': { args: []; result: { found: { id: string; name: string }[]; current: string | null } }
  'editors:choose-app': { args: []; result: { app: string; name: string } | null }
  'freellm:get': { args: []; result: FreeLlmInfo }
  'freellm:check': { args: []; result: FreeLlmInfo }
  'freellm:save': { args: [{ baseUrl: string; model: string; key?: string | null }]; result: FreeLlmInfo }
  'integrations:get': { args: []; result: IntegrationsInfo }
  'kit:leaks': { args: []; result: LeakKitInfo }
  'kit:save': { args: []; result: string }
  'webhook:set': { args: [{ kind: 'slack' | 'teams' | 'discord' | 'generic'; events: 'errors' | 'all' } | null, string | null]; result: IntegrationsInfo }
  'webhook:test': { args: []; result: void }
  'raycast:install': { args: []; result: IntegrationsInfo }
  'mcp:enable': { args: [boolean]; result: IntegrationsInfo }
  'sessions:delete': { args: [string]; result: SessionInfo[] }
  'sessions:cancel': { args: [string]; result: void }
  'sessions:pdf': { args: [string]; result: string | null }
  'sessions:open': { args: [string, 'folder' | 'code' | 'claude' | 'claude-one' | 'codex' | 'file', string?, number?]; result: void }
  'sessions:discard-code': { args: [string]; result: SessionInfo }

  'ai:agents': { args: []; result: AgentInfo[] }
  'ai:install-agent': { args: ['claude' | 'codex']; result: void }
  'ai:set-key': { args: [string | null]; result: { hasKey: boolean } }
  'ai:key-status': { args: []; result: { hasKey: boolean } }
  'ai:skills': { args: []; result: { name: string; mine: boolean }[] }
  'ai:open-app': { args: ['claude' | 'codex' | 'lmstudio' | 'burp']; result: void }
  'ai:detect': { args: []; result: LocalLlm[] }
  'ai:test': { args: [string, string]; result: LlmTest }
  'ai:servers': { args: []; result: ModelServer[] }
  'ai:save-server': { args: [ModelServerInput]; result: ModelServer[] }
  'ai:delete-server': { args: [string]; result: ModelServer[] }

  'logs:list': { args: []; result: LogLine[] }
  'logs:clear': { args: []; result: void }
}

export interface Events {
  /** From the menu bar: go to a page, or open one result. */
  'app:navigate': { page: string; session?: string }
  'tools:updates': string[]
  'jobs:changed': JobInfo[]
  'sessions:changed': SessionInfo[]
  'session:updated': SessionInfo
  'logs:line': LogLine
  'app:update': UpdateInfo
  'watch:alert': { title: string; body: string }
  /** A message for the notification toasts and history. */
  notice: { kind: 'info' | 'success' | 'error'; title: string; body?: string }
}

export interface MacSecApi {
  invoke<K extends keyof Channels>(channel: K, ...args: Channels[K]['args']): Promise<Channels[K]['result']>
  on<K extends keyof Events>(event: K, cb: (payload: Events[K]) => void): () => void
  platform: string
}

export interface SkillChoice {
  id: string
  name: string
  source: string
  about: string
  guides: number
}

export interface SkillPlan {
  /** What the project is made of, as short tags (php, laravel, react...). */
  stack: string[]
  items: SkillChoice[]
  recommended: string[]
  files: number
}

export interface WatchAlert {
  at: string
  kind: 'packages' | 'retest'
  project: string
  /** The session to open for details. */
  session: string
  count: number
  titles: string[]
}

export interface WatchInfo {
  /** Daily: new flaws in the packages of the projects you reviewed. */
  packages: boolean
  /** Weekly: the newest review of each project runs again. */
  retest: boolean
  lastPackages: string | null
  lastRetest: string | null
  projects: number
  alerts: WatchAlert[]
  window: WatchWindow
}

export interface OwaspItemInfo {
  id: string
  name: string
  about: string
  howToCheck: string
  status: 'issues' | 'checked' | 'not-checked'
  count: number
  worst: Severity | null
  examples: string[]
  checkedBy: string[]
}

/** A session's findings under the OWASP Top 10 (2025), and what the session could see. */
export interface OwaspChecklistInfo {
  items: OwaspItemInfo[]
  other: number
  covered: number
}

/** The "Stop leaking keys" kit: a pre-commit hook, a pre-commit config and a GitHub Action. */
export interface LeakKitInfo {
  hook: string
  preCommit: string
  action: string
  steps: { hook: string[]; preCommit: string[]; action: string[] }
  version: string
}

/** One page from a recon's crawl, broken down (read only). */
export interface ReconPage {
  url: string
  status: number
  title?: string
  type: string
  bytes: number
  ms: number
  redirect?: string
  forms: { action: string; method: string; inputs: { name: string; type: string }[]; csrf: boolean; password: boolean; offsite: boolean; insecure: boolean }[]
  params: string[]
  scripts: { total: number; inline: number; external: string[]; withoutSri: number }
  headers: { name: string; present: boolean; value?: string }[]
  cookies: { name: string; secure: boolean; httpOnly: boolean; sameSite: string | null }[]
  tech: string[]
  mixed: number
  notes: { severity: Severity; text: string }[]
}

// ---------------------------------------------------------------- Assets, plans and self-test

export interface Chain {
  id: string
  name: string
  story: string
  members: { id: string; title: string; severity: Severity }[]
  /** One level above the worst part, because together they are worse than any one alone. */
  severity: Severity
}

export interface Action {
  title: string
  fix: string
  count: number
  worst: Severity
  /** How much of the total risk goes away when this one action is done, in points of the 0 to 100 score. */
  drop: number
  ids: string[]
}

export interface AssetInfo {
  key: string
  name: string
  kind: 'site' | 'api' | 'domain' | 'app' | 'project' | 'mac' | 'other'
  scans: number
  lastScan: string
  lastSession: string
  open: Record<Severity, number>
  proven: number
  risk: number
  riskLabel: string
  /** The risk after each finished scan, oldest first. */
  trend: { at: string; risk: number; open: number }[]
  fixed: number
  /** Average days between a finding first being seen and the first scan that no longer had it. */
  mttrDays?: number
  actions: Action[]
  dropIfDone: number
  chains: Chain[]
}

export interface FixPlan {
  actions: Action[]
  before: number
  after: number
  chains: Chain[]
}


/** Hours of the day (0 to 23, this Mac's time) when automatic scans may run. */
export interface WatchWindow {
  on: boolean
  from: number
  to: number
}

export type ChecklistState = 'found' | 'clear' | 'ai-ok' | 'ai-issue' | 'manual'
export interface ChecklistItemInfo {
  id: string
  text: string
  state: ChecklistState
  by: 'macsec' | 'ai' | 'none'
  covered?: string
  findings?: string[]
  note?: string
}
export interface ChecklistInfo {
  at: string
  ai: boolean
  sections: { n: number; title: string; relevant: boolean; items: ChecklistItemInfo[] }[]
}
export interface ChecklistData {
  checklist: ChecklistInfo | null
  user: Record<string, { state: 'done' | 'problem' | 'na'; note?: string; at: string }>
}
