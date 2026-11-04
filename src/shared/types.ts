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
}

export type Reviewer = 'none' | 'claude' | 'claude-local' | 'codex' | 'gemini' | 'model'

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
  reviewer: Reviewer
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

export interface ReviewRequest {
  source: ReviewSource
  reviewer: Reviewer
  depth: ReviewDepth
  focus: ReviewFocus
  /** Keep the downloaded code after the review, to fix it. Remote sources only. */
  keepCode: boolean
  /** Tool ids to skip. */
  skip?: string[]
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
  | { kind: 'server'; host: string; ports: 'top100' | 'top1000'; reviewer: Reviewer; authorized: boolean }

/** A mobile app: its source folder, or a built .apk or .ipa file. */
export interface ReconRequest {
  target: string
  depth: 'passive' | 'standard' | 'deep'
  reviewer: Reviewer
  authorized: boolean
}

export interface MobileScanRequest {
  path: string
  reviewer: Reviewer
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
  error?: string
  languages?: string[]
  files?: number
}

export interface SessionDetail extends SessionInfo {
  findings: Finding[]
  /** The AI reviewer's written report (markdown). */
  aiReport?: string
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
  /** Default reviewer for new reviews. */
  reviewer: Reviewer
  notifications: boolean
  /** How Claude Code signs in: your normal account, or an Anthropic API key from the Keychain. */
  claudeAuth: 'account' | 'key'
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
  'cloud:status': { args: []; result: { azure: string | null; aws: string | null } }
  'cloud:azure-login': { args: []; result: { azure: string | null; aws: string | null } }
  'tools:optional': { args: []; result: OptionalTool[] }
  'recon:start': { args: [ReconRequest]; result: SessionInfo }
  'recon:data': { args: [string]; result: { hosts: { host: string; ips: string[]; cname?: string; live?: { url: string; status: number; title?: string; tech: string[] }; sources: string[] }[]; js: { url: string; bytes: number; sourceMap?: { url: string; files: number; sample: string[] }; endpoints: string[]; secrets: { kind: string; masked: string }[] }[]; endpoints: string[]; params: string[]; urls: number } | null }
  'ai:claude-skills': { args: [boolean | null]; result: { installed: boolean } }
  'sessions:list': { args: []; result: SessionInfo[] }
  'sessions:get': { args: [string]; result: SessionDetail }
  'sessions:delete': { args: [string]; result: SessionInfo[] }
  'sessions:cancel': { args: [string]; result: void }
  'sessions:pdf': { args: [string]; result: string | null }
  'sessions:open': { args: [string, 'folder' | 'code' | 'claude' | 'codex' | 'file', string?, number?]; result: void }
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
  'tools:updates': string[]
  'jobs:changed': JobInfo[]
  'sessions:changed': SessionInfo[]
  'session:updated': SessionInfo
  'logs:line': LogLine
}

export interface MacSecApi {
  invoke<K extends keyof Channels>(channel: K, ...args: Channels[K]['args']): Promise<Channels[K]['result']>
  on<K extends keyof Events>(event: K, cb: (payload: Events[K]) => void): () => void
  platform: string
}
