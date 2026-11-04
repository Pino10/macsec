/**
 * The AI reviewers both apps can use, shared by Laramac and MacSec (keep the two copies of
 * src/main/seckit the same). Every reviewer runs read-only.
 *
 *   claude        Claude Code with your normal sign-in: plan mode, only Read, Grep, Glob and Skill.
 *   claude-local  The same Claude Code, talking to your own model in LM Studio (or any server with
 *                 an Anthropic-compatible /v1/messages endpoint) instead of Anthropic.
 *   codex         OpenAI's Codex in its read-only sandbox.
 *   gemini        Google's Gemini CLI, in plan mode (it reads, it cannot change files or run commands).
 *   coderabbit    CodeRabbit's CLI: an independent second opinion on the changes in a Git project.
 */
import { randomUUID } from 'crypto'

export type ReviewerId = 'claude' | 'claude-local' | 'codex' | 'gemini' | 'coderabbit'

export interface LocalModel {
  /** The server's address, such as http://127.0.0.1:1234/v1 (LM Studio). */
  baseUrl: string
  model: string
  /** LM Studio's API token when "Require authentication" is on. */
  token?: string
}

export interface ReviewerRun {
  bin: string
  args: string[]
  env: Record<string, string>
  /** For Claude Code: the session, so you can carry on with it later. */
  session?: string
  /** CodeRabbit reviews changes, not a whole folder. */
  needsGit?: boolean
}

export const REVIEWER_NAMES: Record<ReviewerId, string> = {
  claude: 'Claude Code',
  'claude-local': 'Claude Code on your model',
  codex: 'Codex',
  gemini: 'Gemini CLI',
  coderabbit: 'CodeRabbit'
}

/** Where Claude Code should send requests for a local server: its root, without /v1. */
export function anthropicBase(baseUrl: string): string {
  return baseUrl.trim().replace(/\/+$/, '').replace(/\/v1$/, '').replace('://localhost', '://127.0.0.1')
}

/** Environment that points Claude Code at a local model; nothing else in your Claude setup changes. */
export function localModelEnv(m: LocalModel): Record<string, string> {
  return {
    ANTHROPIC_BASE_URL: anthropicBase(m.baseUrl),
    ANTHROPIC_AUTH_TOKEN: m.token || 'lmstudio',
    ANTHROPIC_API_KEY: '',
    ANTHROPIC_MODEL: m.model,
    ANTHROPIC_DEFAULT_SONNET_MODEL: m.model,
    ANTHROPIC_DEFAULT_OPUS_MODEL: m.model,
    ANTHROPIC_DEFAULT_HAIKU_MODEL: m.model,
    ANTHROPIC_SMALL_FAST_MODEL: m.model,
    CLAUDE_CODE_SUBAGENT_MODEL: m.model,
    CLAUDE_CODE_ATTRIBUTION_HEADER: '0',
    // Leave room in a local model's context for the files it reads.
    CLAUDE_CODE_MAX_OUTPUT_TOKENS: '8192',
    // A local model cannot use Anthropic's web tools or telemetry.
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1',
    DISABLE_TELEMETRY: '1'
  }
}

/** The command line for one reviewer. `bin` is the CLI's path; `plugins` are --plugin-dir folders. */
export function reviewerRun(id: ReviewerId, bin: string, prompt: string, o: { plugins?: string[]; name?: string; local?: LocalModel; outFile?: string; cwd?: string; base?: string } = {}): ReviewerRun {
  if (id === 'claude' || id === 'claude-local') {
    const session = randomUUID()
    const plugins = (o.plugins ?? []).flatMap((p) => ['--plugin-dir', p])
    return {
      bin,
      session,
      args: ['-p', prompt, '--output-format', 'text', '--permission-mode', 'plan', '--allowedTools', 'Read,Grep,Glob,Skill', '--disallowedTools', 'Bash,Edit,Write,NotebookEdit,WebFetch,WebSearch', '--session-id', session, ...(o.name ? ['--name', o.name.slice(0, 80)] : []), ...(id === 'claude-local' && o.local ? ['--model', o.local.model] : []), ...plugins],
      env: id === 'claude-local' && o.local ? localModelEnv(o.local) : {}
    }
  }
  if (id === 'codex') return { bin, args: ['exec', '--sandbox', 'read-only', '--skip-git-repo-check', '--color', 'never', ...(o.outFile ? ['--output-last-message', o.outFile] : []), prompt], env: {} }
  if (id === 'gemini') return { bin, args: ['-p', prompt, '--approval-mode', 'plan', '--output-format', 'text'], env: { GEMINI_CLI_NO_RELAUNCH: 'true' } }
  return { bin, args: ['review', '--plain', '--no-color', ...(o.base ? ['--base', o.base] : ['--type', 'all']), ...(o.cwd ? ['--cwd', o.cwd] : [])], env: {}, needsGit: true }
}

/** Claude Code's error text, in words a person can act on. */
export function explainFailure(id: ReviewerId, err: string): string {
  if (id === 'claude-local' && /ECONNREFUSED|connect|fetch failed|404/i.test(err)) return 'Claude Code could not reach your model. In LM Studio, load the model and start the server (Developer, Start server), then try again. LM Studio 0.4.1 or newer is needed.'
  if (id === 'claude-local' && /context|too long|maximum/i.test(err)) return 'The model’s context window is too small for Claude Code. In LM Studio, load it with a context length of 32,000 tokens or more.'
  if (/log ?in|auth|credential|api key|401/i.test(err)) return `${REVIEWER_NAMES[id]} is not signed in. Open it once in Terminal and sign in, then try again.`
  if (id === 'coderabbit' && /not a git|no changes/i.test(err)) return 'CodeRabbit reviews the changes in a Git project. Commit or change something first, or choose another reviewer.'
  return `${REVIEWER_NAMES[id]} stopped without a report. ${err.trim().split('\n').slice(-2).join(' ')}`.trim()
}
