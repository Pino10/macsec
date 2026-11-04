/** What AI tools can do with MacSec through MCP, and the macsec command for Terminal and Raycast. */
import type { Finding, SessionInfo } from '../shared/types'
import type { McpTool } from './mcp'

export interface McpDeps {
  sessions: () => SessionInfo[]
  session: (id: string) => SessionInfo & { findings: Finding[]; aiReport?: string }
  compare: (id: string) => unknown
  projects: () => { name: string; path: string; languages: string[]; url?: string }[]
  review: (path: string, depth: 'quick' | 'standard' | 'deep') => SessionInfo | Promise<SessionInfo>
  checkup: () => Promise<unknown>
}

const str = (v: unknown, name: string): string => {
  if (typeof v !== 'string' || !v.trim()) throw new Error(`${name} is needed.`)
  return v.trim()
}

export function macsecTools(d: McpDeps): McpTool[] {
  return [
    { name: 'list_sessions', description: 'MacSec sessions (code reviews, web, API, mobile and recon scans), newest first, with counts by severity.', inputSchema: { type: 'object', properties: { limit: { type: 'number' } } }, run: async (a) => d.sessions().slice(0, Math.min(Number(a.limit) || 20, 100)).map((s) => ({ id: s.id, kind: s.kind, title: s.title, target: s.target, status: s.status, at: s.createdAt, counts: s.counts })) },
    {
      name: 'get_session',
      description: 'One session with its findings: severity, title, file and line, description and fix. Secrets are never included, only where they are.',
      inputSchema: { type: 'object', properties: { id: { type: 'string' }, severity: { type: 'string', description: 'critical, high, medium, low or info: only this level and above' } }, required: ['id'] },
      run: async (a) => {
        const s = d.session(str(a.id, 'id'))
        const order = ['critical', 'high', 'medium', 'low', 'info']
        const min = order.indexOf(String(a.severity ?? 'info'))
        return { ...s, findings: s.findings.filter((f) => order.indexOf(f.severity) <= (min < 0 ? 4 : min)).map(({ context: _c, ...f }) => f) }
      }
    },
    { name: 'compare_session', description: 'What is new, fixed or still there compared with the previous session on the same target.', inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] }, run: async (a) => d.compare(str(a.id, 'id')) },
    { name: 'list_projects', description: 'Projects in the www folder (shared with Laramac), with their languages and Laramac address.', inputSchema: { type: 'object', properties: {} }, run: async () => d.projects() },
    {
      name: 'start_code_review',
      description: 'Starts a read-only security review of a project in the www folder (scanners, then the AI reviewer). Returns the session id; read it with get_session when it is done.',
      writes: true,
      inputSchema: { type: 'object', properties: { project: { type: 'string', description: 'Folder name in www' }, depth: { type: 'string', enum: ['quick', 'standard', 'deep'] } }, required: ['project'] },
      run: async (a) => {
        const p = d.projects().find((x) => x.name === str(a.project, 'project'))
        if (!p) throw new Error('No project with that name in the www folder. See list_projects.')
        const s = await d.review(p.path, a.depth === 'quick' || a.depth === 'deep' ? a.depth : 'standard')
        return { session: s.id, status: s.status }
      }
    },
    { name: 'mac_checkup', description: 'Checks this Mac’s security settings: FileVault, firewall, Gatekeeper, SIP, updates, login items, open ports, SSH keys and browser extensions. Only reads.', inputSchema: { type: 'object', properties: {} }, run: async () => d.checkup() }
  ]
}

/**
 * The macsec command: a small shell script that talks to MacSec's MCP server with its token.
 * macOS's own JavaScript (osascript) reads the answers, so nothing else is needed.
 */
export function macsecCli(tokenFile: string, port: number): string {
  return `#!/bin/bash
# Written by MacSec. Usage: macsec help
TOKEN_FILE="${tokenFile}"
[ -r "$TOKEN_FILE" ] || { echo "macsec: open MacSec and turn on \\"Let AI tools use MacSec\\" in Settings." >&2; exit 1; }
TOKEN=$(cat "$TOKEN_FILE")
JSON=0
ARGS=()
for a in "$@"; do [ "$a" = "--json" ] && JSON=1 || ARGS+=("$a"); done
set -- "\${ARGS[@]}"
call() {
  curl -sS --max-time 600 -X POST "http://127.0.0.1:${port}/mcp" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" --data "$1" || { echo "macsec: MacSec is not answering. Open it first." >&2; exit 1; }
}
text() {
  /usr/bin/osascript -l JavaScript -e 'function run(a){const r=JSON.parse(a[0]);if(r.error)return "macsec: "+r.error.message;return r.result.content[0].text}' "$1"
}
tool() { text "$(call "{\\"jsonrpc\\":\\"2.0\\",\\"id\\":1,\\"method\\":\\"tools/call\\",\\"params\\":{\\"name\\":\\"$1\\",\\"arguments\\":$2}}")"; }
pretty() {
  if [ "$JSON" = 1 ]; then cat; else /usr/bin/osascript -l JavaScript -e 'function run(a){let d;try{d=JSON.parse(a[0])}catch(e){return a[0]}if(Array.isArray(d))return d.map(x=>[x.status||"",x.title||x.name||"",x.target||x.path||"",x.counts?("crit "+x.counts.critical+" high "+x.counts.high+" med "+x.counts.medium):""].join("  ")).join("\\n");if(d.checks)return "Score "+d.score+"/100\\n"+d.checks.map(c=>(c.status==="ok"?"✓ ":c.status==="bad"?"✗ ":"! ")+c.title+": "+c.detail).join("\\n");return JSON.stringify(d,null,2)}' "$(cat)"; fi
}
case "$1" in
  sessions) tool list_sessions '{}' | pretty ;;
  session) tool get_session "{\\"id\\":\\"$2\\"}" | pretty ;;
  compare) tool compare_session "{\\"id\\":\\"$2\\"}" | pretty ;;
  projects) tool list_projects '{}' | pretty ;;
  review) [ -n "$2" ] || { echo "Usage: macsec review <project in www> [quick|standard|deep]"; exit 1; }; tool start_code_review "{\\"project\\":\\"$2\\",\\"depth\\":\\"\${3:-standard}\\"}" | pretty ;;
  checkup) tool mac_checkup '{}' | pretty ;;
  *) cat <<'HELP'
macsec: MacSec from Terminal, Raycast and Shortcuts

  macsec sessions              latest sessions and their counts
  macsec session <id>          one session's findings
  macsec compare <id>          new, fixed and remaining since last time
  macsec projects              projects in your www folder
  macsec review <project>      start a code review [quick|standard|deep]
  macsec checkup               this Mac's security settings

Add --json for machine-readable output.
HELP
  ;;
esac
`
}
