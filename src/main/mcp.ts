import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'http'
import { randomBytes, timingSafeEqual } from 'crypto'
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs'
import { join } from 'path'
import { dirs } from './paths'

/**
 * A Model Context Protocol server, so Claude Code, Claude desktop, Cursor and other agents can
 * work with MacSec: read sessions and findings, compare them over time, start a code review of
 * a project in your www folder, scan a site on this Mac, and run the Mac check-up.
 *
 * Off until you turn it on. Streamable HTTP, JSON only, on 127.0.0.1, with a bearer token kept
 * in ~/MacSec/config/mcp-token (0600). Browser origins are refused, so a web page cannot reach it.
 */
export const MCP_PORT = 53537
const PROTOCOLS = ['2025-11-25', '2025-06-18', '2025-03-26']

export interface McpTool {
  name: string
  description: string
  inputSchema: Record<string, unknown>
  /** Changes something rather than only reading. */
  writes?: boolean
  run: (args: Record<string, unknown>) => Promise<unknown>
}

const tokenFile = (): string => join(dirs.config(), 'mcp-token')

export function mcpToken(): string {
  if (existsSync(tokenFile())) {
    const t = readFileSync(tokenFile(), 'utf8').trim()
    if (/^[a-f0-9]{48}$/.test(t)) return t
  }
  mkdirSync(dirs.config(), { recursive: true, mode: 0o700 })
  const t = randomBytes(24).toString('hex')
  writeFileSync(tokenFile(), t + '\n', { mode: 0o600 })
  chmodSync(tokenFile(), 0o600)
  return t
}

export const mcpUrl = (port = MCP_PORT): string => `http://127.0.0.1:${port}/mcp`

type Rpc = { jsonrpc: '2.0'; id?: string | number | null; method: string; params?: Record<string, unknown> }

function rpcResult(id: Rpc['id'], result: unknown): object {
  return { jsonrpc: '2.0', id: id ?? null, result }
}
function rpcError(id: Rpc['id'], code: number, message: string): object {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message } }
}

function authorized(req: IncomingMessage, token: string, port: number): string | null {
  const host = req.headers.host ?? ''
  if (host !== `127.0.0.1:${port}` && host !== `localhost:${port}`) return 'Unknown host.'
  // Browsers always send Origin on cross-site requests; agents do not.
  const origin = req.headers.origin
  if (origin && origin !== `http://127.0.0.1:${port}` && origin !== `http://localhost:${port}`) return 'Browser requests are not allowed.'
  const auth = req.headers.authorization ?? ''
  const given = Buffer.from(auth.startsWith('Bearer ') ? auth.slice(7).trim() : '')
  const want = Buffer.from(token)
  if (given.length !== want.length || !timingSafeEqual(given, want)) return 'Missing or wrong token.'
  return null
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = ''
    req.setEncoding('utf8')
    req.on('data', (c: string) => {
      body += c
      if (body.length > 1_000_000) {
        reject(new Error('Request too large.'))
        req.destroy()
      }
    })
    req.on('end', () => resolve(body))
    req.on('error', reject)
  })
}

export async function handleRpc(msg: Rpc, tools: McpTool[], version: string, onCall?: (name: string) => void): Promise<object | null> {
  if (msg?.jsonrpc !== '2.0' || typeof msg.method !== 'string') return rpcError(null, -32600, 'Invalid request.')
  const isNotification = msg.id === undefined
  switch (msg.method) {
    case 'initialize': {
      const asked = String(msg.params?.protocolVersion ?? '')
      return rpcResult(msg.id, {
        protocolVersion: PROTOCOLS.includes(asked) ? asked : PROTOCOLS[0],
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'macsec', title: 'MacSec', version },
        instructions:
          'MacSec is a read-only security workbench on this Mac. Use list_sessions and get_session to read past reviews and scans (secrets are never included, only where they are), compare_session to see what is new or fixed, list_projects to see the www folder, start_code_review to review a project, and mac_checkup for this Mac\'s security settings. It never attacks anything.'
      })
    }
    case 'ping':
      return rpcResult(msg.id, {})
    case 'tools/list':
      return rpcResult(msg.id, {
        tools: tools.map((t) => ({
          name: t.name,
          description: t.description,
          inputSchema: t.inputSchema,
          annotations: { readOnlyHint: !t.writes, destructiveHint: false, openWorldHint: false }
        }))
      })
    case 'tools/call': {
      const name = String(msg.params?.name ?? '')
      const tool = tools.find((t) => t.name === name)
      if (!tool) return rpcError(msg.id, -32602, `Unknown tool: ${name}`)
      const args = (msg.params?.arguments ?? {}) as Record<string, unknown>
      if (typeof args !== 'object' || Array.isArray(args)) return rpcError(msg.id, -32602, 'Arguments must be an object.')
      onCall?.(name)
      try {
        const out = await tool.run(args)
        const text = typeof out === 'string' ? out : JSON.stringify(out, null, 2)
        return rpcResult(msg.id, { content: [{ type: 'text', text }], isError: false })
      } catch (err) {
        return rpcResult(msg.id, { content: [{ type: 'text', text: (err as Error).message }], isError: true })
      }
    }
    default:
      if (isNotification) return null
      return rpcError(msg.id, -32601, `Method not found: ${msg.method}`)
  }
}

export function startMcpServer(opts: { tools: McpTool[]; version: string; port?: number; onCall?: (name: string) => void }): Promise<Server> {
  const port = opts.port ?? MCP_PORT
  const token = mcpToken()
  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const send = (status: number, body?: object): void => {
      res.writeHead(status, body ? { 'Content-Type': 'application/json' } : {})
      res.end(body ? JSON.stringify(body) : undefined)
    }
    const problem = authorized(req, token, port)
    if (problem) return send(problem.startsWith('Unknown host') ? 421 : 401, rpcError(null, -32001, problem))
    if ((req.url ?? '').split('?')[0] !== '/mcp') return send(404)
    if (req.method === 'GET') return send(405)
    if (req.method === 'DELETE') return send(200)
    if (req.method !== 'POST') return send(405)
    let parsed: unknown
    try {
      parsed = JSON.parse(await readBody(req))
    } catch {
      return send(400, rpcError(null, -32700, 'Parse error.'))
    }
    if (Array.isArray(parsed)) {
      const out = (await Promise.all(parsed.map((m) => handleRpc(m as Rpc, opts.tools, opts.version, opts.onCall)))).filter(Boolean) as object[]
      return out.length ? send(200, out as unknown as object) : send(202)
    }
    const out = await handleRpc(parsed as Rpc, opts.tools, opts.version, opts.onCall)
    return out ? send(200, out) : send(202)
  })
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, '127.0.0.1', () => resolve(server))
  })
}
