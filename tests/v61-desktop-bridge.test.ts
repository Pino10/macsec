import { afterEach, describe, expect, it } from 'vitest'
import { chmodSync, mkdtempSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { spawn } from 'child_process'
import { createServer, type Server } from 'http'
import { desktopBridge } from '../src/main/seckit/desktopbridge'

let srv: Server | null = null
afterEach(async () => {
  if (srv) await new Promise((r) => srv!.close(() => r(null)))
  srv = null
})

function setup(url: string): string {
  const d = mkdtempSync(join(tmpdir(), 'bridge-'))
  writeFileSync(join(d, 'token'), 'abc123\n')
  const script = join(d, 'bridge.sh')
  writeFileSync(script, desktopBridge(url, join(d, 'token'), 'MacSec'))
  chmodSync(script, 0o755)
  return script
}
const run = (script: string, input: string): Promise<string> =>
  new Promise((resolve) => {
    const p = spawn('/bin/sh', [script])
    let out = ''
    p.stdout.on('data', (c) => (out += c))
    p.on('close', () => resolve(out))
    p.stdin.end(input)
  })
const listen = (handler: (status: { code: number; body: string }) => void, code: number, body: string): Promise<string> =>
  new Promise((resolve) => {
    srv = createServer((_q, r) => {
      handler({ code, body })
      r.writeHead(code, { 'content-type': 'application/json' })
      r.end(body)
    })
    srv.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${(srv!.address() as { port: number }).port}/mcp`))
  })

describe('the Claude desktop bridge', () => {
  it('answers a request with its id when the app is not running', async () => {
    const out = await run(setup('http://127.0.0.1:9/mcp'), '{"jsonrpc":"2.0","id":7,"method":"tools/list"}\n')
    expect(JSON.parse(out)).toMatchObject({ id: 7, error: { message: expect.stringContaining('not running') } })
  })
  it('finds a string id that is not first', async () => {
    const script = setup('http://127.0.0.1:9/mcp')
    expect(JSON.parse(await run(script, '{"method":"tools/list","id":"abc-1","jsonrpc":"2.0"}\n')).id).toBe('abc-1')
  })
  it('stays silent for a notification', async () => {
    expect(await run(setup('http://127.0.0.1:9/mcp'), '{"jsonrpc":"2.0","method":"notifications/initialized"}\n')).toBe('')
  })
  it('says what is wrong when the token is refused, instead of waiting', async () => {
    const url = await listen(() => undefined, 401, '{"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"Missing or wrong token."}}')
    const out = await run(setup(url), '{"jsonrpc":"2.0","id":3,"method":"initialize"}\n')
    expect(JSON.parse(out)).toMatchObject({ id: 3, error: { message: expect.stringContaining('wrong token') } })
  })
  it('passes a good answer through on one line and sends the token', async () => {
    let seen = ''
    const url = await new Promise<string>((resolve) => {
      srv = createServer((q, r) => {
        seen = String(q.headers.authorization)
        q.resume()
        r.writeHead(200, { 'content-type': 'application/json' })
        r.end('{"jsonrpc":"2.0","id":1,"result":{"ok":true}}')
      })
      srv.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${(srv!.address() as { port: number }).port}/mcp`))
    })
    const out = await run(setup(url), '{"jsonrpc":"2.0","id":1,"method":"ping"}\n')
    expect(JSON.parse(out)).toEqual({ jsonrpc: '2.0', id: 1, result: { ok: true } })
    expect(seen).toBe('Bearer abc123')
  })
})
