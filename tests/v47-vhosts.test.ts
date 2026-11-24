/** 1.27: bounded virtual-host discovery, against a local server that answers by Host. */
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createServer, type Server } from 'http'
import { probeVhosts } from '../src/main/vhosts'

let server: Server
let port = 0
beforeAll(async () => {
  server = createServer((req, res) => {
    if (req.headers.host === 'admin.shop.test') {
      res.writeHead(200, { 'content-type': 'text/html' })
      res.end('<title>Admin panel</title><h1>Orders</h1>')
      return
    }
    res.writeHead(404, { 'content-type': 'text/html' })
    res.end('<title>Not found</title>')
  })
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()))
  port = (server.address() as { port: number }).port
})
afterAll(() => void server.close())

describe('virtual-host discovery', () => {
  it('finds the one name that answers differently, and leaves the default alone', async () => {
    const hits = await probeVhosts(`http://127.0.0.1:${port}`, '127.0.0.1', ['admin.shop.test', 'www.shop.test'], { delayMs: 0, timeoutMs: 3000 })
    expect(hits.map((h) => h.name)).toEqual(['admin.shop.test'])
    expect(hits[0]).toMatchObject({ status: 200, title: 'Admin panel' })
    expect(hits[0].reason).toMatch(/cannot exist answered 404/)
  })
  it('refuses names that are not plain hostnames and caps the list', async () => {
    const hits = await probeVhosts(`http://127.0.0.1:${port}`, '127.0.0.1', ['admin.shop.test', 'bad name', '../etc', 'x'.repeat(300)], { delayMs: 0, max: 2 })
    expect(hits.length).toBeLessThanOrEqual(2)
    expect(hits.every((h) => !h.name.includes(' '))).toBe(true)
  })
  it('reports nothing when every name answers like the baseline', async () => {
    const hits = await probeVhosts(`http://127.0.0.1:${port}`, '127.0.0.1', ['a.shop.test', 'b.shop.test'], { delayMs: 0 })
    expect(hits).toEqual([])
  })
})
