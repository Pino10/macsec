/**
 * A local metering proxy for plugin tools that honour HTTP(S)_PROXY. It counts requests and refuses
 * past the budget. It is not a sandbox: a tool that ignores the proxy is not counted, and a tool
 * that opens raw sockets is not seen at all. The UI says so.
 */
import { createServer, request as httpRequest, type Server } from 'http'
import { connect, type Socket } from 'net'

export interface MeteredProxy {
  url: string
  count: () => number
  exceeded: () => boolean
  close: () => Promise<void>
}

export async function startMeteredProxy(cap: number, onExceeded?: () => void): Promise<MeteredProxy> {
  let n = 0
  let over = false
  const sockets = new Set<Socket>()
  const server: Server = createServer((req, res) => {
    if (over) {
      res.writeHead(429, { 'content-type': 'text/plain' })
      res.end('MacSec plugin budget exhausted')
      return
    }
    n += 1
    if (n > cap) {
      over = true
      res.writeHead(429, { 'content-type': 'text/plain' })
      res.end('MacSec plugin budget exhausted')
      onExceeded?.()
      return
    }
    let target: URL
    try {
      target = new URL(req.url ?? '', 'http://127.0.0.1')
    } catch {
      res.writeHead(400).end('bad request')
      return
    }
    if (!/^https?:$/.test(target.protocol)) {
      res.writeHead(405).end('only http and https through CONNECT')
      return
    }
    const up = httpRequest(
      { hostname: target.hostname, port: target.port || 80, path: target.pathname + target.search, method: req.method, headers: { ...req.headers, host: target.host, connection: 'close' } },
      (r) => {
        res.writeHead(r.statusCode ?? 502, r.headers)
        r.pipe(res)
      }
    )
    up.on('error', () => {
      if (!res.headersSent) res.writeHead(502)
      res.end('upstream error')
    })
    req.pipe(up)
  })
  server.on('connect', (req, client, head) => {
    if (over) {
      client.end('HTTP/1.1 429 Too Many Requests\r\n\r\n')
      return
    }
    n += 1
    if (n > cap) {
      over = true
      client.end('HTTP/1.1 429 Too Many Requests\r\n\r\n')
      onExceeded?.()
      return
    }
    const [host, p] = (req.url ?? '').split(':')
    const up = connect(Number(p || 443), host, () => {
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n')
      if (head.length) up.write(head)
      up.pipe(client)
      client.pipe(up)
    })
    sockets.add(up)
    up.on('close', () => sockets.delete(up))
    up.on('error', () => client.destroy())
    client.on('error', () => up.destroy())
    client.on('close', () => up.destroy())
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()))
  const addr = server.address()
  const port = typeof addr === 'object' && addr ? addr.port : 0
  return {
    url: `http://127.0.0.1:${port}`,
    count: () => n,
    exceeded: () => over,
    close: () =>
      new Promise<void>((resolve) => {
        for (const s of sockets) s.destroy()
        server.close(() => resolve())
      })
  }
}
