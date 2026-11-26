/**
 * A local metering proxy for plugin tools that honour HTTP(S)_PROXY. It counts requests and refuses
 * past the budget. It is not a sandbox: a tool that ignores the proxy is not counted, and a tool
 * that opens raw sockets is not seen at all. The UI says so.
 */
import { createServer, request as httpRequest, type Server } from 'http'
import { connect, isIP, type Socket } from 'net'
import type { NetGuard } from './netguard'

export interface MeteredProxy {
  url: string
  count: () => number
  exceeded: () => boolean
  close: () => Promise<void>
}

/** Which hosts the proxy may reach. With a scope, anything else is refused and every host goes through the network guard. */
export interface ProxyScope {
  hosts: string[]
  guard: NetGuard
}

/** Splits "host:port" or "[v6]:port" without being fooled by the colons in an IPv6 address. */
export function splitHostPort(value: string, fallback: number): { host: string; port: number } | null {
  const m = /^\[([^\]]+)\](?::(\d{1,5}))?$/.exec(value) ?? /^([^:\[\]]+)(?::(\d{1,5}))?$/.exec(value)
  if (!m) return null
  const port = m[2] ? Number(m[2]) : fallback
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null
  return { host: m[1].toLowerCase(), port }
}

export async function startMeteredProxy(cap: number, onExceeded?: () => void, bind = '127.0.0.1', scope?: ProxyScope): Promise<MeteredProxy> {
  const covered = (host: string): boolean => !scope || scope.hosts.some((h) => h.toLowerCase() === host)
  /** The address to connect to: the one the guard approved, never a fresh lookup. Throws when the host is out of scope or refused. */
  const route = async (host: string): Promise<string> => {
    if (!covered(host)) throw new Error('outside the engagement')
    if (!scope) return host
    await scope.guard.check(host)
    return isIP(host) ? host : (scope.guard.addressFor(host) ?? host)
  }
  let n = 0
  let over = false
  const sockets = new Set<Socket>()
  const server: Server = createServer(async (req, res) => {
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
    const hostName = target.hostname.replace(/^\[|\]$/g, '').toLowerCase()
    let address: string
    try {
      address = await route(hostName)
    } catch (e) {
      res.writeHead(403, { 'content-type': 'text/plain' }).end(`MacSec refused: ${(e as Error).message}`)
      return
    }
    const up = httpRequest(
      { hostname: address, port: target.port || 80, path: target.pathname + target.search, method: req.method, headers: { ...req.headers, host: target.host, connection: 'close' } },
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
  server.on('connect', async (req, client, head) => {
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
    const hp = splitHostPort(req.url ?? '', 443)
    let address = ''
    try {
      if (!hp) throw new Error('bad address')
      address = await route(hp.host)
    } catch (e) {
      client.end(`HTTP/1.1 403 Forbidden\r\n\r\nMacSec refused: ${(e as Error).message}`)
      return
    }
    const up = connect(hp!.port, address, () => {
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
  await new Promise<void>((resolve) => server.listen(0, bind, () => resolve()))
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
