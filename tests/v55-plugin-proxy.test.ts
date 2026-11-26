/** 1.38: the metering proxy counts and refuses past its cap. */
import { afterEach, describe, expect, it } from 'vitest'
import { createServer, request as httpRequest, type Server } from 'http'
import { startMeteredProxy } from '../src/main/pluginproxy'
import { containerArgs } from '../src/main/plugins'

const close = (s: Server): Promise<void> => new Promise((r) => s.close(() => r()))
let target: Server | null = null
let proxy: Awaited<ReturnType<typeof startMeteredProxy>> | null = null
afterEach(async () => {
  await proxy?.close()
  if (target) await close(target)
  target = null
  proxy = null
})

describe('the container runner', () => {
  it('runs the image on the internal network with the proxy as the only route', () => {
    const args = containerArgs({ id: 'p', name: 'Tool', bin: '', args: ['-u', '{target}'], parser: 'json', containerImage: 'example/tool:1' }, 'c1', 'net1', 'http://host.docker.internal:1234', 'https://app/x', 'app')
    expect(args).toContain('--network')
    expect(args).toContain('net1')
    expect(args).toContain('host.docker.internal:host-gateway')
    expect(args).toContain('HTTP_PROXY=http://host.docker.internal:1234')
    expect(args).toContain('example/tool:1')
    expect(args).not.toContain('app') // the target is only in the placeholder, not a direct arg here
  })
})

describe('the metering proxy', () => {
  it('counts a request and refuses past the cap', async () => {
    target = createServer((_q, r) => {
      r.writeHead(200, { 'content-type': 'text/plain' })
      r.end('ok')
    })
    await new Promise<void>((r) => target!.listen(0, '127.0.0.1', () => r()))
    const t = target.address()
    const port = typeof t === 'object' && t ? t.port : 0
    proxy = await startMeteredProxy(1)
    const p = new URL(proxy.url)
    const get = (): Promise<number> =>
      new Promise((resolve, reject) => {
        const req = httpRequest({ hostname: p.hostname, port: p.port, path: `http://127.0.0.1:${port}/`, method: 'GET' }, (res) => {
          res.resume()
          res.on('end', () => resolve(res.statusCode ?? 0))
        })
        req.on('error', reject)
        req.end()
      })
    expect(await get()).toBe(200)
    expect(await get()).toBe(429)
    expect(proxy.exceeded()).toBe(true)
    expect(proxy.count()).toBe(2)
  })
})

describe('the proxy scope', () => {
  it('refuses a host outside the engagement and a metadata address', async () => {
    const { NetGuard } = await import('../src/main/netguard')
    const { splitHostPort } = await import('../src/main/pluginproxy')
    const guard = new NetGuard(async (h: string) => (h === 'meta.example' ? ['169.254.169.254'] : ['93.184.216.34']))
    proxy = await startMeteredProxy(10, undefined, '127.0.0.1', { hosts: ['shop.example', 'meta.example'], guard })
    const p = new URL(proxy.url)
    const get = (path: string): Promise<number> =>
      new Promise((resolve, reject) => {
        const req = httpRequest({ hostname: p.hostname, port: p.port, path, method: 'GET' }, (res) => {
          res.resume()
          res.on('end', () => resolve(res.statusCode ?? 0))
        })
        req.on('error', reject)
        req.end()
      })
    expect(await get('http://other.example/')).toBe(403)
    expect(await get('http://meta.example/')).toBe(403)
    expect(splitHostPort('[::1]:8443', 443)).toEqual({ host: '::1', port: 8443 })
    expect(splitHostPort('Shop.Example', 443)).toEqual({ host: 'shop.example', port: 443 })
    expect(splitHostPort('a:99999', 443)).toBeNull()
  })
})
