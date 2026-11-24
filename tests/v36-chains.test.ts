/** Attack paths: only from real parts, with one fix that breaks the path. */
import { describe, expect, it } from 'vitest'
import { chainsOf } from '../src/main/chains'
import type { Finding } from '../src/shared/types'

const f = (id: string, title: string, severity: Finding['severity'] = 'high', fix?: string): Finding => ({ id, tool: 'MacSec', category: 'web', severity, title, ...(fix ? { fix } : {}) })

describe('attack paths', () => {
  it('builds the file-to-key path and names the file as the place to break it', () => {
    const chains = chainsOf([f('a', 'Public file: /.git/config', 'high', 'Remove it.'), f('b', 'GitHub token in public JavaScript', 'critical')])
    const c = chains.find((x) => x.id === 'files-to-keys')
    expect(c).toBeTruthy()
    expect(c?.severity).toBe('critical')
    expect(c?.breakAt?.id).toBe('a')
    expect(c?.breakAt?.fix).toMatch(/Remove the file|rotate/)
    expect(c?.impact).toMatch(/attacker/)
    const other = chains.find((x) => x.id === 'secret-to-cloud')
    expect(other).toBeUndefined()
  })

  it('breaks an XSS path at the output escaping, not at the cookie', () => {
    const c = chainsOf([f('x', 'Input comes back in the page without escaping: /search'), f('y', 'Cookie "session" is missing the HttpOnly flag', 'medium')]).find((x) => x.id === 'xss-to-session')
    expect(c?.breakAt?.id).toBe('x')
    expect(c?.breakAt?.fix).toMatch(/Escape output/i)
  })

  it('shows an upload path only when uploads are served as pages', () => {
    const yes = chainsOf([f('u', 'Upload accepted: avatar field'), f('v', 'The uploaded file is readable as HTML', 'high')]).find((x) => x.id === 'upload-to-active-content')
    expect(yes).toBeTruthy()
    expect(yes?.breakAt?.fix).toMatch(/separate domain|Content-Disposition/)
    expect(chainsOf([f('u', 'Upload accepted: avatar field')])).toHaveLength(0)
  })

  it('never builds a path from one finding twice, and never from a ruled-out one', () => {
    const chains = chainsOf([{ ...f('a', 'Public file: /.env with a key'), verdict: 'false-positive' }])
    expect(chains).toHaveLength(0)
    const single = chainsOf([f('a', 'Source map public: 12 original files')])
    expect(single).toHaveLength(0)
  })

  it('puts the worst path first', () => {
    const list = [
      f('a', 'Input comes back in the page without escaping: /q', 'medium'),
      f('b', 'Cookie "sid" is missing the HttpOnly flag', 'low'),
      f('c', 'Public file: /.env', 'high'),
      f('d', 'API key found in public JavaScript', 'critical')
    ]
    const chains = chainsOf(list)
    expect(chains[0].severity).toBe('critical')
    const order = ['info', 'low', 'medium', 'high', 'critical']
    for (let i = 1; i < chains.length; i++) expect(order.indexOf(chains[i - 1].severity)).toBeGreaterThanOrEqual(order.indexOf(chains[i].severity))
  })
})
