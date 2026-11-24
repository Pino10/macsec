/** 1.36: the plugin parsers and the bounty submission draft. */
import { describe, expect, it } from 'vitest'
import type { PluginDef, SessionDetail } from '../src/shared/types'
import { parsePluginOutput } from '../src/main/plugins'
import { bountyReport } from '../src/main/exports'

const plugin = (parser: PluginDef['parser'], pattern?: string): PluginDef => ({ id: 'p1', name: 'Tool', bin: '/bin/echo', args: [], parser, pattern, severity: 'medium' })

describe('plugin output', () => {
  it('reads a JSON array, keeps the title and defaults a bad severity', () => {
    const out = parsePluginOutput('[{"title":"Exposed panel","location":"/admin","evidence":"200"},{"title":"","location":"/x"}]', plugin('json'), 'https://app')
    expect(out).toHaveLength(1)
    expect(out[0]).toMatchObject({ title: 'Exposed panel', severity: 'medium', location: '/admin' })
  })
  it('reads one finding per line, capped', () => {
    const out = parsePluginOutput('a\n\nb\n', plugin('lines'), 'https://app')
    expect(out.map((x) => x.title)).toEqual(['a', 'b'])
  })
  it('reads a regex capture and ignores lines without a match', () => {
    const out = parsePluginOutput('INFO ok\nWARN missing header\nINFO ok', plugin('regex', 'WARN (.+)'), 'https://app')
    expect(out).toHaveLength(1)
    expect(out[0].title).toBe('missing header')
  })
  it('returns nothing for malformed JSON instead of inventing a finding', () => {
    expect(parsePluginOutput('not json', plugin('json'), 'https://app')).toEqual([])
  })
})

describe('the bounty draft', () => {
  it('includes open findings, excludes info and false positives, and keeps the evidence', () => {
    const d = {
      id: 's1', title: 'App', target: 'https://app.example',
      findings: [
        { id: 'a', tool: 'x', title: 'IDOR on invoice', severity: 'high', category: 'web', confidence: 'confirmed', description: 'Other invoice read', proof: 'GET /invoice/2 -> 200', url: 'https://app.example/invoice/2' },
        { id: 'b', tool: 'x', title: 'Info note', severity: 'info', category: 'web' },
        { id: 'c', tool: 'x', title: 'False', severity: 'high', category: 'web', verdict: 'false-positive' }
      ]
    } as unknown as SessionDetail
    const md = bountyReport(d, { client: 'Program', authorityRef: 'H1-1' })
    expect(md).toContain('IDOR on invoice')
    expect(md).toContain('GET /invoice/2 -> 200')
    expect(md).not.toContain('Info note')
    expect(md).not.toContain('False')
    expect(md).toContain('Program')
  })
  it('says so when there is nothing open', () => {
    const d = { id: 's', title: 'App', target: 'x', findings: [] } as unknown as SessionDetail
    expect(bountyReport(d, null)).toContain('No open finding to submit')
  })
})
