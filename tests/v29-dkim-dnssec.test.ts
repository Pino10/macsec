import { generateKeyPairSync } from 'crypto'
import { describe, expect, it } from 'vitest'
import { dkimChecks, dkimKeyBits, dnsChecks, dnssecCheck, type Doh, type Resolver } from '../src/main/webposture'

const key = (bits: number): string =>
  (generateKeyPairSync('rsa', { modulusLength: bits }).publicKey.export({ type: 'spki', format: 'der' }) as Buffer).toString('base64')

describe('DKIM', () => {
  it('reads the real size of real keys', () => {
    expect(dkimKeyBits(key(512))).toBe(512)
    expect(dkimKeyBits(key(1024))).toBe(1024)
    expect(dkimKeyBits(key(2048))).toBe(2048)
    expect(dkimKeyBits('not a key')).toBeNull()
  })
  it('reports short keys, 1024 keys, withdrawn keys and test mode, and nothing for a good key', () => {
    const t = (selector: string, txt: string) => dkimChecks('shop.example', [{ selector, txt }])
    expect(t('a', `v=DKIM1; k=rsa; p=${key(512)}`)[0].severity).toBe('medium')
    expect(t('b', `v=DKIM1; k=rsa; p=${key(1024)}`)[0].severity).toBe('low')
    expect(t('c', 'v=DKIM1; k=rsa; p=')[0].severity).toBe('info')
    expect(t('d', `v=DKIM1; t=y; p=${key(2048)}`)[0].title).toMatch(/test mode/)
    expect(t('e', `v=DKIM1; k=rsa; p=${key(2048)}`)).toEqual([])
    expect(t('f', 'v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=')).toEqual([])
  })
  it('never says a key is weak without the record as proof', () => {
    const f = dkimChecks('shop.example', [{ selector: 'a', txt: `v=DKIM1; p=${key(512)}` }])[0]
    expect(f.confidence).toBe('confirmed')
    expect(f.proof?.reproduce).toBe('dig +short TXT a._domainkey.shop.example')
  })
  it('is found through the normal mail check', async () => {
    const r: Resolver = {
      resolveTxt: async (h) => (h === 'shop.example' ? [['v=spf1 -all']] : h === '_dmarc.shop.example' ? [['v=DMARC1; p=reject']] : h === 'google._domainkey.shop.example' ? [[`v=DKIM1; p=${key(512)}`]] : []),
      resolveCname: async () => [],
      resolve4: async () => [],
      resolveMx: async () => [{ exchange: 'mx.shop.example', priority: 1 }]
    }
    const out = await dnsChecks('www.shop.example', r)
    expect(out.map((x) => x.title).join('|')).toMatch(/google on shop\.example is only about 512 bits/)
    expect(out.some((x) => /DNSSEC/.test(x.title))).toBe(false) // an injected resolver never reaches the network
  })
})

describe('DNSSEC', () => {
  const doh = (r: Awaited<ReturnType<Doh>>): Doh => async () => r
  it('reports unsigned only after a clean empty answer', async () => {
    expect((await dnssecCheck('a.example', doh({ status: 0, ad: false, answers: 0 })))[0].confidence).toBe('possible')
  })
  it('says nothing for a signed domain, an error, a missing name or no answer', async () => {
    expect(await dnssecCheck('a.example', doh({ status: 0, ad: true, answers: 1 }))).toEqual([])
    expect(await dnssecCheck('a.example', doh({ status: 2, ad: false, answers: 0 }))).toEqual([])
    expect(await dnssecCheck('a.example', doh({ status: 3, ad: false, answers: 0 }))).toEqual([])
    expect(await dnssecCheck('a.example', doh(null))).toEqual([])
  })
})
