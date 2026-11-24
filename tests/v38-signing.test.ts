/** A release is only installed when its checksum list was signed by MacSec's key. */
import { describe, expect, it } from 'vitest'
import { generateKeyPairSync, sign } from 'crypto'
import { verifyChecksums } from '../src/main/releasesign'

const keypair = (): { priv: string; pub: string } => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  return { priv: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), pub: publicKey.export({ type: 'spki', format: 'pem' }).toString() }
}

describe('the release signature', () => {
  it('accepts a list signed with the matching key, and refuses anything else', () => {
    const { priv, pub } = keypair()
    const text = 'a'.repeat(64) + '  MacSec-1.19.0-arm64.dmg\n'
    const sig = sign(null, Buffer.from(text, 'utf8'), priv)
    expect(verifyChecksums(text, sig, pub)).toBe(true)
    expect(verifyChecksums(text + 'tampered', sig, pub)).toBe(false)
    const other = keypair()
    expect(verifyChecksums(text, sig, other.pub)).toBe(false)
    expect(verifyChecksums(text, Buffer.from('not a signature'), pub)).toBe(false)
  })
})
