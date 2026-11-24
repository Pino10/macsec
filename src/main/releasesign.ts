/**
 * Release signature check, kept apart from Electron so it can be tested on its own.
 * The signature covers SHA256SUMS.txt, and that list covers the DMG.
 */
import { createPublicKey, verify } from 'crypto'
import { RELEASE_PUBKEY } from './releasekey'

export function verifyChecksums(text: string, signature: Buffer, pem: string = RELEASE_PUBKEY): boolean {
  try {
    return verify(null, Buffer.from(text, 'utf8'), createPublicKey(pem), signature)
  } catch {
    return false
  }
}
