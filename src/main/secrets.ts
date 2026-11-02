/**
 * Tokens (GitHub, Azure DevOps) are encrypted with the macOS Keychain (Electron safeStorage)
 * and stored in ~/MacSec/config. They never go to the window.
 */
import { existsSync, readFileSync, writeFileSync } from 'fs'
import { join } from 'path'
import { dirs } from './paths'

export interface Crypto {
  available: () => boolean
  encrypt: (s: string) => string
  decrypt: (s: string) => string
}

let crypto: Crypto | null = null
export function setSecretsCrypto(c: Crypto | null): void {
  crypto = c
}

const file = (): string => join(dirs.config(), 'secrets.json')
function load(): Record<string, string> {
  try {
    return existsSync(file()) ? (JSON.parse(readFileSync(file(), 'utf8')) as Record<string, string>) : {}
  } catch {
    return {}
  }
}

export function getSecret(key: string): string | null {
  const v = load()[key]
  if (!v) return null
  if (!crypto?.available()) return null
  try {
    return crypto.decrypt(v)
  } catch {
    return null
  }
}

export function setSecret(key: string, value: string | null): void {
  const all = load()
  if (value === null || value === '') delete all[key]
  else {
    if (!crypto?.available()) throw new Error('The Keychain is not available, so the token cannot be stored safely.')
    all[key] = crypto.encrypt(value)
  }
  writeFileSync(file(), JSON.stringify(all, null, 2), { mode: 0o600 })
}

/** Plain values that are not secret (the Azure organization name, the GitHub login). */
export function getPlain(key: string): string | null {
  return load()[`plain:${key}`] ?? null
}
export function setPlain(key: string, value: string | null): void {
  const all = load()
  if (value === null) delete all[`plain:${key}`]
  else all[`plain:${key}`] = value
  writeFileSync(file(), JSON.stringify(all, null, 2), { mode: 0o600 })
}
