/**
 * Saved options, so a scan or a review does not have to be set up again from memory. A profile holds
 * choices only: never a target, never a cookie, never a token. They live under ~/MacSec/config.
 */
import { randomBytes } from 'crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs'
import { join } from 'path'
import type { SavedProfile } from '../shared/types'
import { dirs } from './paths'

const file = (): string => join(dirs.config(), 'profiles.json')
const MAX = 50

const load = (): SavedProfile[] => {
  try {
    const list = JSON.parse(readFileSync(file(), 'utf8')) as SavedProfile[]
    return Array.isArray(list) ? list.filter((p) => p && typeof p.id === 'string' && typeof p.name === 'string') : []
  } catch {
    return []
  }
}

const write = (list: SavedProfile[]): void => {
  mkdirSync(dirs.config(), { recursive: true, mode: 0o700 })
  writeFileSync(file(), JSON.stringify(list.slice(0, MAX), null, 2), { mode: 0o600 })
}

const SECRET_KEY = /cookie|token|authorization|password|secret|headers/i

export function listProfiles(): SavedProfile[] {
  return load().sort((a, b) => a.name.localeCompare(b.name))
}

export function saveProfile(input: unknown): SavedProfile[] {
  const p = (input ?? {}) as { name?: unknown; kind?: unknown; options?: unknown }
  const name = typeof p.name === 'string' ? p.name.trim().replace(/\s+/g, ' ').slice(0, 60) : ''
  if (!name) throw new Error('Give the profile a name.')
  if (p.kind !== 'web' && p.kind !== 'review') throw new Error('A profile is for a web scan or a code review.')
  if (!p.options || typeof p.options !== 'object' || Array.isArray(p.options)) throw new Error('That profile has no options.')
  const options = p.options as Record<string, unknown>
  // A profile is a set of choices: no session, no credential, ever.
  for (const k of Object.keys(options)) if (SECRET_KEY.test(k)) throw new Error(`A profile cannot hold "${k}". Sign in at the time of the scan instead.`)
  if (Buffer.byteLength(JSON.stringify(options)) > 20_000) throw new Error('That profile is too big.')
  const list = load().filter((x) => !(x.kind === p.kind && x.name.toLowerCase() === name.toLowerCase()))
  const profile: SavedProfile = { id: `pf-${randomBytes(4).toString('hex')}`, name, kind: p.kind, options, createdAt: new Date().toISOString() }
  if (list.length >= MAX) throw new Error(`MacSec keeps ${MAX} profiles. Remove one first.`)
  write([profile, ...list])
  return listProfiles()
}

export function deleteProfile(id: string): SavedProfile[] {
  const list = load().filter((p) => p.id !== id)
  write(list)
  return listProfiles()
}
