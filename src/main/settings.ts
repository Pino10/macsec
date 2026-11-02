import { existsSync, readFileSync, writeFileSync } from 'fs'
import { homedir } from 'os'
import { join } from 'path'
import type { AppSettings } from '../shared/types'
import { dirs } from './paths'

/** Laramac's www folder, read from Laramac's own settings when it is installed. */
export function laramacWww(): string {
  try {
    const s = JSON.parse(readFileSync(join(homedir(), '.laramac', 'settings.json'), 'utf8')) as { wwwPath?: string }
    if (s.wwwPath) return s.wwwPath
  } catch {
    // Laramac is not installed, or has not saved settings yet.
  }
  return join(homedir(), 'Laramac', 'www')
}

const defaults = (): AppSettings => ({
  wwwPath: laramacWww(),
  llm: { baseUrl: 'http://127.0.0.1:1234/v1', model: '' },
  reviewer: 'claude',
  notifications: true,
  claudeAuth: 'account'
})

const file = (): string => join(dirs.config(), 'settings.json')

export function getSettings(): AppSettings {
  const base = defaults()
  if (!existsSync(file())) return base
  try {
    const loaded = JSON.parse(readFileSync(file(), 'utf8')) as Partial<AppSettings>
    return { ...base, ...loaded, llm: { ...base.llm, ...(loaded.llm ?? {}) } }
  } catch {
    return base
  }
}

export function setSettings(patch: Partial<AppSettings>): AppSettings {
  const current = getSettings()
  const next: AppSettings = { ...current, ...patch, llm: { ...current.llm, ...(patch.llm ?? {}) } }
  writeFileSync(file(), JSON.stringify(next, null, 2), { mode: 0o600 })
  return next
}
