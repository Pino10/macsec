/**
 * Free LLM API in MacSec: its address and model are settings, its unified key is a secret in the
 * Keychain (secrets.ts) and is only ever sent to that address.
 */
import type { LocalModel } from './seckit/reviewers'
import { FREELLM_DEFAULT_URL, freeLlmUrl } from './seckit/freellm'
import { getSecret } from './secrets'
import { getSettings } from './settings'

export const FREE_KEY = 'freellm-key'

export const freeConfig = (): { baseUrl: string; model: string } => {
  const f = getSettings().freellm
  return { baseUrl: f?.baseUrl ?? FREELLM_DEFAULT_URL, model: f?.model || 'auto' }
}

/** The server Claude Code uses for a claude-free review. Throws when no key is saved. */
export function freeServer(): LocalModel {
  const key = getSecret(FREE_KEY)
  if (!key) throw new Error('Connect Free LLM API on the Tools page first.')
  const c = freeConfig()
  return { baseUrl: freeLlmUrl(c.baseUrl), model: c.model, token: key }
}
