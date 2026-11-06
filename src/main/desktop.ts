/**
 * Claude desktop: connect it to MacSec's MCP server, so a chat or a Claude Code session in the
 * Claude app can read your sessions, start a code review and run the Mac check-up.
 *
 * The entry runs a small script (see seckit/desktopbridge.ts) that passes the conversation to
 * MacSec's local server with its token. Only the "macsec" entry in the app's config is added or
 * changed; everything else in the file is kept.
 */
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs'
import { homedir } from 'os'
import { dirname, join } from 'path'
import { dirs } from './paths'
import { desktopBridge } from './seckit/desktopbridge'

export const desktopConfigPath = (): string => join(homedir(), 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')
export const desktopAppPath = (): string | null => (existsSync('/Applications/Claude.app') ? '/Applications/Claude.app' : existsSync(join(homedir(), 'Applications', 'Claude.app')) ? join(homedir(), 'Applications', 'Claude.app') : null)
export const desktopAppInstalled = (): boolean => !!desktopAppPath()

type Config = { mcpServers?: Record<string, { command: string; args?: string[]; env?: Record<string, string> }> } & Record<string, unknown>

/** The config file, or null when it exists but cannot be read: it is then left alone. */
function read(): Config | null {
  if (!existsSync(desktopConfigPath())) return {}
  try {
    return JSON.parse(readFileSync(desktopConfigPath(), 'utf8')) as Config
  } catch {
    return null
  }
}

export const desktopBridgePath = (): string => join(dirs.bin(), 'macsec-mcp')

export function connectClaudeDesktop(url: string, tokenFile: string): { connected: boolean; path: string } {
  const cfg = read()
  if (!cfg) throw new Error('The Claude app’s settings file could not be read, so it was left as it is. Open the Claude app once, then try again.')
  mkdirSync(dirs.bin(), { recursive: true })
  writeFileSync(desktopBridgePath(), desktopBridge(url, tokenFile, 'MacSec'))
  chmodSync(desktopBridgePath(), 0o755)
  cfg.mcpServers = { ...(cfg.mcpServers ?? {}), macsec: { command: desktopBridgePath(), args: [] } }
  mkdirSync(dirname(desktopConfigPath()), { recursive: true })
  writeFileSync(desktopConfigPath(), JSON.stringify(cfg, null, 2) + '\n')
  chmodSync(desktopConfigPath(), 0o600)
  return { connected: true, path: desktopConfigPath() }
}

export const desktopConnected = (): boolean => !!read()?.mcpServers?.macsec
