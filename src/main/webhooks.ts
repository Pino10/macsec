/**
 * Messages to Slack, Microsoft Teams, Discord or any address that takes JSON, when something
 * fails or finishes. The address is a secret (anyone with it can post), so it is kept in the
 * Keychain and only sent to the service it belongs to.
 */
export type HookKind = 'slack' | 'teams' | 'discord' | 'generic'

export function checkHookUrl(kind: HookKind, url: string): string {
  let u: URL
  try {
    u = new URL(url.trim())
  } catch {
    throw new Error('Paste the full webhook address.')
  }
  if (u.protocol !== 'https:') throw new Error('Webhook addresses must start with https://.')
  const h = u.hostname
  const ok =
    kind === 'slack'
      ? h === 'hooks.slack.com'
      : kind === 'discord'
        ? (h === 'discord.com' || h === 'discordapp.com' || h.endsWith('.discord.com')) && u.pathname.startsWith('/api/webhooks/')
        : kind === 'teams'
          ? h.endsWith('.webhook.office.com') || h.endsWith('.logic.azure.com') || h.endsWith('.environment.api.powerplatform.com')
          : !/^(localhost|127\.|10\.|192\.168\.|169\.254\.)/.test(h)
  if (!ok) throw new Error(kind === 'slack' ? 'That is not a Slack incoming webhook (hooks.slack.com).' : kind === 'discord' ? 'That is not a Discord webhook (discord.com/api/webhooks/…).' : kind === 'teams' ? 'That is not a Teams webhook (a Workflows or Office 365 connector address).' : 'Use an https address on the internet.')
  return u.toString()
}

/** The JSON each service expects. */
export function hookBody(kind: HookKind, app: string, kindOfEvent: 'error' | 'success' | 'info', title: string, body?: string): object {
  const icon = kindOfEvent === 'error' ? '🔴' : kindOfEvent === 'success' ? '🟢' : '🔵'
  const text = `${icon} *${app}*: ${title}${body ? `\n${body}` : ''}`
  if (kind === 'slack') return { text }
  if (kind === 'discord') return { content: text.replace(/\*/g, '**').slice(0, 1900), username: app }
  if (kind === 'teams')
    return {
      type: 'message',
      attachments: [{ contentType: 'application/vnd.microsoft.card.adaptive', content: { type: 'AdaptiveCard', version: '1.4', body: [{ type: 'TextBlock', weight: 'Bolder', text: `${app}: ${title}`, wrap: true }, ...(body ? [{ type: 'TextBlock', text: body, wrap: true }] : [])] } }]
    }
  return { app, kind: kindOfEvent, title, body: body ?? null, at: new Date().toISOString() }
}

export async function sendHook(kind: HookKind, url: string, payload: object): Promise<void> {
  const res = await fetch(checkHookUrl(kind, url), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), signal: AbortSignal.timeout(15000) })
  if (!res.ok) throw new Error(`The webhook answered ${res.status}.`)
}

/** Raycast script commands that drive an app through its command-line tool. */
export function raycastScripts(cli: string, app: 'Laramac' | 'MacSec'): { file: string; text: string }[] {
  const head = (title: string, mode: 'fullOutput' | 'compact' | 'silent', arg?: string): string =>
    `#!/bin/bash\n\n# Required parameters:\n# @raycast.schemaVersion 1\n# @raycast.title ${title}\n# @raycast.mode ${mode}\n# @raycast.packageName ${app}\n${arg ? `# @raycast.argument1 { "type": "text", "placeholder": "${arg}" }\n` : ''}\n# Written by ${app}.\n`
  if (app === 'Laramac')
    return [
      { file: 'laramac-status.sh', text: `${head('Laramac status', 'fullOutput')}"${cli}" status\n` },
      { file: 'laramac-sites.sh', text: `${head('Laramac sites', 'fullOutput')}"${cli}" sites\n` },
      { file: 'laramac-open.sh', text: `${head('Open a Laramac site', 'silent', 'site')}"${cli}" open "$1"\n` },
      { file: 'laramac-start.sh', text: `${head('Start a Laramac service', 'compact', 'service')}"${cli}" start "$1"\n` },
      { file: 'laramac-stop.sh', text: `${head('Stop a Laramac service', 'compact', 'service')}"${cli}" stop "$1"\n` },
      { file: 'laramac-dev.sh', text: `${head('Start a dev server', 'compact', 'site')}"${cli}" dev "$1"\n` }
    ]
  return [
    { file: 'macsec-sessions.sh', text: `${head('MacSec sessions', 'fullOutput')}"${cli}" sessions\n` },
    { file: 'macsec-checkup.sh', text: `${head('Mac security check-up', 'fullOutput')}"${cli}" checkup\n` },
    { file: 'macsec-review.sh', text: `${head('MacSec review a folder', 'compact', 'folder')}"${cli}" review "$1"\n` }
  ]
}
