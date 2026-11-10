/**
 * Special audits beyond code and websites. Both only read:
 *
 *   Cloud account   ScoutSuite's best-practice audit of an Azure or AWS account, CloudFox's map
 *                   of what the account exposes, and (AWS) PMapper's privilege escalation paths
 *   Server          the open ports on a server you own (naabu, plain connections), the service
 *                   on each one (Nmap, when installed, without its scripts), and which of them
 *                   should not be reachable
 *
 * The Azure sign-in lives in MacSec's own tools folder. AWS uses your existing profile, read only.
 */
import { execFile } from 'child_process'
import { existsSync, readdirSync, readFileSync } from 'fs'
import { homedir } from 'os'
import { join } from 'path'
import type { AuditRequest, Finding, SessionInfo } from '../shared/types'
import { beginOp, endOp, runTool, SessionRun } from './engine'
import { createSession, saveAiReport } from './sessions'
import { parseNaabu, parseNmapXml, parsePmapper, parseScoutSuite, portFindings, type OpenPort } from './scanners/infra'
import { appPath, installTool, isInstalled, toolDef, toolEnv, toolPath } from './toolbox'
import { summarizeWithAi, summaryPrompt } from './aisummary'
import { log } from './logs'
import { isPrivateTarget } from './targets'
import { writeFileSync } from 'fs'

type Cloud = Extract<AuditRequest, { kind: 'cloud' }>
type Server = Extract<AuditRequest, { kind: 'server' }>

/** AWS reads your own profile files (never writes them); everything else stays in MacSec. */
export function cloudEnv(): Record<string, string> {
  const aws = join(homedir(), '.aws')
  const pass = Object.fromEntries(['AWS_PROFILE', 'AWS_REGION', 'AWS_DEFAULT_REGION'].filter((k) => process.env[k]).map((k) => [k, process.env[k] as string]))
  return {
    ...pass,
    ...(existsSync(aws) ? { AWS_SHARED_CREDENTIALS_FILE: join(aws, 'credentials'), AWS_CONFIG_FILE: join(aws, 'config') } : {}),
    AZURE_CORE_COLLECT_TELEMETRY: 'false',
    AZURE_CORE_ONLY_SHOW_ERRORS: 'true'
  }
}

function cli(bin: string, args: string[], timeout = 60_000): Promise<string> {
  return new Promise((resolve, reject) =>
    execFile(toolPath(bin), args, { env: toolEnv(cloudEnv()), timeout, maxBuffer: 20 * 1024 * 1024 }, (e, out, err) => (e ? reject(new Error((err || e.message).trim().split('\n').pop() ?? 'Failed')) : resolve(out)))
  )
}

/** Who MacSec is signed in as, in each cloud. */
export async function cloudStatus(): Promise<{ azure: string | null; aws: string | null }> {
  const azure = existsSync(toolPath('az'))
    ? await cli('az', ['account', 'show', '-o', 'json'])
        .then((o) => {
          const a = JSON.parse(o) as { user?: { name?: string }; name?: string }
          return `${a.user?.name ?? 'Signed in'} (${a.name ?? 'subscription'})`
        })
        .catch(() => null)
    : null
  const aws = existsSync(toolPath('aws'))
    ? await cli('aws', ['sts', 'get-caller-identity', '--output', 'json'])
        .then((o) => (JSON.parse(o) as { Arn?: string }).Arn ?? 'Signed in')
        .catch(() => null)
    : null
  return { azure, aws }
}

/** Opens Microsoft's sign-in page in the browser; the sign-in is kept inside MacSec. */
export async function azureLogin(): Promise<void> {
  if (!existsSync(toolPath('az'))) await installTool('azure-cli', () => undefined)
  await cli('az', ['login', '--only-show-errors', '-o', 'none'], 5 * 60_000)
}

/** Installs a tool into MacSec the first time it is needed, saying so in the step. */
async function ensure(id: string, note?: (d: string) => void): Promise<void> {
  const d = toolDef(id)
  if (!d || isInstalled(d)) return
  note?.(`Installing ${d.name} into MacSec first`)
  await installTool(id, (p) => note?.(`Installing ${d.name} into MacSec first${p !== null ? `, ${Math.round(p)}%` : ''}`))
}

export function startInfraAudit(req: Cloud | Server): SessionInfo {
  if (req.kind === 'cloud') {
    const info = createSession('audit', `${req.provider === 'azure' ? 'Azure' : 'AWS'} account audit`, req.provider === 'azure' ? 'Azure' : 'AWS')
    info.reviewer = req.reviewer
    void cloud(info.id, req).catch((e) => log('error', `Cloud audit: ${(e as Error).message}`, info.id))
    return info
  }
  const info = createSession('audit', `Server check of ${req.host}`, req.host)
  info.reviewer = req.reviewer
  void server(info.id, req).catch((e) => log('error', `Server check: ${(e as Error).message}`, info.id))
  return info
}

async function cloud(id: string, req: Cloud): Promise<void> {
  const op = beginOp(id)
  const s = new SessionRun(id, op)
  const azure = req.provider === 'azure'
  const st = {
    who: s.step('who', azure ? 'Check the Azure sign-in' : 'Check the AWS profile'),
    scout: s.step('scout', 'ScoutSuite: every setting against best practice'),
    fox: s.step('cloudfox', 'CloudFox: what the account exposes'),
    pm: azure ? null : s.step('pmapper', 'PMapper: users and roles that could raise their own access'),
    ai: req.reviewer !== 'none' ? s.step('ai', 'AI: what matters most and how to fix it') : null
  }
  const env = cloudEnv()
  let tenant = ''
  try {
    await s.run(st.who, async (note) => {
      await ensure(azure ? 'azure-cli' : 'awscli')
      if (azure) {
        const a = JSON.parse(await cli('az', ['account', 'show', '-o', 'json']).catch(() => {
          throw new Error('Sign in to Azure first, on Special audits.')
        })) as { user?: { name?: string }; tenantId?: string; name?: string }
        tenant = a.tenantId ?? ''
        note(`${a.user?.name ?? ''}, ${a.name ?? ''}`)
      } else {
        const a = JSON.parse(await cli('aws', ['sts', 'get-caller-identity', '--output', 'json']).catch(() => {
          throw new Error('No working AWS profile was found. Run "aws configure" or "aws sso login" in Terminal first.')
        })) as { Arn?: string }
        note(a.Arn ?? '')
      }
    })
    if (st.who.status === 'failed') throw new Error(st.who.detail)

    await s.run(st.scout, async (note, line) => {
      await ensure('scoutsuite', note)
      const dir = join(s.raw, 'scoutsuite')
      const args = azure ? ['azure', '--cli', '--all-subscriptions', '--report-dir', dir, '--no-browser'] : ['aws', '--report-dir', dir, '--no-browser', ...(env.AWS_PROFILE ? ['--profile', env.AWS_PROFILE] : [])]
      await runTool({ name: 'scoutsuite', bin: 'scout', args, timeoutMs: 90 * 60_000, env }, op, s.raw, line).catch((e) => {
        if (!existsSync(join(dir, 'scoutsuite-results'))) throw e
        return ''
      })
      const res = join(dir, 'scoutsuite-results')
      const file = existsSync(res) ? readdirSync(res).find((f) => /^scoutsuite_results_.*\.js$/.test(f)) : undefined
      if (!file) throw new Error('ScoutSuite finished without results.')
      return parseScoutSuite(readFileSync(join(res, file), 'utf8'))
    })

    await s.run(st.fox, async (note, line) => {
      await ensure('cloudfox', note)
      const dir = join(s.raw, 'cloudfox')
      const args = azure ? ['azure', 'inventory', ...(tenant ? ['--tenant', tenant] : []), '--outdir', dir] : ['aws', 'inventory', ...(env.AWS_PROFILE ? ['--profile', env.AWS_PROFILE] : []), '--outdir', dir]
      await runTool({ name: 'cloudfox', bin: 'cloudfox', args, timeoutMs: 30 * 60_000, env }, op, s.raw, line)
      note('Inventory saved with the session (What ran, open folder)')
    })

    if (st.pm)
      await s.run(st.pm, async (note, line) => {
        await ensure('pmapper', note)
        await runTool({ name: 'pmapper-graph', bin: 'pmapper', args: ['graph', 'create'], timeoutMs: 60 * 60_000, env }, op, s.raw, line)
        const out = await runTool({ name: 'pmapper', bin: 'pmapper', args: ['analysis', '--output-type', 'json'], timeoutMs: 20 * 60_000, env }, op, s.raw, line)
        return parsePmapper(out)
      })

    await aiStep(s, st.ai, req.reviewer, 'cloud', azure ? 'Azure' : 'AWS', `A read-only audit of a whole ${azure ? 'Azure' : 'AWS'} account. Give the exact ${azure ? 'az' : 'aws'} command or portal steps for each fix.`)
    s.finish()
  } catch (e) {
    s.finish((e as Error).message)
  } finally {
    endOp(id)
  }
}

export function isLocalHost(host: string): boolean {
  return /^(localhost|127\.\d+\.\d+\.\d+|::1)$/.test(host) || /\.(test|localhost)$/.test(host)
}

async function server(id: string, req: Server): Promise<void> {
  const op = beginOp(id)
  const s = new SessionRun(id, op)
  const nmap = appPath('nmap')
  const hosts = req.hosts?.length ? req.hosts : [req.host]
  const many = hosts.length > 1
  const st = {
    ports: s.step('naabu', `Find open ports${many ? ` on ${hosts.length} servers` : ''} (the ${req.ports === 'top100' ? '100' : '1,000'} most common)`),
    nmap: s.step('nmap', nmap ? 'Name the service on each open port (Nmap)' : 'Name the services (install Nmap to add this)'),
    ai: req.reviewer !== 'none' ? s.step('ai', 'AI: what should not be reachable and how to close it') : null
  }
  let open: OpenPort[] = []
  try {
    await s.run(st.ports, async (note, line) => {
      await ensure('naabu', note)
      const out = join(s.raw, 'naabu.jsonl')
      // Several servers go in a file, one per line, so nothing typed is ever read as an option.
      const list = join(s.raw, 'targets.txt')
      writeFileSync(list, `${hosts.join('\n')}\n`)
      await runTool({ name: 'naabu', bin: 'naabu', args: [...(many ? ['-list', list] : ['-host', req.host]), '-top-ports', req.ports === 'top100' ? '100' : '1000', '-scan-type', 'c', '-json', '-silent', '-duc', '-rate', '300', '-o', out, '-stats', '-si', '5'], timeoutMs: 30 * 60_000, output: out }, op, s.raw, line).catch((e) => {
        if (!existsSync(out)) throw e
        return ''
      })
      open = existsSync(out) ? parseNaabu(readFileSync(out, 'utf8')) : []
      note(open.length ? `Open: ${open.map((p) => p.port).join(', ')}` : 'No open ports found')
    })

    await s.run(st.nmap, async (note, line) => {
      if (!nmap) return note('Skipped: Nmap is not installed (brew install nmap)')
      if (!open.length) return note('Nothing to look at')
      // Version detection only: no NSE scripts (-sC / --script), no OS fingerprinting, plain TCP connections.
      // One run per server, with only the ports that server answered on.
      const byHost = [...new Set(open.map((p) => p.host))]
      let all: OpenPort[] = []
      for (const [i, h] of byHost.entries()) {
        const mine = open.filter((p) => p.host === h)
        const out = join(s.raw, `nmap-${i}.xml`)
        note(`Nmap: ${h} (${i + 1} of ${byHost.length})`)
        await runTool({ name: 'nmap', bin: nmap, absolute: true, args: ['-sT', '-sV', '--version-light', '-Pn', '-n', '-p', mine.map((p) => p.port).join(','), '-oX', out, h], timeoutMs: 30 * 60_000, output: out }, op, s.raw, line)
        const named = parseNmapXml(readFileSync(out, 'utf8'))
        all = all.concat(mine.map((p) => ({ ...p, ...named.find((n) => n.port === p.port), host: p.host })))
      }
      open = all
    })
    s.add([...new Set(open.map((p) => p.host))].flatMap((h) => portFindings(open.filter((p) => p.host === h), !many && isLocalHost(req.host))))

    await aiStep(s, st.ai, req.reviewer, 'server', req.host, `Open ports and services on ${many ? `${hosts.length} servers (${hosts.slice(0, 12).join(', ')}${hosts.length > 12 ? ', and more' : ''}), ${hosts.every(isPrivateTarget) ? 'all on a private network' : 'some reachable from the internet'}` : req.host}${!many && isLocalHost(req.host) ? ' (this Mac or a local development host)' : ''}. Say which hosts should not expose each service. Give firewall commands for the likely platform.`)
    s.finish()
  } catch (e) {
    s.finish((e as Error).message)
  } finally {
    endOp(id)
  }
}

async function aiStep(s: SessionRun, step: ReturnType<SessionRun['step']> | null, reviewer: Cloud['reviewer'], kind: 'cloud' | 'server', target: string, context: string): Promise<void> {
  if (!step) return
  await s.run(step, async () => {
    const r = await summarizeWithAi(reviewer, summaryPrompt(kind, target, context, s.findings.filter((f: Finding) => f.severity !== 'info' || kind === 'server')), s.op, s.raw)
    for (const f of s.findings) {
      const d = r.details.get(f.id)
      if (d) {
        f.verdict = d.verdict
        f.aiNote = d.reason
      }
    }
    saveAiReport(s.info.id, r.report)
    return []
  })
}
