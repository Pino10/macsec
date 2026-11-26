import { useEffect, useState } from 'react'
import { ArrowLeft, Copy, ShieldCheck } from 'lucide-react'
import { useApp } from '../store'
import { PageHead } from '../ui'

interface Block {
  title: string
  lines: string[]
}

/** Plain-English promises, kept in step with the rules in CLAUDE.md. Written for security teams who need to know what a tool will do on their systems. */
const BLOCKS: Block[] = [
  {
    title: 'Who should use it',
    lines: [
      'Use MacSec only on systems you own or have written permission to test: your own apps, an internal penetration test, or a bug bounty programme inside its published scope.',
      'For bug bounty work, read the programme rules first (allowed targets, rate limits, what is out of scope). MacSec asks you to confirm before it tests anything that is not on this Mac.',
      'MacSec is a helper for developers and testers. It does not replace a professional penetration test or an audit.'
    ]
  },
  {
    title: 'What ordinary scans do',
    lines: [
      'Code, web, API, mobile and Mac checks only read. They send ordinary requests, never exploits, never anything that changes data, and never guess passwords.',
      'Nuclei runs with its “changes things” templates excluded, Nmap runs without scripts, and WPScan never guesses passwords or lists users.',
      'Tools never receive your session credentials. A signed-in walk goes only through MacSec’s own capped, same-host client.'
    ]
  },
  {
    title: 'Control confirmations (optional)',
    lines: [
      'Switched on per scan. They prove a problem is real so reports have no false alarms.',
      'They stay on the same host, send harmless markers only, use a request cap and a pause between requests, stop if the server struggles, and repeat every finding a second time before reporting it.',
      'They never change data. The only form they send is a login with a made-up user.'
    ]
  },
  {
    title: 'Controlled proofs (only inside an engagement)',
    lines: [
      'This is the only part of MacSec that can change data or read real data. It cannot run without an engagement: a written scope with the host, a time window, the allowed goals and request caps.',
      'You type the confirmation yourself (“EXPLOIT” and the host). A step that writes needs a stated way to undo it.',
      'Every step has a fixed bound: what it sends, what it never does, its request cap and its cleanup. Nothing outside that list can run.',
      'It stops at the first proof. It does not flood, does not dump customer data, does not hide from a firewall, and does not guess passwords. A write is one plain text file that is removed again, or, if that fails, listed with its exact address so you can remove it.',
      'There is a kill switch, and every run is recorded. The record holds the method, the masked address, the status and a hash, never a cookie or a secret.',
      'Attack tools such as sqlmap run only inside an engagement, only with the small fixed settings MacSec allows, and never by themselves.'
    ]
  },
  {
    title: 'Phones and traffic',
    lines: [
      'The live phone test runs an Android app on a test phone you pick and only watches it. It does not bypass the app’s protections, and it removes the app again if MacSec installed it.',
      'Traffic capture listens on this Mac only. You set up the phone yourself, and MacSec never touches it.'
    ]
  },
  {
    title: 'How it protects the target and you',
    lines: [
      'A network guard refuses cloud metadata addresses and stops a test if a site name mixes public and private addresses or switches between them (DNS rebinding). Requests then connect to the address the guard approved, not to a fresh lookup.',
      'Passwords, tokens and keys that it finds are never written into reports. Only the kind, the place and the name are kept.',
      'Your tokens live in the macOS Keychain, are sent only to their own service, and are removed from logs.',
      'Everything MacSec writes goes under ~/MacSec. Downloaded tools are checked against the publisher’s checksum, and MacSec’s own updates are signed.'
    ]
  },
  {
    title: 'How it decides what is true',
    lines: [
      '“Confirmed” needs proof you can repeat: the request, a command to run it again, and what in the answer shows the problem.',
      'A match on a version number is only ever “possible”. An AI opinion alone is never “confirmed”.',
      'Known decoys and honeypots are turned down to a note, never hidden. You can mark a finding “Not a problem” and MacSec remembers it.'
    ]
  },
  {
    title: 'The AI reviewer',
    lines: [
      'AI reviewers run read-only. They can read code but not change it, and they do not load your own MCP servers.',
      'A suggested fix is written in a scratch copy of the project, never in the project itself. Applying it needs you to type a confirmation and the project’s own tests to pass, and a copy is kept so you can roll it back.',
      'If you pick a cloud AI, the code it reviews is sent to that service under your account. Choose a local model to keep everything on this Mac.'
    ]
  },
  {
    title: 'Honest limits',
    lines: [
      'It is not certified, and nothing here is a compliance claim. Findings need a person to review them.',
      'No scanner finds everything. A clear result means “nothing found by these checks”, not “secure”.'
    ]
  }
]

const asText = (org: string): string =>
  [`How MacSec stays safe${org ? ` (used by ${org})` : ''}`, '', ...BLOCKS.flatMap((b) => [b.title.toUpperCase(), ...b.lines.map((l) => `- ${l}`), ''])].join('\n')

export default function Safety(): React.JSX.Element {
  const { setPage, settings, updateSettings } = useApp()
  const [org, setOrg] = useState(settings?.organisation ?? '')
  const [copied, setCopied] = useState(false)
  useEffect(() => setOrg(settings?.organisation ?? ''), [settings?.organisation])

  return (
    <>
      <PageHead title="How MacSec stays safe" desc="What MacSec will never do, what it only does when you ask, and how it proves a problem. Share this with your security team." />
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginBottom: 14 }}>
        <button className="btn btn-sm" onClick={() => setPage('settings')}>
          <ArrowLeft size={14} /> Back
        </button>
        <button
          className="btn btn-sm"
          onClick={async () => {
            await navigator.clipboard.writeText(asText(org))
            setCopied(true)
            setTimeout(() => setCopied(false), 2000)
          }}
        >
          <Copy size={14} /> {copied ? 'Copied' : 'Copy as text'}
        </button>
      </div>
      <div className="glass" style={{ padding: 16, marginBottom: 14, display: 'grid', gap: 6 }}>
        <label className="row-title" htmlFor="org">
          Organisation (optional)
        </label>
        <input id="org" className="input" placeholder="For example: your company or team name" maxLength={80} value={org} onChange={(e) => setOrg(e.target.value)} onBlur={() => void updateSettings({ organisation: org })} />
        <span className="hint">You type this yourself. It is shown here and in the copied text, nowhere else.</span>
      </div>
      {org && (
        <p className="hint" style={{ marginBottom: 10 }}>
          <ShieldCheck size={14} /> Used by {org}
        </p>
      )}
      <div style={{ display: 'grid', gap: 12 }}>
        {BLOCKS.map((b) => (
          <section key={b.title} className="glass" style={{ padding: 16 }}>
            <h3 style={{ margin: '0 0 8px' }}>{b.title}</h3>
            <ul style={{ margin: 0, paddingLeft: 20, display: 'grid', gap: 6 }}>
              {b.lines.map((l) => (
                <li key={l}>{l}</li>
              ))}
            </ul>
          </section>
        ))}
      </div>
    </>
  )
}
