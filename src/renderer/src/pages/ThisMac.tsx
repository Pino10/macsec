import { useEffect, useState } from 'react'
import { Box, CheckCircle2, CircleAlert, CircleX, Info, Laptop, Play } from 'lucide-react'
import type { CheckupResult, Finding } from '@shared/types'
import { useApp } from '../store'
import { PageHead } from '../ui'

const ICON = { ok: <CheckCircle2 size={16} style={{ color: 'var(--ok, #3ccf8e)' }} />, warn: <CircleAlert size={16} style={{ color: 'var(--warn, #e0a64b)' }} />, bad: <CircleX size={16} style={{ color: 'var(--bad, #f0605d)' }} />, info: <Info size={16} style={{ opacity: 0.7 }} /> }

/** This Mac's security settings, and the container images on it. Everything only reads. */
export default function ThisMac(): React.JSX.Element {
  const { act, busy } = useApp()
  const api = window.macsec
  const [r, setR] = useState<CheckupResult | null>(null)
  const [tab, setTab] = useState<'checks' | 'login' | 'ports' | 'ssh' | 'ext' | 'images'>('checks')
  const [images, setImages] = useState<{ running: boolean; images: { ref: string; size: string; created: string }[] } | null>(null)
  const [scan, setScan] = useState<{ ref: string; findings: Finding[] } | null>(null)
  useEffect(() => {
    void api.invoke('checkup:last').then(setR)
  }, [api])
  useEffect(() => {
    if (tab === 'images' && !images) void api.invoke('docker:images').then(setImages)
  }, [api, tab, images])
  const run = async (): Promise<void> => setR((await act('checkup', () => api.invoke('checkup:run'))) ?? r)
  return (
    <>
      <PageHead title="This Mac" desc="A security check-up of the Mac you are using: disk encryption, firewall, Gatekeeper, updates, programs that start on their own, open ports, SSH keys and browser extensions. It only reads, and nothing leaves the Mac.">
        <button className="btn btn-primary" disabled={busy.has('checkup')} onClick={run}>
          <Play size={14} /> {busy.has('checkup') ? 'Checking…' : r ? 'Check again' : 'Check this Mac'}
        </button>
      </PageHead>
      {r && (
        <div className="panel mac-score">
          <Laptop size={28} />
          <div>
            <strong>{r.score} / 100</strong>
            <span className="hint">macOS {r.macos} · checked {new Date(r.at).toLocaleString()}</span>
          </div>
          <span className="hint" style={{ marginLeft: 'auto' }}>
            {r.checks.filter((c) => c.status === 'bad').length} to fix now · {r.checks.filter((c) => c.status === 'warn').length} to look at
          </span>
        </div>
      )}
      <div className="seg" role="radiogroup" aria-label="Section" style={{ margin: '14px 0' }}>
        {(
          [
            ['checks', 'Settings'],
            ['login', `Start on their own${r ? ` (${r.loginItems.length})` : ''}`],
            ['ports', `Open ports${r ? ` (${r.ports.length})` : ''}`],
            ['ssh', `SSH keys${r ? ` (${r.sshKeys.length})` : ''}`],
            ['ext', `Browser extensions${r ? ` (${r.extensions.length})` : ''}`],
            ['images', 'Container images']
          ] as const
        ).map(([k, l]) => (
          <button key={k} role="radio" aria-checked={tab === k} onClick={() => setTab(k)}>
            {l}
          </button>
        ))}
      </div>
      {!r && tab !== 'images' && <div className="panel empty-state">Press “Check this Mac”. It takes a few seconds.</div>}
      {r && tab === 'checks' && (
        <div className="panel">
          {[...new Set(r.checks.map((c) => c.group ?? 'Settings'))].map((g) => (
            <div key={g}>
              <div className="mac-group">{g}</div>
              {r.checks
                .filter((c) => (c.group ?? 'Settings') === g)
                .map((c) => (
                  <div key={c.id} className="row mac-row">
                    {ICON[c.status]}
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div className="row-title">{c.title}</div>
                      <div className="row-sub" style={{ whiteSpace: 'normal' }}>{c.detail}</div>
                      {c.fix && <div className="row-sub fix-line" style={{ whiteSpace: 'normal' }}>How: {c.fix}</div>}
                    </div>
                  </div>
                ))}
            </div>
          ))}
        </div>
      )}
      {r && tab === 'login' && (
        <div className="panel">
          {r.loginItems.length === 0 && <div className="empty-state">No launch agents or daemons.</div>}
          {r.loginItems.map((l) => (
            <div key={l.plist} className="row mac-row">
              {ICON[l.status]}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="row-title">{l.label} <span className="tag">{l.where}</span></div>
                <div className="row-sub mono" style={{ whiteSpace: 'normal' }}>{l.program ?? l.plist}</div>
                <div className="row-sub" style={{ whiteSpace: 'normal' }}>{l.note}</div>
              </div>
            </div>
          ))}
        </div>
      )}
      {r && tab === 'ports' && (
        <div className="panel">
          {r.ports.length === 0 && <div className="empty-state">Nothing is listening.</div>}
          {r.ports.map((p) => (
            <div key={`${p.command}${p.port}${p.address}`} className="row mac-row">
              {p.everyone ? ICON.warn : ICON.ok}
              <div style={{ flex: 1 }}>
                <div className="row-title">{p.command} <span className="hint">pid {p.pid}</span></div>
                <div className="row-sub">{p.everyone ? `Reachable from your network on port ${p.port}` : `Only this Mac (${p.address}:${p.port})`}</div>
              </div>
            </div>
          ))}
        </div>
      )}
      {r && tab === 'ssh' && (
        <div className="panel">
          {r.sshKeys.length === 0 && <div className="empty-state">No private keys in ~/.ssh.</div>}
          {r.sshKeys.map((k) => (
            <div key={k.file} className="row mac-row">
              {!k.permissionsOk ? ICON.bad : k.protectedByPassphrase === false ? ICON.warn : ICON.ok}
              <div style={{ flex: 1 }}>
                <div className="row-title mono">{k.file}</div>
                <div className="row-sub">{k.kind} key · {k.protectedByPassphrase === null ? 'passphrase unknown' : k.protectedByPassphrase ? 'protected by a passphrase' : 'no passphrase'} · {k.permissionsOk ? 'only you can read it' : 'other users can read it: chmod 600'}</div>
              </div>
            </div>
          ))}
        </div>
      )}
      {r && tab === 'ext' && (
        <div className="panel">
          {r.extensions.length === 0 && <div className="empty-state">No extensions in Chrome, Brave, Edge, Arc or Vivaldi.</div>}
          {r.extensions.map((e) => (
            <div key={`${e.browser}${e.id}`} className="row mac-row">
              {e.risky.includes('reads every site') ? ICON.warn : ICON.info}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="row-title">{e.name} <span className="tag">{e.browser}</span> <span className="hint">{e.version}</span></div>
                <div className="row-sub" style={{ whiteSpace: 'normal' }}>{e.risky.length ? `Can: ${e.risky.join(', ')}` : 'No broad permissions.'}</div>
              </div>
            </div>
          ))}
        </div>
      )}
      {tab === 'images' && (
        <div className="panel">
          {!images && <div className="empty-state">Looking for Docker…</div>}
          {images && !images.running && <div className="empty-state">Docker is not running. Start OrbStack, Docker Desktop or Colima to scan your images.</div>}
          {images?.running && images.images.length === 0 && <div className="empty-state">No images on this Mac.</div>}
          {images?.images.map((i) => (
            <div key={i.ref} className="row mac-row">
              <Box size={16} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="row-title mono">{i.ref}</div>
                <div className="row-sub">{i.size} · {i.created}</div>
              </div>
              <button className="btn btn-sm" disabled={busy.has(`img-${i.ref}`)} onClick={async () => { const f = await act(`img-${i.ref}`, () => api.invoke('docker:scan', i.ref)); if (f) setScan({ ref: i.ref, findings: f }) }}>
                {busy.has(`img-${i.ref}`) ? 'Scanning…' : 'Scan with Trivy'}
              </button>
            </div>
          ))}
          {scan && (
            <div className="pad">
              <div className="row-title" style={{ margin: '10px 0' }}>{scan.ref}: {scan.findings.length} findings</div>
              {scan.findings.slice(0, 200).map((f) => (
                <div key={f.id} className="row mac-row">
                  <span className="sev" data-sev={f.severity}>{f.severity}</span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div className="row-title">{f.title}</div>
                    {f.fix && <div className="row-sub">{f.fix}</div>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </>
  )
}
