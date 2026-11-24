import { useEffect, useMemo, useState } from 'react'
import { Crosshair, FlaskConical, ShieldAlert, ShieldCheck, Trash2 } from 'lucide-react'
import type { Engagement, ImpactActionInfo, ImpactClass, ImpactPlan, ImpactRun, PlannedStep } from '@shared/impact'
import { IMPACT_CLASSES, IMPACT_LETTER } from '@shared/impact'
import { useApp } from '../store'
import { Empty, PageHead } from '../ui'

const day = (offset: number): string => {
  const d = new Date(Date.now() + offset * 86400_000)
  return d.toISOString().slice(0, 10)
}

const cls = (c: ImpactClass): string => (c === 'confidentiality' ? 'C' : c === 'integrity' ? 'I' : 'A')
const clsName = (c: ImpactClass): string => c[0].toUpperCase() + c.slice(1)

const DRAFT_DEFAULTS = {
  profile: 'pentest',
  client: '',
  authorityRef: '',
  authorizedBy: '',
  hosts: '',
  allowPrivate: false,
  startsAt: day(0),
  endsAt: day(14),
  requests: 400,
  writes: 10,
  minutes: 20,
  confidentiality: true,
  integrity: true,
  availability: true,
  notes: ''
}

/** An engagement, written once, is the authority every controlled proof stands on. */
function EngagementForm({ onSaved }: { onSaved: (e: Engagement) => void }): React.JSX.Element {
  const { act, notify } = useApp()
  const api = window.macsec
  const [f, setF] = useState(DRAFT_DEFAULTS)
  const set = (patch: Partial<typeof DRAFT_DEFAULTS>): void => setF((x) => ({ ...x, ...patch }))
  const allowed = IMPACT_CLASSES.filter((c) => f[c])
  return (
    <div className="flow">
      <section className="flow-step glass" data-state="current">
        <span className="flow-num" aria-hidden>
          1
        </span>
        <div className="flow-body">
          <h2 className="flow-title">Write the engagement</h2>
          <p className="flow-help">
            A controlled proof changes things or reads real data, so it needs the same thing a person would have in hand on site: who allowed it, for which hosts, until when, and how many requests. Everything here is stored on this Mac and printed with every run.
          </p>
          <div className="choices" style={{ display: 'grid', gap: 10 }}>
            <label className="hint" style={{ display: 'grid', gap: 4 }}>
              Engagement type
              <select className="input" value={f.profile} onChange={(e) => set({ profile: e.target.value })}>
                <option value="pentest">Pentest or assessment</option>
                <option value="bounty">Bug bounty programme</option>
                <option value="red-team">Red team or adversary simulation</option>
                <option value="internal">Internal audit</option>
                <option value="lab">Lab or training</option>
              </select>
            </label>
            <input className="input" placeholder="Client or project" value={f.client} onChange={(e) => set({ client: e.target.value })} aria-label="Client or project" />
            <input className="input" placeholder="Authority reference (contract, ticket, email subject, programme id)" value={f.authorityRef} onChange={(e) => set({ authorityRef: e.target.value })} aria-label="Authority reference" />
            <input className="input" placeholder="Who gave the authority (a person, or the programme)" value={f.authorizedBy} onChange={(e) => set({ authorizedBy: e.target.value })} aria-label="Who gave the authority" />
            <textarea className="input mono" rows={3} placeholder="Hosts the authority covers, one per line. shop.example.com, or *.example.com for its subdomains." value={f.hosts} onChange={(e) => set({ hosts: e.target.value })} aria-label="Hosts" />
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
              <label className="hint" style={{ display: 'grid', gap: 4 }}>
                Starts
                <input className="input" type="date" value={f.startsAt} onChange={(e) => set({ startsAt: e.target.value })} />
              </label>
              <label className="hint" style={{ display: 'grid', gap: 4 }}>
                Ends
                <input className="input" type="date" value={f.endsAt} onChange={(e) => set({ endsAt: e.target.value })} />
              </label>
              <label className="hint" style={{ display: 'grid', gap: 4 }}>
                Requests
                <input className="input" type="number" min={1} max={20000} value={f.requests} onChange={(e) => set({ requests: Number(e.target.value) })} />
              </label>
              <label className="hint" style={{ display: 'grid', gap: 4 }}>
                Writes
                <input className="input" type="number" min={0} max={200} value={f.writes} onChange={(e) => set({ writes: Number(e.target.value) })} />
              </label>
              <label className="hint" style={{ display: 'grid', gap: 4 }}>
                Minutes per run
                <input className="input" type="number" min={1} max={480} value={f.minutes} onChange={(e) => set({ minutes: Number(e.target.value) })} />
              </label>
            </div>
            <div className="chips">
              {IMPACT_CLASSES.map((c) => (
                <button key={c} className="chip" aria-pressed={!!f[c]} onClick={() => set({ [c]: !f[c] } as Partial<typeof DRAFT_DEFAULTS>)}>
                  {clsName(c)} <i>{cls(c)}</i>
                </button>
              ))}
            </div>
            <label className="consent">
              <input type="checkbox" checked={f.allowPrivate} onChange={(e) => set({ allowPrivate: e.target.checked })} />
              <span>This engagement may test a staging server on this Mac or on the local network. Leave it off for anything reachable from the internet.</span>
            </label>
            <textarea className="input" rows={2} placeholder="Anything else the authority says (optional)" value={f.notes} onChange={(e) => set({ notes: e.target.value })} aria-label="Notes" />
          </div>
          <div style={{ display: 'flex', gap: 10, marginTop: 14, alignItems: 'center' }}>
            <button
              className="btn btn-primary"
              disabled={!f.client.trim() || !f.authorityRef.trim() || !f.authorizedBy.trim() || !f.hosts.trim() || !allowed.length}
              onClick={async () => {
                const e = await act('impact-engagement', () =>
                  api.invoke('impact:save-engagement', {
                    profile: f.profile as 'pentest' | 'bounty' | 'red-team' | 'internal' | 'lab',
                    client: f.client,
                    authorityRef: f.authorityRef,
                    authorizedBy: f.authorizedBy,
                    hosts: f.hosts.split(/[\s,;]+/).filter(Boolean),
                    allowPrivate: f.allowPrivate,
                    startsAt: new Date(`${f.startsAt}T00:00:00`).toISOString(),
                    endsAt: new Date(`${f.endsAt}T23:59:59`).toISOString(),
                    caps: { requests: f.requests, writes: f.writes, minutes: f.minutes },
                    allowed,
                    notes: f.notes
                  })
                )
                if (e) {
                  notify({ kind: 'success', title: 'Engagement saved', text: `${e.hosts.length} host${e.hosts.length === 1 ? '' : 's'} until ${e.endsAt.slice(0, 10)}.` })
                  onSaved(e)
                }
              }}
            >
              <ShieldCheck size={15} /> Save the engagement
            </button>
            <span className="hint">Nothing is sent by saving this. It is the form of words a run is checked against.</span>
          </div>
        </div>
      </section>
    </div>
  )
}

/** The box the whole page sits in: current engagement, and how to end it. */
function EngagementCard({ e, onRevoke }: { e: Engagement; onRevoke: (e: Engagement) => void }): React.JSX.Element {
  const { act } = useApp()
  const [sure, setSure] = useState(false)
  const api = window.macsec
  const left = e.caps.requests - e.used.requests
  return (
    <div className="panel" style={{ padding: 16, marginBottom: 18 }}>
      <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start', flexWrap: 'wrap' }}>
        <ShieldCheck size={18} style={{ color: 'var(--ok)' }} />
        <div className="grow">
          <div className="row-title">{e.client}</div>
          <div className="row-sub">
            Authority {e.authorityRef}, given by {e.authorizedBy}. {e.hosts.join(', ')}. Until {e.endsAt.slice(0, 10)}.
            {e.allowPrivate ? ' Staging servers allowed.' : ''}
          </div>
          <div className="hint" style={{ marginTop: 4 }}>
            {left} of {e.caps.requests} requests left, {e.caps.writes - e.used.writes} of {e.caps.writes} writes, {e.caps.minutes} minutes per run. Allowed: {e.allowed.map(clsName).join(', ')}.
          </div>
        </div>
        {sure ? (
          <>
            <button className="btn btn-danger btn-sm" onClick={async () => { const x = await act('impact-revoke', () => api.invoke('impact:revoke', e.id)); if (x) onRevoke(x) }}>
              <Trash2 size={13} /> Revoke now
            </button>
            <button className="btn btn-sm" onClick={() => setSure(false)}>
              Keep it
            </button>
          </>
        ) : (
          <button className="btn btn-sm" onClick={() => setSure(true)}>
            Revoke
          </button>
        )}
      </div>
    </div>
  )
}

function RunResult({ run }: { run: ImpactRun }): React.JSX.Element {
  const mark = (c: ImpactClass): boolean => run.proven.includes(c)
  return (
    <div className="panel" style={{ padding: 16, marginTop: 14 }}>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <ShieldAlert size={17} style={{ color: run.proven.length ? 'var(--sev-high)' : 'var(--ink-3)' }} />
        <strong>{run.stopped}</strong>
        <span className="hint">
          {run.requests} requests, {run.writes} writes, {run.steps.length} step{run.steps.length === 1 ? '' : 's'}
          {run.linked?.length ? `, ${run.linked.length} finding${run.linked.length === 1 ? '' : 's'} marked Proven` : ''}
        </span>
      </div>
      <div className="chips" style={{ marginTop: 10 }}>
        {IMPACT_CLASSES.map((c) => (
          <span key={c} className="chip" aria-pressed={mark(c)}>
            {cls(c)} {clsName(c)} <i>{mark(c) ? 'proven' : 'not proven'}</i>
          </span>
        ))}
      </div>
      {run.steps.map((s) => (
        <div key={s.step} className="ms-row" style={{ alignItems: 'flex-start' }}>
          <span className="tag" data-sev={s.status === 'proven' ? 'ok' : s.status === 'failed' ? 'critical' : undefined}>
            {s.status}
          </span>
          <div className="grow">
            <div className="row-title">{s.title}</div>
            <div className="row-sub">{s.detail}</div>
            {s.evidence ? (
              <div className="hint mono" style={{ marginTop: 6 }}>
                {s.evidence.method} {s.evidence.url} → HTTP {s.evidence.status}, {s.evidence.bytes.toLocaleString()} bytes, sha256 {s.evidence.sha256.slice(0, 16)}…
                <div style={{ marginTop: 4 }}>{s.evidence.shows.map((x) => `· ${x}`).join('\n')}</div>
              </div>
            ) : null}
            {s.cleanup ? <div className="hint">Cleanup: {s.cleanup.how}</div> : null}
          </div>
          <span className="hint">{cls(s.aims)}</span>
        </div>
      ))}
      {run.leftover.length > 0 && (
        <div className="notice bad" style={{ marginTop: 10 }}>
          <ShieldAlert size={16} />
          <div>
            <b>Left behind:</b> {run.leftover.map((l) => `${l.what} at ${l.where}. ${l.how}`).join(' ')}
          </div>
        </div>
      )}
    </div>
  )
}

/** The fields a plan cannot know, filled in by the person before the run. */
function missingFields(s: PlannedStep): string[] {
  const out: string[] = []
  if ((s.action === 'replay-request' || s.action === 'auth-bypass') && !s.expect) out.push('the string that proves it')
  if (s.action === 'replay-request' && !s.url.includes('?')) out.push('the address and method you mean')
  if (s.action === 'upload-write' && !s.verifyUrl) out.push('where the file can be read back')
  if (s.action === 'msf-run' && !s.module) out.push('which Metasploit module to run')
  if (s.write && !s.undo) out.push('how to undo it')
  return out
}

const parseHeaderLines = (text: string): Record<string, string> => {
  const out: Record<string, string> = {}
  for (const line of text.split('\n')) {
    const i = line.indexOf(':')
    if (i < 1) continue
    const k = line.slice(0, i).trim()
    const v = line.slice(i + 1).trim()
    if (/^[A-Za-z0-9-]{2,64}$/.test(k) && v) out[k] = v
  }
  return out
}

function StepEditor({ s, plan, onSaved, onCancel }: { s: PlannedStep; plan: ImpactPlan; onSaved: (p: ImpactPlan) => void; onCancel: () => void }): React.JSX.Element {
  const { act } = useApp()
  const api = window.macsec
  const [expect, setExpect] = useState(s.expect ?? '')
  const [undo, setUndo] = useState(s.undo ?? '')
  const [verifyUrl, setVerifyUrl] = useState(s.verifyUrl ?? '')
  const [method, setMethod] = useState<NonNullable<PlannedStep['method']>>(s.method ?? 'GET')
  const [headers, setHeaders] = useState(Object.entries(s.headers ?? {}).map(([k, v]) => `${k}: ${v}`).join('\n'))
  const [body, setBody] = useState(s.body ?? '')
  const [module, setModule] = useState(s.module ?? '')
  const [modules, setModules] = useState<{ module: string; cve: string; title: string; what: string; risk: string }[]>([])
  const api2 = window.macsec
  useEffect(() => {
    if (s.action === 'msf-run') void api2.invoke('impact:msf-modules').then(setModules)
  }, [api2, s.action])
  const replay = s.action === 'replay-request'
  const upload = s.action === 'upload-write'
  const needExpect = replay || s.action === 'auth-bypass'
  const save = async (): Promise<void> => {
    const patch: Record<string, unknown> = {}
    if (needExpect) patch.expect = expect.trim()
    if (upload) patch.verifyUrl = verifyUrl.trim()
    if (s.write) patch.undo = undo.trim()
    if (s.action === 'msf-run') patch.module = module
    if (replay) {
      patch.method = method
      patch.body = body
      patch.headers = parseHeaderLines(headers)
    }
    const p = await act('impact-step', () => api.invoke('impact:update-step', { planId: plan.id, stepId: s.id, patch }))
    if (p) onSaved(p)
  }
  return (
    <div style={{ display: 'grid', gap: 8, marginTop: 10, paddingTop: 10, borderTop: '1px solid var(--line)' }}>
      {needExpect && (
        <label className="hint" style={{ display: 'grid', gap: 4 }}>
          The string the answer must contain, which only a signed-in person (or the right account) should see
          <input className="input mono" value={expect} onChange={(e) => setExpect(e.target.value)} placeholder="your own email, an order number, a name" />
        </label>
      )}
      {upload && (
        <label className="hint" style={{ display: 'grid', gap: 4 }}>
          Where the uploaded file can be read back, with {'{name}'} for the file name
          <input className="input mono" value={verifyUrl} onChange={(e) => setVerifyUrl(e.target.value)} placeholder="https://shop.example/uploads/{name}" />
        </label>
      )}
      {replay && (
        <>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <span className="hint">Method</span>
            <select className="input" style={{ width: 110 }} value={method} onChange={(e) => setMethod(e.target.value as NonNullable<PlannedStep['method']>)} aria-label="Method">
              {(['GET', 'POST', 'PUT', 'PATCH'] as const).map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
            <span className="hint">Headers, one Name: value per line (only what this request needs)</span>
          </div>
          <textarea className="input mono" rows={3} value={headers} onChange={(e) => setHeaders(e.target.value)} placeholder={'Accept: application/json\nContent-Type: application/json'} aria-label="Headers" />
          <textarea className="input mono" rows={3} value={body} onChange={(e) => setBody(e.target.value)} placeholder="Request body, if the request sends one" aria-label="Body" />
        </>
      )}
      {s.action === 'msf-run' && (
        <div style={{ display: 'grid', gap: 6 }}>
          <span className="hint">The module to run. Metasploit is needed, and the target must be able to reach this Mac.</span>
          <select className="input mono" value={module} onChange={(e) => setModule(e.target.value)} aria-label="Metasploit module">
            <option value="">Pick a module</option>
            {modules.map((m) => (
              <option key={m.module} value={m.module}>
                {m.title} ({m.cve})
              </option>
            ))}
          </select>
          {(() => {
            const chosen = modules.find((m) => m.module === module)
            return chosen ? (
              <span className="hint">
                {chosen.what} {chosen.risk}
              </span>
            ) : null
          })()}
        </div>
      )}
      {s.write && (
        <label className="hint" style={{ display: 'grid', gap: 4 }}>
          How to undo it, in one sentence
          <input className="input" value={undo} onChange={(e) => setUndo(e.target.value)} placeholder="Delete the row I made, or the file in the uploads folder" />
        </label>
      )}
      <div style={{ display: 'flex', gap: 8 }}>
        <button className="btn btn-sm btn-primary" onClick={() => void save()}>
          Save the step
        </button>
        <button className="btn btn-sm" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </div>
  )
}

export default function Impact(): React.JSX.Element {
  const { act, busy, sessions, settings, notify } = useApp()
  const api = window.macsec
  const [engagements, setEngagements] = useState<Engagement[]>([])
  const [current, setCurrent] = useState<Engagement | null>(null)
  const [catalog, setCatalog] = useState<ImpactActionInfo[]>([])
  const [runs, setRuns] = useState<ImpactRun[]>([])
  const [target, setTarget] = useState('')
  const [goal, setGoal] = useState<ImpactClass[]>([...IMPACT_CLASSES])
  const [useAi, setUseAi] = useState(false)
  const [plan, setPlan] = useState<ImpactPlan | null>(null)
  const [cost, setCost] = useState<{ tokens: number } | null>(null)
  const [approved, setApproved] = useState<Set<string>>(new Set())
  const [phrase, setPhrase] = useState('')
  const [acceptLeftovers, setAcceptLeftovers] = useState(false)
  const [lines, setLines] = useState<string[]>([])
  const [result, setResult] = useState<ImpactRun | null>(null)
  const [running, setRunning] = useState(false)
  const [editing, setEditing] = useState<string | null>(null)

  useEffect(() => {
    void api.invoke('impact:engagements').then((l) => {
      setEngagements(l)
      setCurrent(l.find((e) => !e.revokedAt && new Date(e.endsAt).getTime() > Date.now()) ?? null)
    })
    void api.invoke('impact:current').then(setCurrent)
    void api.invoke('impact:catalog').then(setCatalog)
    void api.invoke('impact:runs').then(setRuns)
  }, [api])

  useEffect(() => api.on('impact:progress', (p) => setLines((l) => [...l.slice(-160), p.line])), [api])

  // A target to start from: the newest finished test, if it has a web address.
  const suggested = useMemo(() => {
    for (const s of sessions) {
      if (s.status === 'running') continue
      if (/^https?:\/\//.test(s.target)) return s.target
      if (!/[/\\]/.test(s.target) && s.target.includes('.')) return `https://${s.target}`
    }
    return ''
  }, [sessions])

  const host = useMemo(() => {
    try {
      return new URL(target).host.toLowerCase()
    } catch {
      return ''
    }
  }, [target])
  const wanted = useMemo(() => `EXPLOIT ${host}`, [host])
  const writeSteps = plan ? plan.steps.filter((s) => s.write) : []
  const incomplete = plan ? plan.steps.filter((s) => approved.has(s.id) && missingFields(s).length > 0) : []
  const ready =
    !!plan &&
    !!current &&
    plan.steps.length > 0 &&
    approved.size > 0 &&
    phrase === wanted &&
    incomplete.length === 0 &&
    (!writeSteps.length || acceptLeftovers) &&
    !running
  const allowedGoals = current?.allowed ?? IMPACT_CLASSES

  return (
    <>
      <PageHead
        title="Controlled proofs"
        desc="Prove what someone could actually do, under a written engagement, without flooding anything or dumping data. Every proof stops at the first result and cleans up after itself."
      />

      {!current ? (
        <EngagementForm onSaved={(e) => { setCurrent(e); setEngagements((l) => [e, ...l]) }} />
      ) : (
        <>
          <EngagementCard e={current} onRevoke={(e) => { setCurrent(null); setEngagements((l) => l.map((x) => (x.id === e.id ? e : x))) }} />

          {engagements.length > 1 && (
            <div className="chips" style={{ marginBottom: 14 }}>
              {engagements.map((e) => (
                <button key={e.id} className="chip" aria-pressed={current.id === e.id} onClick={() => setCurrent(e)}>
                  {e.client} <i>{e.revokedAt ? 'revoked' : e.endsAt.slice(0, 10)}</i>
                </button>
              ))}
            </div>
          )}

          <div className="panel" style={{ padding: 16 }}>
            <h2 className="section-title" style={{ marginTop: 0 }}>
              What to prove
            </h2>
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
              <input
                className="input mono grow"
                placeholder="https://staging.example.com"
                value={target || suggested}
                onChange={(e) => setTarget(e.target.value)}
                aria-label="Target address"
              />
              <div className="chips">
                {IMPACT_CLASSES.map((c) => {
                  const allowed = allowedGoals.includes(c)
                  const on = goal.includes(c)
                  return (
                    <button
                      key={c}
                      className="chip"
                      disabled={!allowed}
                      aria-pressed={on}
                      title={allowed ? undefined : 'The engagement does not allow this kind of impact'}
                      onClick={() => setGoal((g) => (on ? g.filter((x) => x !== c) : [...g, c]))}
                    >
                      {cls(c)} {clsName(c)}
                    </button>
                  )
                })}
              </div>
            </div>
            <label className="check" style={{ marginTop: 10, display: 'inline-flex', gap: 8 }}>
              <input type="checkbox" checked={useAi} onChange={(e) => setUseAi(e.target.checked)} />
              Let the AI choose the steps as well (one call, findings only, a few thousand tokens at most)
            </label>
            <div style={{ display: 'flex', gap: 10, marginTop: 12, alignItems: 'center', flexWrap: 'wrap' }}>
              <button
                className="btn btn-primary"
                disabled={!target.trim() || !goal.length || busy.has('impact-plan')}
                onClick={async () => {
                  const r = await act('impact-plan', () =>
                    api.invoke('impact:plan', { engagementId: current.id, target: target || suggested, goal, useAi, reviewer: settings?.reviewer ?? 'claude' })
                  )
                  if (r) {
                    setPlan(r.plan)
                    setApproved(new Set(r.plan.steps.map((s) => s.id)))
                    setPhrase('')
                    setResult(null)
                    setLines([])
                    setCost(r.cost ? { tokens: r.cost.tokens } : null)
                  }
                }}
              >
                <FlaskConical size={15} /> {busy.has('impact-plan') ? 'Planning…' : useAi ? 'Plan with the AI' : 'Plan from the findings'}
              </button>
              <span className="hint">
                {cost ? `That plan used about ${cost.tokens.toLocaleString()} tokens of planning.` : 'Planning is free: it uses the findings already on this Mac.'}
              </span>
            </div>
          </div>

          {plan && (
            <div className="panel" style={{ padding: 16, marginTop: 14 }}>
              <h2 className="section-title" style={{ marginTop: 0 }}>
                The plan ({plan.source === 'ai' ? 'chosen by the AI, checked by MacSec' : 'from the findings'})
              </h2>
              {plan.notes.map((n, i) => (
                <p key={i} className="hint">
                  {n}
                </p>
              ))}
              {plan.steps.length === 0 && <Empty title="No step for this target yet">Add a finding with a page and a parameter, or use the replay proof with a request you paste.</Empty>}
              {plan.steps.map((s) => {
                const info = catalog.find((c) => c.id === s.action)
                return (
                  <div key={s.id} className="ms-row" style={{ alignItems: 'flex-start' }}>
                    <input
                      type="checkbox"
                      checked={approved.has(s.id)}
                      aria-label={`Approve ${s.id}`}
                      onChange={(e) =>
                        setApproved((set) => {
                          const n = new Set(set)
                          if (e.target.checked) n.add(s.id)
                          else n.delete(s.id)
                          return n
                        })
                      }
                    />
                    <div className="grow">
                      <div className="row-title">
                        {s.id} · {info?.name ?? s.action} <span className="tag">{cls(s.aims)} {clsName(s.aims)}</span>
                        {s.write ? <span className="tag tag-warn"> can write </span> : null}
                      </div>
                      <div className="row-sub">{s.why}</div>
                      <div className="hint mono" style={{ marginTop: 6 }}>
                        {s.preview.map((p) => `· ${p}`).join('\n')}
                      </div>
                      {s.undo ? <div className="hint">Undo: {s.undo}</div> : null}
                      {info ? <div className="hint">{info.cleanup}</div> : null}
                      {missingFields(s).length > 0 ? (
                        <div className="hint" style={{ color: 'var(--warn)' }}>
                          Needs you: {missingFields(s).join('; ')}.{' '}
                          <button className="link" onClick={() => setEditing(editing === s.id ? null : s.id)}>
                            {editing === s.id ? 'Close' : 'Fill in'}
                          </button>
                        </div>
                      ) : (
                        <div className="hint">
                          Complete. <button className="link" onClick={() => setEditing(editing === s.id ? null : s.id)}>{editing === s.id ? 'Close' : 'Edit'}</button>
                        </div>
                      )}
                      {editing === s.id ? (
                        <StepEditor
                          s={s}
                          plan={plan}
                          onCancel={() => setEditing(null)}
                          onSaved={(p) => {
                            setPlan(p)
                            setEditing(null)
                          }}
                        />
                      ) : null}
                    </div>
                  </div>
                )
              })}
              {plan.steps.length > 0 && (
                <div style={{ marginTop: 14, display: 'grid', gap: 10 }}>
                  {writeSteps.length > 0 && (
                    <label className="consent">
                      <input type="checkbox" checked={acceptLeftovers} onChange={(e) => setAcceptLeftovers(e.target.checked)} />
                      <span>
                        One or more steps can write to the site. I accept that a file may be left behind and I know where it goes. MacSec will try to remove it and will list it if it cannot.
                      </span>
                    </label>
                  )}
                  <label className="consent">
                    <input type="checkbox" checked={phrase === wanted} onChange={(e) => setPhrase(e.target.checked ? wanted : '')} />
                    <span>
                      I have the authority for <b>{host || 'this target'}</b> and I am allowed to prove impact on it.
                    </span>
                  </label>
                  <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                    <input className="input mono" style={{ maxWidth: 320 }} placeholder={wanted} value={phrase} onChange={(e) => setPhrase(e.target.value)} aria-label="Confirmation phrase" />
                    <button
                      className="btn btn-danger"
                      disabled={!ready}
                      onClick={async () => {
                        setRunning(true)
                        setLines([])
                        try {
                          const run = await act('impact-run', () =>
                            api.invoke('impact:run', { planId: plan.id, phrase, approved: [...approved], acceptLeftovers })
                          )
                          if (run) {
                            setResult(run)
                            setRuns((l) => [run, ...l].slice(0, 12))
                            notify({ kind: run.proven.length ? 'success' : 'info', title: run.proven.length ? 'Impact proven' : 'Nothing proven', text: run.stopped })
                          }
                        } finally {
                          setRunning(false)
                        }
                      }}
                    >
                      <Crosshair size={15} /> {running ? 'Running…' : 'Run the approved steps'}
                    </button>
                    {running && (
                      <button className="btn btn-sm" onClick={() => void act('impact-stop', () => api.invoke('impact:stop'))}>
                        Stop
                      </button>
                    )}
                    <span className="hint">
                      Requests are sent one at a time, with a pause, and the run stops at the first proof of each goal. Every request is logged.
                    </span>
                  </div>
                </div>
              )}
            </div>
          )}

          {(running || lines.length > 0) && (
            <div className="panel" style={{ padding: 12, marginTop: 14 }}>
              <div className="hint mono" style={{ maxHeight: 220, overflow: 'auto' }}>
                {lines.length ? lines.join('\n') : 'Waiting for the first step…'}
              </div>
            </div>
          )}

          {result && <RunResult run={result} />}

          {runs.length > 0 && (
            <div className="panel" style={{ padding: 16, marginTop: 18 }}>
              <h2 className="section-title" style={{ marginTop: 0 }}>
                Earlier runs
              </h2>
              {runs.map((r) => (
                <button key={r.id} className="row" onClick={() => setResult(r)}>
                  <Crosshair size={15} />
                  <span className="grow">
                    <span className="row-title" style={{ display: 'block' }}>
                      {new URL(r.target).host}
                    </span>
                    <span className="row-sub">
                      {new Date(r.startedAt).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' })} · {r.requests} requests · {r.stopped}
                    </span>
                  </span>
                  <span className="chips">
                    {IMPACT_CLASSES.filter((c) => r.proven.includes(c)).map((c) => (
                      <span key={c} className="tag tag-ok">
                        {IMPACT_LETTER[c]}
                      </span>
                    ))}
                  </span>
                </button>
              ))}
            </div>
          )}
        </>
      )}
    </>
  )
}
