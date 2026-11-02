import { useState } from 'react'
import { FileJson, Plug, Radar, Upload } from 'lucide-react'
import type { ApiAuth, ApiSpecInfo, Reviewer, ScanMode } from '@shared/types'
import { useApp } from '../store'
import { FlowStep, PageHead, Seg } from '../ui'
import ReviewerChoice from '../components/ReviewerChoice'
import { MODES } from './WebScan'

const FORMAT = { postman: 'Postman collection', openapi: 'OpenAPI', swagger: 'Swagger', har: 'Recorded traffic (HAR)' }
const API_MODES = MODES.map((m) => ({ ...m, text: m.id === 'quick' ? 'Reviews the file and makes ordinary requests to 25 endpoints.' : m.id === 'standard' ? 'Up to 120 endpoints, plus Nuclei’s checks for exposed docs and settings.' : 'Up to 500 endpoints, everything included.' }))

export default function ApiSecurity(): React.JSX.Element {
  const { settings, act, busy, showSession } = useApp()
  const api = window.macsec
  const [spec, setSpec] = useState<ApiSpecInfo | null>(null)
  const [base, setBase] = useState('')
  const [auth, setAuth] = useState<ApiAuth>({ kind: 'bearer', value: '' })
  const [mode, setMode] = useState<ScanMode>('standard')
  const [reviewer, setReviewer] = useState<Reviewer>(settings?.reviewer ?? 'none')
  const [ok, setOk] = useState(false)
  const target = base.trim() || spec?.baseUrl || ''
  const local = /^https?:\/\/(localhost|127\.|[^/]+\.(test|localhost))/.test(target)
  const valid = /^https?:\/\/[^\s/]+/.test(target)

  return (
    <>
      <PageHead title="API security" desc="Load the file that describes your API. MacSec reviews what it says, then makes ordinary GET requests signed in as you to see what the API gives away. Nothing is sent that could change data." />
      <div className="flow">
        <FlowStep n={1} title="The API" help="A Postman collection, an OpenAPI or Swagger file, or a HAR recording from your browser." state={spec ? 'done' : 'current'}>
          {spec ? (
            <div className="pick-list" style={{ maxHeight: 'none' }}>
              <div className="pick-item" aria-selected style={{ cursor: 'default' }}>
                <FileJson size={17} style={{ color: 'var(--threat)' }} />
                <span className="grow">
                  {spec.name}
                  <span className="sub">
                    {FORMAT[spec.format]}, {spec.endpoints.length} endpoints, {spec.endpoints.filter((e) => e.method === 'GET').length} of them GET
                  </span>
                </span>
                <button className="btn btn-sm" onClick={() => setSpec(null)}>
                  Change
                </button>
              </div>
            </div>
          ) : (
            <button
              className="pick-list"
              style={{ display: 'grid', placeItems: 'center', gap: 8, padding: '34px 20px', cursor: 'pointer', color: 'var(--ink-2)', textAlign: 'center' }}
              onClick={async () => {
                const s = await act('spec', () => api.invoke('api:load-spec'))
                if (s) {
                  setSpec(s)
                  setBase('')
                }
              }}
            >
              <span className="glyph" style={{ ['--g' as string]: '#ff3d7f' }}>
                <Upload size={20} />
              </span>
              <strong style={{ color: 'var(--ink)', fontFamily: 'var(--display)' }}>{busy.has('spec') ? 'Reading…' : 'Load a Postman collection, OpenAPI file or HAR file'}</strong>
              <span className="hint">.json, .yaml or .har. A copy is kept in MacSec so you can test it again.</span>
            </button>
          )}
        </FlowStep>

        {spec && (
          <>
            <FlowStep n={2} title="Where it runs, and who you are" help="Point it at staging if you can. Your token is used for this test only and never saved." state={valid ? 'done' : 'current'}>
            <div className="two">
              <div className="field">
                <span className="field-label">Address</span>
                <input className="input mono" placeholder={spec.baseUrl || 'https://api.example.com'} value={base} onChange={(e) => setBase(e.target.value)} aria-label="API address" />
                <span className="field-help">Leave empty to use the one in the file{spec.baseUrl ? ` (${spec.baseUrl})` : ''}.</span>
              </div>
              <div className="field">
                <span className="field-label">Sign in as you</span>
                <Seg<ApiAuth['kind']>
                  label="Sign-in"
                  value={auth.kind}
                  onChange={(k) => setAuth({ ...auth, kind: k })}
                  options={[
                    ['bearer', 'Bearer token'],
                    ['header', 'API key header'],
                    ['none', 'None']
                  ]}
                />
                {auth.kind !== 'none' && (
                  <div style={{ display: 'grid', gridTemplateColumns: auth.kind === 'header' ? '160px 1fr' : '1fr', gap: 8 }}>
                    {auth.kind === 'header' && <input className="input mono" placeholder="X-API-Key" value={auth.header ?? ''} onChange={(e) => setAuth({ ...auth, header: e.target.value })} aria-label="Header name" />}
                    <input className="input mono" type="password" autoComplete="off" placeholder={auth.kind === 'bearer' ? 'Your token' : 'Your key'} value={auth.value ?? ''} onChange={(e) => setAuth({ ...auth, value: e.target.value })} aria-label="Token" />
                  </div>
                )}
              </div>
            </div>
            </FlowStep>

            <FlowStep n={3} title="How much to cover" state="current">
              <div className="choices" role="radiogroup" aria-label="Mode">
                {API_MODES.map((m) => (
                  <button key={m.id} className="choice" role="radio" aria-checked={mode === m.id} onClick={() => setMode(m.id)}>
                    <span className="ci" style={{ ['--g' as string]: '#ff3d7f' }}>
                      {m.icon}
                    </span>
                    <strong>{m.title}</strong>
                    <span>{m.text}</span>
                  </button>
                ))}
              </div>
            </FlowStep>

            <FlowStep n={4} title="Who writes the report" state="current">
              <ReviewerChoice value={reviewer} onChange={setReviewer} what="findings" />
            </FlowStep>

            {valid && !local && (
              <label className="consent">
                <input type="checkbox" checked={ok} onChange={(e) => setOk(e.target.checked)} />
                <span>
                  <strong style={{ color: 'var(--ink)' }}>I own this API, or have written permission to test it.</strong>
                </span>
              </label>
            )}
          </>
        )}

        <div className="flow-go glass">
          <span className="hint grow">{spec ? (valid ? `Tests ${target}` : 'Enter the API’s address.') : 'Start by loading the file.'}</span>
          <button
            className="btn btn-primary btn-lg"
            disabled={!spec || !valid || (!local && !ok) || busy.has('api')}
            onClick={async () => {
              const s = await act('api', () => api.invoke('api:start', { spec: spec!.id, baseUrl: base.trim(), auth, mode, authorized: ok, reviewer }))
              if (s) showSession(s.id)
            }}
          >
            <Radar size={16} /> Start review
          </button>
        </div>
      </div>
      {spec && (
        <>
          <h2 className="section-title">Endpoints in the file</h2>
          <div className="panel" style={{ maxHeight: 340, overflow: 'auto' }}>
            {spec.endpoints.slice(0, 300).map((e, i) => (
              <div key={i} className="row" style={{ padding: '9px 18px' }}>
                <span className="tag" style={{ minWidth: 62, justifyContent: 'center', color: e.method === 'GET' ? 'var(--ok)' : e.method === 'DELETE' ? 'var(--bad)' : 'var(--warn)' }}>
                  {e.method}
                </span>
                <span className="grow mono" style={{ color: 'var(--ink-2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {e.url}
                </span>
                {e.name && <span className="hint">{e.name}</span>}
              </div>
            ))}
          </div>
        </>
      )}
      <p className="hint" style={{ marginTop: 14 }}>
        <Plug size={12} style={{ verticalAlign: -2 }} /> For hands-on testing of the same API, open Burp Suite from the Web scan page.
      </p>
    </>
  )
}
