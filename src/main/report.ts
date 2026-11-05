/**
 * A session as a self-contained HTML page, which Electron prints to PDF. Nothing is loaded from
 * the network, and every value from the code or a scanner is escaped.
 */
import type { Finding, SessionDetail, Severity } from '../shared/types'

export const esc = (s: unknown): string => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!)

function inline(s: string): string {
  return esc(s)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/(^|[\s(])\*([^*\s][^*]*)\*/g, '$1<em>$2</em>')
}

/** A small, safe Markdown renderer: headings, lists, code blocks, bold, inline code. */
export function markdownToHtml(md: string): string {
  const out: string[] = []
  let list: 'ul' | 'ol' | null = null
  let code: string[] | null = null
  const close = (): void => {
    if (list) out.push(`</${list}>`)
    list = null
  }
  for (const line of md.split('\n')) {
    if (code) {
      if (/^```/.test(line)) {
        out.push(`<pre><code>${esc(code.join('\n'))}</code></pre>`)
        code = null
      } else code.push(line)
      continue
    }
    if (/^```/.test(line)) {
      close()
      code = []
      continue
    }
    const h = /^(#{1,4})\s+(.*)$/.exec(line)
    if (h) {
      close()
      const sev = /^\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s*(.*)$/i.exec(h[2])
      out.push(sev ? `<h${h[1].length + 1}><span class="sev ${sev[1].toLowerCase()}">${sev[1]}</span> ${inline(sev[2])}</h${h[1].length + 1}>` : `<h${h[1].length + 1}>${inline(h[2])}</h${h[1].length + 1}>`)
      continue
    }
    if (/^\s*\|.*\|\s*$/.test(line)) {
      close()
      if (/^\s*\|[\s:|-]+\|\s*$/.test(line)) continue
      const cells = line.trim().slice(1, -1).split('|').map((c) => inline(c.trim()))
      const prev = out[out.length - 1]
      if (prev?.endsWith('</table>')) out[out.length - 1] = prev.replace('</table>', `<tr>${cells.map((c) => `<td>${c}</td>`).join('')}</tr></table>`)
      else out.push(`<table><tr>${cells.map((c) => `<th>${c}</th>`).join('')}</tr></table>`)
      continue
    }
    const li = /^\s*([-*]|\d+\.)\s+(.*)$/.exec(line)
    if (li) {
      const kind = /\d/.test(li[1]) ? 'ol' : 'ul'
      if (list !== kind) {
        close()
        out.push(`<${kind}>`)
        list = kind
      }
      out.push(`<li>${inline(li[2])}</li>`)
      continue
    }
    close()
    if (line.trim()) out.push(`<p>${inline(line)}</p>`)
  }
  close()
  if (code) out.push(`<pre><code>${esc((code as string[]).join('\n'))}</code></pre>`)
  return out.join('\n')
}

const ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
const COLOR: Record<Severity, string> = { critical: '#e11d5c', high: '#ea580c', medium: '#ca8a04', low: '#2563eb', info: '#64748b' }
const WEIGHT: Record<Severity, number> = { critical: 25, high: 10, medium: 4, low: 1, info: 0 }
const score = (c: Record<Severity, number>): number => Math.max(0, Math.round(100 - 100 * (1 - Math.exp(-ORDER.reduce((n, k) => n + c[k] * WEIGHT[k], 0) / 60))))

function contextHtml(f: Finding): string {
  if (!f.context) return f.snippet ? `<pre class="code">${esc(f.snippet)}</pre>` : ''
  return `<pre class="code">${f.context.lines.map((l, i) => {
    const n = f.context!.start + i
    return `<span class="ln${n === f.context!.at ? ' hit' : ''}"><i>${n}</i>${esc(l) || ' '}</span>`
  }).join('')}</pre>`
}

function findingHtml(f: Finding): string {
  return `<div class="finding" style="--c:${COLOR[f.severity]}">
  <div class="fh"><span class="sev">${f.severity.toUpperCase()}</span><h4>${esc(f.title)}</h4>${f.verdict === 'confirmed' ? '<span class="ok">Confirmed by AI</span>' : ''}</div>
  <div class="meta">${f.file ? `<code>${esc(f.file)}${f.line ? `:${f.line}` : ''}</code>` : ''}<span>${esc(f.tool)}</span>${f.cwe ? `<span>${esc(f.cwe)}</span>` : ''}${f.advisory ? `<span>${esc(f.advisory)}</span>` : ''}</div>
  ${f.description ? `<p>${esc(f.description).slice(0, 1500)}</p>` : ''}
  ${contextHtml(f)}
  ${f.why || f.aiNote ? `<p><b>Why it is rated ${f.severity}:</b> ${esc(f.why ?? f.aiNote)}</p>` : ''}
  ${f.impact ? `<p><b>Impact:</b> ${esc(f.impact)}</p>` : ''}
  ${f.fix || f.fixCode ? `<div class="fix"><b>How to fix</b>${f.fix ? `<p>${esc(f.fix)}</p>` : ''}${f.fixCode ? `<pre class="code">${esc(f.fixCode)}</pre>` : ''}</div>` : ''}
  ${f.verify ? `<p class="verify"><b>How to verify:</b> ${esc(f.verify)}</p>` : ''}
</div>`
}

export function sessionHtml(s: SessionDetail): string {
  const real = s.findings.filter((f) => f.verdict !== 'false-positive')
  const ruledOut = s.findings.length - real.length
  const reviewer = s.reviewer === 'claude' ? 'Claude Code' : s.reviewer === 'claude-local' ? 'Claude Code on a local model' : s.reviewer === 'claude-free' ? 'Claude Code on Free LLM API' : s.reviewer === 'gemini' ? 'Gemini CLI' : s.reviewer === 'codex' ? 'Codex' : s.reviewer === 'model' ? 'Local model' : 'Scanners only'
  const kind = s.kind === 'web-scan' ? 'Web scan' : s.kind === 'api-scan' ? 'API security review' : s.kind === 'mobile-scan' ? 'Mobile app check' : s.kind === 'recon' ? 'Recon' : s.kind === 'audit' ? 'Security audit' : 'Code review'
  const total = ORDER.reduce((n, k) => n + s.counts[k], 0) || 1
  const sc = score(s.counts)
  return `<!doctype html><html><head><meta charset="utf-8"><title>${esc(s.title)}: MacSec report</title>
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<style>
  @page { margin: 16mm 15mm; }
  body { font: 10.5pt -apple-system, 'Helvetica Neue', Arial, sans-serif; color: #111827; line-height: 1.55; margin: 0; }
  .cover { margin: -16mm -15mm 0; padding: 22mm 15mm 14mm; color: #fff; background: radial-gradient(60% 90% at 0% 0%, #0e7490 0%, transparent 60%), radial-gradient(60% 80% at 100% 0%, #6d28d9 0%, transparent 60%), radial-gradient(50% 70% at 80% 100%, #be185d 0%, transparent 60%), #0b1020; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .cover small { opacity: .75; font-size: 10pt; }
  .cover h1 { font-size: 28pt; margin: 6px 0 4px; letter-spacing: -0.02em; }
  .cover .sub { opacity: .8; }
  .score { display: flex; align-items: center; gap: 22px; margin-top: 20px; }
  .score b { font-size: 46pt; line-height: 1; }
  .bar { display: flex; height: 8px; border-radius: 8px; overflow: hidden; background: rgba(255,255,255,.15); margin-top: 16px; }
  .counts { display: flex; gap: 22px; margin-top: 10px; }
  .counts div b { display: block; font-size: 18pt; }
  .counts div span { font-size: 9pt; opacity: .8; text-transform: capitalize; }
  h2 { font-size: 15pt; margin: 26px 0 10px; padding-bottom: 6px; border-bottom: 2px solid #e5e7eb; letter-spacing: -0.01em; }
  h3, h4, h5 { margin: 14px 0 6px; }
  .finding { border: 1px solid #e5e7eb; border-left: 4px solid var(--c); border-radius: 10px; padding: 12px 14px; margin: 10px 0; page-break-inside: avoid; }
  .fh { display: flex; align-items: center; gap: 10px; }
  .fh h4 { margin: 0; font-size: 11.5pt; flex: 1; }
  .sev { font-size: 7.5pt; font-weight: 700; letter-spacing: .04em; color: #fff; background: var(--c); padding: 2px 7px; border-radius: 5px; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .ok { font-size: 8pt; color: #047857; font-weight: 600; }
  .meta { display: flex; flex-wrap: wrap; gap: 12px; color: #6b7280; font-size: 9pt; margin: 6px 0; }
  .code { background: #0b1020; color: #dbeafe; border-radius: 8px; padding: 8px 0; font: 8.6pt Menlo, monospace; white-space: pre-wrap; word-break: break-word; overflow: hidden; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .code .ln { display: block; padding: 0 10px; }
  .code .ln i { display: inline-block; width: 34px; color: #64748b; font-style: normal; }
  .code .hit { background: rgba(225, 29, 92, .28); }
  .fix { background: #ecfdf5; border-radius: 8px; padding: 8px 12px; margin-top: 8px; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .fix .code { margin-top: 6px; }
  .verify { color: #374151; }
  table { border-collapse: collapse; width: 100%; font-size: 9.5pt; }
  td, th { text-align: left; padding: 5px 8px; border-bottom: 1px solid #eef0f3; vertical-align: top; }
  th { color: #6b7280; font-weight: 600; }
  .ai pre { background: #0b1020; color: #dbeafe; border-radius: 8px; padding: 10px; font: 8.6pt Menlo, monospace; white-space: pre-wrap; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .foot { margin-top: 28px; color: #9ca3af; font-size: 8pt; }
</style></head><body>
<div class="cover">
  <small>${esc(kind)} by MacSec</small>
  <h1>${esc(s.title)}</h1>
  <div class="sub">${esc(s.target)}<br>${new Date(s.createdAt).toLocaleString('en-GB', { dateStyle: 'long', timeStyle: 'short' })}, ${esc(reviewer)}${s.depth || s.mode ? `, ${esc(s.depth ?? s.mode)}` : ''}${s.files ? `, ${s.files.toLocaleString()} files` : ''}</div>
  <div class="score"><b>${sc}</b><div>Security posture out of 100<br><small>${real.length} open findings${ruledOut ? `, ${ruledOut} ruled out by the AI reviewer` : ''}</small></div></div>
  <div class="bar">${ORDER.filter((k) => s.counts[k]).map((k) => `<span style="width:${(s.counts[k] / total) * 100}%;background:${COLOR[k]}"></span>`).join('')}</div>
  <div class="counts">${ORDER.map((k) => `<div><b>${s.counts[k]}</b><span>${k}</span></div>`).join('')}</div>
</div>
${s.aiReport ? `<div class="ai">${markdownToHtml(s.aiReport)}</div>` : ''}
<h2>All findings (${real.length})</h2>
${ORDER.map((k) => real.filter((f) => f.severity === k).map(findingHtml).join('')).join('')}
${ruledOut ? `<h2>Ruled out by the AI reviewer (${ruledOut})</h2>${s.findings.filter((f) => f.verdict === 'false-positive').map((f) => `<p><b>${esc(f.title)}</b> <code>${esc(f.file ?? '')}${f.line ? `:${f.line}` : ''}</code><br>${esc(f.aiNote ?? '')}</p>`).join('')}` : ''}
<h2>What ran</h2>
<table><tr><th>Step</th><th>Result</th></tr>${s.steps.map((st) => `<tr><td>${esc(st.label)}</td><td>${esc(st.status)}${st.detail ? `: ${esc(st.detail)}` : ''}</td></tr>`).join('')}</table>
<div class="foot">Made with MacSec. Findings come from automated tools and AI review; confirm before acting. Secrets are masked. Session ${esc(s.id)}.</div>
</body></html>`
}
