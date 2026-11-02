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

function findingHtml(f: Finding): string {
  return `<div class="finding">
  <div class="fh"><span class="sev ${f.severity}">${f.severity.toUpperCase()}</span> <strong>${esc(f.title)}</strong>${f.verdict === 'confirmed' ? ' <span class="tag ok">Confirmed by AI</span>' : ''}</div>
  <div class="meta">${f.file ? `<code>${esc(f.file)}${f.line ? `:${f.line}` : ''}</code> · ` : ''}${esc(f.tool)}${f.cwe ? ` · ${esc(f.cwe)}` : ''}${f.advisory ? ` · ${esc(f.advisory)}` : ''}</div>
  ${f.description ? `<p>${esc(f.description).slice(0, 1500)}</p>` : ''}
  ${f.snippet ? `<pre><code>${esc(f.snippet)}</code></pre>` : ''}
  ${f.fix ? `<p class="fix"><strong>Fix:</strong> ${esc(f.fix)}</p>` : ''}
</div>`
}

export function sessionHtml(s: SessionDetail): string {
  const real = s.findings.filter((f) => f.verdict !== 'false-positive')
  const ruledOut = s.findings.length - real.length
  const reviewer = s.reviewer === 'claude' ? 'Claude Code' : s.reviewer === 'codex' ? 'Codex' : s.reviewer === 'model' ? 'Local model' : 'Scanners only'
  return `<!doctype html><html><head><meta charset="utf-8"><title>${esc(s.title)}: MacSec report</title>
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<style>
  @page { margin: 18mm 16mm; }
  body { font: 10.5pt -apple-system, 'Helvetica Neue', Arial, sans-serif; color: #15171c; line-height: 1.5; }
  h1 { font-size: 22pt; margin: 0 0 4px; letter-spacing: -0.02em; }
  h2 { font-size: 14pt; margin: 22px 0 8px; border-bottom: 1px solid #e3e5ea; padding-bottom: 4px; }
  h3, h4, h5 { font-size: 11.5pt; margin: 16px 0 6px; }
  .sub { color: #5c6270; margin-bottom: 18px; }
  .counts { display: flex; gap: 8px; margin: 12px 0 4px; }
  .count { border-radius: 8px; padding: 8px 12px; min-width: 64px; background: #f3f4f7; }
  .count b { display: block; font-size: 16pt; }
  .sev { display: inline-block; font-size: 7.5pt; font-weight: 700; letter-spacing: 0.04em; padding: 2px 6px; border-radius: 4px; color: #fff; vertical-align: 1px; }
  .critical { background: #b4232c; } .high { background: #d9480f; } .medium { background: #b7791f; } .low { background: #2f6fb3; } .info { background: #6b7280; }
  .count.critical, .count.high, .count.medium, .count.low, .count.info { color: #fff; }
  .finding { border: 1px solid #e3e5ea; border-radius: 8px; padding: 10px 12px; margin: 8px 0; page-break-inside: avoid; }
  .meta { color: #5c6270; font-size: 9pt; margin: 3px 0 4px; }
  .fix { background: #f1f8f3; border-radius: 6px; padding: 6px 8px; }
  .tag.ok { font-size: 8pt; color: #1b7a3d; }
  pre { background: #f5f6f8; border-radius: 6px; padding: 8px; overflow: hidden; white-space: pre-wrap; word-break: break-word; font-size: 8.5pt; }
  code { font-family: Menlo, monospace; font-size: 8.8pt; }
  table { border-collapse: collapse; width: 100%; font-size: 9pt; }
  td, th { text-align: left; padding: 4px 6px; border-bottom: 1px solid #eceef2; }
  .foot { margin-top: 28px; color: #8a909c; font-size: 8pt; }
</style></head><body>
<h1>${esc(s.title)}</h1>
<div class="sub">Security review · ${esc(s.target)} · ${new Date(s.createdAt).toLocaleString('en-GB', { dateStyle: 'long', timeStyle: 'short' })} · ${esc(reviewer)}${s.depth ? ` · ${esc(s.depth)} depth` : ''}${s.files ? ` · ${s.files.toLocaleString()} files` : ''}</div>
<div class="counts">${ORDER.map((k) => `<div class="count ${s.counts[k] ? k : ''}"><b>${s.counts[k]}</b>${k}</div>`).join('')}</div>
${ruledOut ? `<p class="sub">${ruledOut} scanner alarm${ruledOut === 1 ? ' was' : 's were'} checked by the AI reviewer and ruled out; they are listed at the end.</p>` : ''}
<h2>What ran</h2>
<table>${s.steps.map((st) => `<tr><td>${esc(st.label)}</td><td>${esc(st.status)}</td><td>${esc(st.detail ?? '')}</td></tr>`).join('')}</table>
${s.aiReport ? `<h2>AI review</h2>${markdownToHtml(s.aiReport)}` : ''}
<h2>All findings (${real.length})</h2>
${ORDER.map((k) => real.filter((f) => f.severity === k).map(findingHtml).join('')).join('')}
${ruledOut ? `<h2>Ruled out by the AI reviewer (${ruledOut})</h2>${s.findings.filter((f) => f.verdict === 'false-positive').map(findingHtml).join('')}` : ''}
<div class="foot">Made with MacSec. Findings come from automated tools and AI review; confirm before acting. Session ${esc(s.id)}.</div>
</body></html>`
}
