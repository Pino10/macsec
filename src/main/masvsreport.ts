/**
 * A report of a mobile check for the people who must act on it and for an auditor: what was checked and
 * how far, the OWASP MASVS 2.0 controls with their status, every finding with its evidence, how to see it
 * again and how to fix it, and what a person still has to test by hand. One self-contained HTML page: open
 * it in a browser and choose Print, Save as PDF. Nothing here sends a request.
 */
import type { Finding, MasvsInfo, SessionDetail } from '../shared/types'
import { controlsOf, sessionMasvs } from './masvs'

const esc = (s: unknown): string => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
const RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

/** OWASP Mobile Top 10 (2024) for each MASVS control group, so a report can name both. */
export const MOBILE_TOP10: Record<string, string> = {
  'MASVS-STORAGE': 'M9 Insecure Data Storage',
  'MASVS-CRYPTO-1': 'M10 Insufficient Cryptography',
  'MASVS-CRYPTO-2': 'M1 Improper Credential Usage',
  'MASVS-AUTH': 'M3 Insecure Authentication/Authorization',
  'MASVS-NETWORK': 'M5 Insecure Communication',
  'MASVS-PLATFORM': 'M8 Security Misconfiguration',
  'MASVS-CODE-1': 'M8 Security Misconfiguration',
  'MASVS-CODE-2': 'M8 Security Misconfiguration',
  'MASVS-CODE-3': 'M2 Inadequate Supply Chain Security',
  'MASVS-CODE-4': 'M4 Insufficient Input/Output Validation',
  'MASVS-RESILIENCE': 'M7 Insufficient Binary Protections',
  'MASVS-PRIVACY': 'M6 Inadequate Privacy Controls'
}
export function top10Of(controlId: string): string {
  return MOBILE_TOP10[controlId] ?? MOBILE_TOP10[controlId.replace(/-\d+$/, '')] ?? ''
}

const STATE: Record<string, string> = { found: 'Needs work', clear: 'Clear', partly: 'Partly clear', 'not-tested': 'Needs a person' }

/** How to see this finding again, in plain steps, from what the finding itself holds. */
export function reproduction(f: Finding): string[] {
  if (f.proof?.reproduce) return [`Run: ${f.proof.reproduce}`, ...(f.proof.shows ?? []).map((x) => `You should see: ${x}`)]
  const where = f.file ? `${f.file}${f.line ? ` line ${f.line}` : ''}` : 'the app'
  if (/manifest/i.test(f.tool)) return [`Unpack the app (an .apk is a zip file) and open AndroidManifest.xml, or decode it with apktool or androguard.`, `Find the setting named in the title in ${where}.`]
  if (/Info\.plist|entitlement|privacy|profile/i.test(f.tool + f.title)) return [`Unpack the .ipa (a zip file) and open the Info.plist, the embedded.mobileprovision or the PrivacyInfo.xcprivacy file.`, `Find the setting named in the title in ${where}.`]
  if (/binary/i.test(f.tool)) return [`Run otool -hv and otool -l (iOS) or readelf -l and readelf -d (Android) on ${where}.`, 'Look for the missing protection named in the title.']
  if (f.tool === 'mobsfscan') return [`Open ${where} in the source code.`, 'Or run: mobsfscan <source folder> and find the same rule.']
  if (f.category === 'secret') return [`Open ${where}. The value is kept out of this report: only its kind and place are saved.`]
  return [`Look in ${where}. ${f.description ? 'The description says what to look for.' : ''}`.trim()]
}

const confidence = (f: Finding): string => (f.confidence === 'confirmed' ? 'Confirmed: the problem itself was seen' : 'Possible: the evidence points at it but does not prove it')

function findingHtml(f: Finding): string {
  const ids = controlsOf(f)
  const evidence = [f.file ? `File: ${f.file}${f.line ? `, line ${f.line}` : ''}` : '', f.url ? `Address: ${f.url}` : '', f.cwe ? f.cwe : '', f.advisory ?? ''].filter(Boolean)
  return `<section class="f sev-${esc(f.severity)}">
<h4><span class="sev">${esc(f.severity)}</span> ${esc(f.title)}</h4>
<table>
<tr><th>MASVS</th><td>${ids.length ? ids.map(esc).join(', ') : 'Not mapped'}${ids.length ? `<br><small>${[...new Set(ids.map(top10Of).filter(Boolean))].map(esc).join('; ')}</small>` : ''}</td></tr>
<tr><th>Confidence</th><td>${esc(confidence(f))}${f.exploit ? `<br><small>${esc(f.exploit.label)}: ${esc(f.exploit.why)}</small>` : ''}</td></tr>
<tr><th>Found by</th><td>${esc(f.tool)}</td></tr>
${evidence.length ? `<tr><th>Evidence</th><td>${evidence.map(esc).join('<br>')}${f.snippet ? `<pre>${esc(f.snippet)}</pre>` : ''}</td></tr>` : ''}
${f.description ? `<tr><th>What it is</th><td>${esc(f.description).replace(/\n/g, '<br>')}</td></tr>` : ''}
${f.impact ? `<tr><th>Impact</th><td>${esc(f.impact)}</td></tr>` : ''}
<tr><th>See it again</th><td><ol>${reproduction(f).map((x) => `<li>${esc(x)}</li>`).join('')}</ol></td></tr>
<tr><th>How to fix</th><td>${esc(f.fix ?? 'See the description.')}${f.fixCode ? `<pre>${esc(f.fixCode)}</pre>` : ''}</td></tr>
${f.aiNote ? `<tr><th>Reviewer note</th><td>${esc(f.aiNote)}</td></tr>` : ''}
</table>
</section>`
}

/** The full report as an HTML page. */
export function masvsReportHtml(s: SessionDetail, version: string, masvs: MasvsInfo = sessionMasvs(s), when = new Date()): string {
  const live = s.findings.filter((f) => f.verdict !== 'false-positive' && f.triage !== 'not-a-problem')
  const real = live.filter((f) => f.severity !== 'info').sort((a, b) => RANK[a.severity] - RANK[b.severity])
  const count = (sev: string): number => real.filter((f) => f.severity === sev).length
  const steps = s.steps.map((st) => `<li>${esc(st.label)}: ${esc(st.status === 'done' ? 'done' : st.status)}</li>`).join('')
  const rows = masvs.items
    .map((i) => `<tr class="m-${i.status}"><td>${esc(i.id)}</td><td>${esc(i.name)}</td><td>${esc(STATE[i.status])}</td><td>${esc(top10Of(i.id))}</td><td>${i.findings.length ? i.findings.map((x) => esc(x.title)).join('<br>') : ''}</td></tr>`)
    .join('')
  const manual = masvs.items.filter((i) => i.status !== 'clear' && i.manual)
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Mobile security report: ${esc(s.title)}</title>
<style>
body{font:14px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#1c2333;max-width:900px;margin:32px auto;padding:0 20px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:30px 0 8px;border-bottom:2px solid #d9deeb;padding-bottom:4px}h4{font-size:15px;margin:0 0 8px}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #d9deeb;padding:6px 9px;text-align:left;vertical-align:top}th{background:#f3f5fb;width:130px}
.m table,table.m{font-size:13px}.m-found td:nth-child(3){color:#b3261e;font-weight:700}.m-clear td:nth-child(3){color:#1b7a3d;font-weight:700}.m-partly td:nth-child(3){color:#8a6100;font-weight:700}
.f{border:1px solid #d9deeb;border-radius:8px;padding:12px;margin:12px 0;break-inside:avoid}.sev{display:inline-block;text-transform:uppercase;font-size:11px;padding:2px 7px;border-radius:5px;background:#e8ebf5}
.sev-critical .sev,.sev-high .sev{background:#fbdcd9;color:#8c1d13}.sev-medium .sev{background:#fdecc8;color:#7a5200}.sev-low .sev{background:#dcefe1;color:#1b5e32}
pre{background:#f3f5fb;padding:8px;border-radius:6px;overflow:auto;white-space:pre-wrap}small{color:#586079}.box{background:#f3f5fb;border-radius:8px;padding:10px 14px}
@media print{body{margin:0}.f{break-inside:avoid}}
</style></head><body>
<h1>Mobile security report</h1>
<p><strong>${esc(s.title)}</strong><br><small>${esc(s.target ?? '')}</small><br><small>Made by MacSec ${esc(version)} on ${esc(when.toISOString().slice(0, 10))}</small></p>
<h2>Summary</h2>
<p>${real.length} ${real.length === 1 ? 'finding needs' : 'findings need'} attention: ${count('critical')} critical, ${count('high')} high, ${count('medium')} medium, ${count('low')} low.
Against OWASP MASVS 2.0: ${masvs.found} controls need work, ${masvs.clear} are clear, ${masvs.partly} are partly clear and ${masvs.notTested} need a person to test.</p>
<div class="box"><strong>How to read this.</strong> This report comes from automatic, read-only checks of the app's files. “Clear” means the checks that can see that control ran and found nothing. It is not a pass mark. Authentication, biometrics, PIN and OTP, session handling and business logic need a person with a test account, and are listed under “Still to test by hand”. It does not replace a test by an independent security team.</div>
<h2>What was checked</h2>
<ul>${steps}</ul>
<h2>OWASP MASVS 2.0</h2>
<table class="m"><tr><th>Control</th><th>What it asks</th><th>Status</th><th>Mobile Top 10</th><th>Findings</th></tr>${rows}</table>
<h2>Findings</h2>
${real.length ? real.map(findingHtml).join('') : '<p>No findings from the automatic checks.</p>'}
<h2>Still to test by hand</h2>
${manual.length ? `<ul>${manual.map((i) => `<li><strong>${esc(i.id)} ${esc(i.name)}:</strong> ${esc(i.manual)}</li>`).join('')}</ul>` : '<p>Nothing left.</p>'}
<h2>Notes</h2>
<ul><li>Information items (SDK lists, addresses, privacy details) are kept out of the list above. They are in the session in MacSec.</li><li>Values of keys and passwords are never written to a report: only their kind and place.</li><li>MASVS control names follow OWASP MASVS 2.0; mappings are made from each finding's title and its tool, and the list at mas.owasp.org/MASVS has the full text of each control.</li></ul>
</body></html>`
}
