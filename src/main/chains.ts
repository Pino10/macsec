/**
 * How findings connect. Small problems become serious when they are used together: a public Git
 * folder and a key in it, a way to find real accounts and no limit on guessing their passwords.
 * A chain is only shown when every part of it was found, and it says what it is: a story built
 * from the findings, not a test that the chain works.
 */
import type { Chain, Finding, Severity } from '../shared/types'
export type { Chain }


interface Rule {
  id: string
  name: string
  story: string
  needs: RegExp[]
}

const RULES: Rule[] = [
  { id: 'files-to-keys', name: 'Exposed files lead to stolen keys', needs: [/(Git folder|\.git|\.env|backup|dump|\.sql|state file|public file found|file that should not be public)/i, /(key|token|password|credential|secret)/i], story: 'A file that should not be public is readable, and a key or password was also found. Anyone who reads the file can use the key. Rotate the key first, then remove the file.' },
  { id: 'source-to-api', name: 'Front-end source shows how to attack the API', needs: [/Source map public/i, /(routes|GraphQL|endpoint|original source|in public JavaScript)/i], story: 'The original source code can be rebuilt from the public source map, and it names routes or keys. An attacker reads the code to find every API call and the weak ones, instead of guessing.' },
  { id: 'enumerate-then-guess', name: 'Find a real account, then guess its password', needs: [/(usernames exist|emails have an account)/i, /(does not slow down|wrong (codes|passwords)|ten wrong codes)/i], story: 'The site tells an attacker which accounts exist, and does not limit wrong guesses. Together that is a straight path to taking over an account with a weak password.' },
  { id: 'infra-takeover', name: 'Open build or cluster tools put the servers at risk', needs: [/(Jenkins|Docker API|Kubernetes|etcd|Consul|container registry|Traefik|Argo CD|Portainer|Elasticsearch)/i, /(credentials|state file|secret|token|password|AWS|Terraform|open without|without sign-in)/i], story: 'A tool that controls servers or builds is reachable from the internet, and there are secrets or no sign-in around it. Taking it over usually means taking over what it manages.' },
  { id: 'exploited-no-shield', name: 'Software that attackers use, with nothing in front of it', needs: [/on CISA's exploited list/i, /No web firewall or CDN was recognised/i], story: 'A version listed as exploited in the wild is exposed with no firewall or CDN recognised in front. Patching it is the first fix. A firewall would only slow an attacker down.' },
  { id: 'xss-to-session', name: 'Script injection can steal sessions', needs: [/Input comes back in the page without escaping/i, /Cookie ".*" is missing .*HttpOnly/i], story: 'Input is written into a page unescaped, and a session cookie can be read by scripts. A script an attacker injects can then send the cookie away.' },
  { id: 'ids-to-data', name: 'Numbered records and open access to them', needs: [/Records are numbered in the address/i, /(Another account can open|Shows the same content when signed out)/i], story: 'Records are numbered, and another account can open private pages. An attacker can count through the numbers and read every record.' },
  { id: 'hidden-admin', name: 'Hidden admin screens that answer', needs: [/The front end names \d+ routes, \d+ look private/i, /(Hidden page found|Another account can open an admin page|admin)/i], story: 'The front end names private routes and an admin page answers. Hidden is not protected: check that the server refuses anyone who is not an administrator.' },
  { id: 'redirect-phish', name: 'Your own address can send people to a fake page', needs: [/Open redirect/i, /(Login|login|sign.?in|password)/i], story: 'An open redirect on your own address plus a login page makes a convincing phishing link: it starts on your real site and ends on theirs.' },
  { id: 'poison-reset', name: 'Password reset links can be pointed at an attacker', needs: [/trusts a forwarded host/i, /(Password reset|forgot|reset)/i], story: 'The site builds links from a header the visitor controls, and it has a password reset. If the reset email uses the same link, an attacker can receive the reset token.' }
]

const ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical']
const open = (f: Finding): boolean => f.verdict !== 'false-positive' && !f.triage

export function chainsOf(findings: Finding[]): Chain[] {
  const list = findings.filter(open)
  const out: Chain[] = []
  for (const r of RULES) {
    const parts = r.needs.map((re) => list.filter((f) => re.test(f.title)))
    if (parts.some((p) => !p.length)) continue
    // Each need must be met by a different finding.
    const used = new Set<string>()
    const members: Finding[] = []
    let ok = true
    for (const p of parts) {
      const pick = p.find((f) => !used.has(f.id))
      if (!pick) {
        ok = false
        break
      }
      used.add(pick.id)
      members.push(pick)
    }
    if (!ok) continue
    const worst = Math.max(...members.map((m) => ORDER.indexOf(m.severity)))
    out.push({ id: r.id, name: r.name, story: r.story, members: members.map((m) => ({ id: m.id, title: m.title, severity: m.severity })), severity: ORDER[Math.min(ORDER.length - 1, worst + 1)] })
  }
  return out.sort((a, b) => ORDER.indexOf(b.severity) - ORDER.indexOf(a.severity))
}
