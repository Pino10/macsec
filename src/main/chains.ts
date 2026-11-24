/**
 * How findings connect. Small problems become serious when they are used together: a public Git
 * folder and a key in it, a way to find real accounts and no limit on guessing their passwords.
 *
 * A chain is only shown when every part of it was found, and it says what it is: a story built from
 * the findings, not a test that the chain works. Every chain also names the one fix that breaks it,
 * because "fix this first" is more useful than a list of ten equal findings.
 */
import type { Chain, Finding, Severity } from '../shared/types'
export type { Chain }

interface Rule {
  id: string
  name: string
  story: string
  /** What the parts add up to, in one line. */
  impact: string
  needs: RegExp[]
  /** Which part to break first: the cheapest one that removes the path. */
  breakWith: RegExp
  /** The single fix that breaks the path. */
  breakHint: string
}

const RULES: Rule[] = [
  {
    id: 'files-to-keys',
    name: 'Exposed files lead to stolen keys',
    story: 'A file that should not be public is readable, and a key or password was also found. Anyone who reads the file can use the key.',
    impact: 'An attacker reads the file, takes the key, and uses it against whatever it opens: a database, a cloud account, or a mail service.',
    needs: [/(Git folder|\.git|\.env|backup|dump|\.sql|state file|public file found|file that should not be public)/i, /(key|token|password|credential|secret)/i],
    breakWith: /(Git folder|\.git|\.env|backup|dump|\.sql|state file|public file found|file that should not be public)/i,
    breakHint: 'Remove the file from the web folder or deny it in the web server, then rotate every key it held. The key finding alone does not help an attacker until the file is readable.'
  },
  {
    id: 'source-to-api',
    name: 'Front-end source shows how to attack the API',
    story: 'The original source code can be rebuilt from the public source map, and it names routes or keys. An attacker reads the code to find every API call and the weak ones, instead of guessing.',
    impact: 'Every hidden route, feature flag and API call becomes known, and the slowest part of an attack (finding the endpoints) is done for free.',
    needs: [/Source map public/i, /(routes|GraphQL|endpoint|original source|in public JavaScript)/i],
    breakWith: /Source map public/i,
    breakHint: 'Stop publishing .map files to production (productionBrowserSourceMaps: false in Next.js, build.sourcemap: false in Vite), or upload them only to your error tracker.'
  },
  {
    id: 'enumerate-then-guess',
    name: 'Find a real account, then guess its password',
    story: 'The site tells an attacker which accounts exist, and does not limit wrong guesses. Together that is a straight path to taking over an account with a weak password.',
    impact: 'Account takeover with a password list, without ever touching the victim.',
    needs: [/(usernames exist|emails have an account)/i, /(does not slow down|wrong (codes|passwords)|ten wrong codes)/i],
    breakWith: /(does not slow down|wrong (codes|passwords)|ten wrong codes)/i,
    breakHint: 'Limit failed sign-ins per account and per address (five tries, then a growing delay or a captcha), and alert on bursts. The enumeration alone is much less useful without a guessing window.'
  },
  {
    id: 'infra-takeover',
    name: 'Open build or cluster tools put the servers at risk',
    story: 'A tool that controls servers or builds is reachable from the internet, and there are secrets or no sign-in around it. Taking it over usually means taking over what it manages. MacSec only reads: it never signs in or runs a pipeline.',
    impact: 'Whoever reaches the tool can run builds, read every secret the pipeline holds, and often reach the production servers behind it.',
    needs: [/(Jenkins|Docker API|Kubernetes|etcd|Consul|container registry|Traefik|Argo CD|Portainer|Elasticsearch)/i, /(credentials|state file|secret|token|password|AWS|Terraform|open without|without sign-in)/i],
    breakWith: /(Jenkins|Docker API|Kubernetes|etcd|Consul|container registry|Traefik|Argo CD|Portainer|Elasticsearch)/i,
    breakHint: 'Put the tool behind your sign-in and off the public internet (VPN or address allowlist), then rotate the secrets it can see.'
  },
  {
    id: 'exploited-no-shield',
    name: 'Software that attackers use, with nothing in front of it',
    story: 'A version listed as exploited in the wild is exposed with no firewall or CDN recognised in front. Patching it is the first fix. A firewall would only slow an attacker down.',
    impact: 'Known, working exploitation code is public for this flaw, and nothing is filtering the attempts.',
    needs: [/on CISA's exploited list/i, /No web firewall or CDN was recognised/i],
    breakWith: /on CISA's exploited list/i,
    breakHint: 'Update the software to a fixed version now. Everything else is secondary for a flaw that is already being exploited.'
  },
  {
    id: 'xss-to-session',
    name: 'Script injection can steal sessions',
    story: 'Input is written into a page unescaped, and a session cookie can be read by scripts. A script an attacker injects can then send the cookie away.',
    impact: 'One clicked link takes over the visitor\'s session, including an administrator\'s.',
    needs: [/Input comes back in the page without escaping/i, /Cookie ".*" is missing .*HttpOnly/i],
    breakWith: /Input comes back in the page without escaping/i,
    breakHint: 'Escape output for the place it is used, then set HttpOnly on the session cookie. Either fix breaks the path; both are worth doing.'
  },
  {
    id: 'ids-to-data',
    name: 'Numbered records and open access to them',
    story: 'Records are numbered, and another account can open private pages. An attacker can count through the numbers and read every record.',
    impact: 'Mass disclosure one record at a time, which nobody notices because each request looks normal.',
    needs: [/Records are numbered in the address/i, /(Another account can open|Shows the same content when signed out)/i],
    breakWith: /(Another account can open|Shows the same content when signed out)/i,
    breakHint: 'Check on the server, for every request, that the signed-in user may see that exact record. Unpredictable ids do not fix it; the ownership check does.'
  },
  {
    id: 'hidden-admin',
    name: 'Hidden admin screens that answer',
    story: 'The front end names private routes and an admin page answers. Hidden is not protected: check that the server refuses anyone who is not an administrator.',
    impact: 'An attacker who reads the JavaScript finds the admin screens, and the interface hiding them stops nobody.',
    needs: [/The front end names \d+ routes, \d+ look private/i, /(Hidden page found|Another account can open an admin page|admin)/i],
    breakWith: /(Hidden page found|Another account can open an admin page|admin)/i,
    breakHint: 'Put every admin route behind a server-side role check. Removing the link from the menu does not help.'
  },
  {
    id: 'redirect-phish',
    name: 'Your own address can send people to a fake page',
    story: 'An open redirect on your own address plus a login page makes a convincing phishing link: it starts on your real site and ends on theirs.',
    impact: 'Credential phishing that looks legitimate, and it borrows your domain\'s reputation.',
    needs: [/Open redirect/i, /(Login|login|sign.?in|password)/i],
    breakWith: /Open redirect/i,
    breakHint: 'Only allow redirect targets from a fixed list, or only relative paths. The login page can stay as it is.'
  },
  {
    id: 'poison-reset',
    name: 'Password reset links can be pointed at an attacker',
    story: 'The site builds links from a header the visitor controls, and it has a password reset. If the reset email uses the same link, an attacker can receive the reset token.',
    impact: 'An attacker can trigger a reset for a victim and receive the link, which is account takeover.',
    needs: [/trusts a forwarded host/i, /(Password reset|forgot|reset)/i],
    breakWith: /trusts a forwarded host/i,
    breakHint: 'Build absolute addresses from a fixed setting (APP_URL), not from request headers, and tell your framework which proxies to trust.'
  },
  {
    id: 'upload-to-active-content',
    name: 'A file upload that can host content',
    story: 'Uploads are accepted and served from the site\'s own address, and files are written where the browser will render them. A person who can upload can put their own page, and often their own script, on your domain.',
    impact: 'Stored cross-site scripting on your own domain, used against administrators and customers, or malware hosting under your name.',
    needs: [/(upload|attachment|avatar|media|file was written)/i, /(readable|HTML|script|stored|served)/i],
    breakWith: /(upload|attachment|avatar|media)/i,
    breakHint: 'Accept only the file types you need, scrub them, and serve them from a separate domain (or with Content-Disposition: attachment) so a file can never run as a page on your main domain.'
  },
  {
    id: 'secret-to-cloud',
    name: 'A key that opens a cloud account',
    story: 'A key or token was found, and the same scan found cloud storage or a cloud service it can reach. A leaked cloud key is usually worth more than the website it was found on.',
    impact: 'Read or write access to buckets, databases or AI APIs, billed to you, with no sign-in needed.',
    needs: [/(key|token|secret|credential)/i, /(Firebase|S3|bucket|Google Storage|cloud|AWS|Azure)/i],
    breakWith: /(key|token|secret|credential)/i,
    breakHint: 'Revoke the key, then move it out of the client and into a server-side setting. Deleting the file is not enough: the key is already in caches, logs and archives.'
  },
  {
    id: 'debug-to-secrets',
    name: 'A debug page that hands over the internals',
    story: 'A debug console, stack trace or phpinfo page is readable, and the same scan found secrets or database details. Debug output is a map of the system, and it sometimes includes the credentials.',
    impact: 'An attacker learns the framework, paths, database, and sometimes a live key, which turns guesswork into a plan.',
    needs: [/(debug|stack trace|error page|phpinfo|actuator|console|_profiler)/i, /(key|token|secret|password|database|credential)/i],
    breakWith: /(debug|stack trace|error page|phpinfo|actuator|console|_profiler)/i,
    breakHint: 'Turn debug output off in production and return a plain error page. Rotate anything the page exposed.'
  },
  {
    id: 'cors-to-data',
    name: 'Any website can read your users\' data',
    story: 'The server repeats any Origin it is given, allows credentials, and answers with real user data. A page on an attacker\'s site can then read the data of any visitor who is signed in to yours.',
    impact: 'Cross-site data theft straight from the browser, with no password needed.',
    needs: [/(Cross-origin|CORS|Any website can read)/i, /(signed-in|private|account|data|fields)/i],
    breakWith: /(Cross-origin|CORS|Any website can read)/i,
    breakHint: 'Allow only an exact list of your own origins, and never combine credentials with a reflected Origin.'
  },
  {
    id: 'graphql-to-tenant',
    name: 'A GraphQL API that trusts the account it is asked about',
    story: 'A GraphQL endpoint is open to queries, and account or record data can be read for someone else. GraphQL makes the whole data model reachable through one address, so one missing check covers everything.',
    impact: 'Cross-account data access across the whole schema, not only the fields the app uses.',
    needs: [/GraphQL/i, /(Another account|own data|record|IDOR|signed in as)/i],
    breakWith: /GraphQL/i,
    breakHint: 'Authorize in every resolver, not in the client, and test each operation with a second account.'
  },
  {
    id: 'no-limit-to-takeover',
    name: 'No limit on guessing, and an account to guess',
    story: 'Wrong passwords are answered without any limit, and the site reveals or exposes real accounts. One weak password is enough.',
    impact: 'Account takeover by password spraying, which stays under most alerting that only watches volume.',
    needs: [/(does not slow down|no limit|wrong passwords|wrong guesses)/i, /(admin|account|sign-in|login|username)/i],
    breakWith: /(does not slow down|no limit|wrong passwords|wrong guesses)/i,
    breakHint: 'Rate-limit sign-ins per account and per address, and add a second factor for administrators. The exposed account list on its own is much less dangerous.'
  }
]

const ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical']
const open = (f: Finding): boolean => f.verdict !== 'false-positive' && !f.triage

export function chainsOf(findings: Finding[]): Chain[] {
  const list = findings.filter(open)
  const out: Chain[] = []
  const seen = new Set<string>()
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
    // Overlapping rules can describe the same pair of findings: show it once.
    const signature = members.map((m) => m.id).sort().join('|')
    if (seen.has(signature)) continue
    seen.add(signature)
    const confidence: Chain['confidence'] = members.every((m) => m.confidence === 'confirmed' || !!m.proof) ? 'likely' : 'possible'
    const worst = Math.max(...members.map((m) => ORDER.indexOf(m.severity)))
    const breaker = members.find((m) => r.breakWith.test(m.title)) ?? members[0]
    out.push({
      id: r.id,
      name: r.name,
      story: r.story,
      impact: r.impact,
      members: members.map((m) => ({ id: m.id, title: m.title, severity: m.severity, fix: m.fix })),
      severity: ORDER[Math.min(ORDER.length - 1, worst + 1)],
      confidence,
      breakAt: { id: breaker.id, title: breaker.title, fix: r.breakHint }
    })
  }
  return out.sort((a, b) => ORDER.indexOf(b.severity) - ORDER.indexOf(a.severity))
}
