/**
 * The catalogue of controlled proofs. Every entry is a bound, not a wish: it names what it sends,
 * what it proves, the most requests it can ever send, and how it cleans up.
 *
 * There is deliberately no "shell", no file dump, no password guessing, no persistence, no payload
 * delivery and no evasion. A proof here is the smallest thing that makes an impact real.
 */
import type { ImpactActionId, ImpactActionInfo } from '../../shared/impact'

export const IMPACT_ACTIONS: ImpactActionInfo[] = [
  {
    id: 'traversal-read',
    name: 'Read a system file through a parameter',
    what: 'Takes one parameter of one page and asks for the system files a path traversal would reach. A proof is the shape of the file in the answer, never the file itself.',
    impact: ['confidentiality'],
    sends: 'Up to 10 GET requests: the page with one parameter set to a traversal path for a system file (/etc/passwd, /etc/hosts, C:\\Windows\\win.ini), then one repeat of the hit.',
    never: 'No other files, no backup files, no database, no download of what came back. The answer is hashed and described, not kept.',
    maxRequests: 10,
    writes: false,
    cleanup: 'Nothing to undo: only reads.',
    risk: 'Low. The requests are ordinary GETs with a path in a parameter. A web firewall may log them.',
    needs: ['url', 'param']
  },
  {
    id: 'ssti-marker',
    name: 'Show the server evaluates what a parameter says',
    what: 'Sends the arithmetic a template engine would calculate ({{7*7}} and its variants) and looks for 49 in the answer, with the expression itself gone. That is what a server-side template injection looks like at its smallest.',
    impact: ['integrity'],
    sends: 'Up to 8 GET requests: the page with one parameter set to a template expression, then one repeat of the hit.',
    never: 'No command, no file read, no object walk, no gadget chain. Only arithmetic that the engine itself computes.',
    maxRequests: 8,
    writes: false,
    cleanup: 'Nothing to undo: only reads.',
    risk: 'Very low. Arithmetic in a parameter cannot change data on its own.',
    needs: ['url', 'param']
  },
  {
    id: 'upload-write',
    name: 'Write one file and read it back',
    what: 'Uploads a single small text file with a made-up name, then fetches it from the address you give. A proof is the file coming back with its marker, which proves write access to the public file store.',
    impact: ['integrity'],
    sends: 'One multipart POST with a file of about 80 bytes, and up to two GET requests to read it back. One DELETE attempt to remove it.',
    never: 'No script, no executable, no HTML, no overwrite of an existing file, no path outside the upload directory you name.',
    maxRequests: 4,
    writes: true,
    cleanup: 'Tries DELETE on the address you gave. If the site does not allow it, the run says exactly where the one file is and how to remove it by hand. It is always the only file written.',
    risk: 'Medium. This changes the site: one file with a random name, removed again if the site allows it.',
    needs: ['url', 'param', 'verifyUrl']
  },
  {
    id: 'availability-probe',
    name: 'Measure one request against three',
    what: 'Times the page twice, then asks for it three more times, one at a time, and compares. A proof is one request taking several times as long as its baseline, which is what an expensive or unbounded operation looks like. It never floods anything.',
    impact: ['availability'],
    sends: 'At most 5 sequential GET requests over about 6 seconds. No concurrency, no retries, no load.',
    never: 'No flood, no parallel load, no cache bypass, no long-running request, no request with a larger body than the page itself.',
    maxRequests: 5,
    writes: false,
    cleanup: 'Nothing to undo: only reads, and it stops the moment the server pushes back.',
    risk: 'Medium. It is the only proof that asks a server to do work five times. It stops on the first 429, 503 or timeout.',
    needs: ['url']
  },
  {
    id: 'content-discovery',
    name: 'Find the pages nothing links to',
    what: 'Asks the site for hundreds of common paths with ffuf (signed out, no redirects, its own calibration), then asks again for each path that answered, so a hit is confirmed and not a page that answers 200 for everything.',
    impact: ['confidentiality'],
    sends: 'Up to 435 GET requests at 20 a second, then one GET for each of the first 15 paths that answered. No redirects are followed and no cookie or token is sent.',
    never: 'No fuzzing of parameters, no POST, no bypass of the firewall, no recursion into other hosts, and no request after the cap.',
    maxRequests: 450,
    writes: false,
    cleanup: 'Nothing to undo: only reads.',
    risk: 'Medium. It is several hundred ordinary GETs in under half a minute, from this Mac. A firewall will log it; a small host may feel it. Run it in a quiet moment.',
    needs: ['url']
  },
  {
    id: 'auth-bypass',
    name: 'Read a private page with no credentials',
    what: 'Asks for a page that normally needs a sign-in with no cookie and no token, and looks for the string you name (your own email, an order number, a name only a signed-in person sees). This is the step from "the page is private" to "anyone can read it".',
    impact: ['confidentiality'],
    sends: 'Two GET requests with no credentials, then the run stops.',
    never: 'No cookie, no token, no session of yours, no guessing of passwords.',
    maxRequests: 2,
    writes: false,
    cleanup: 'Nothing to undo: only reads.',
    risk: 'Very low. Two ordinary anonymous requests.',
    needs: ['url', 'expect']
  },
  {
    id: 'sql-injection-proof',
    name: 'Ask sqlmap if one parameter is injectable',
    what: 'Runs sqlmap against one parameter in its careful fingerprint mode: risk 1, level 1, boolean and error techniques only. A proof is sqlmap naming the parameter and the technique. It does not extract data.',
    impact: ['confidentiality'],
    sends: 'One sqlmap run, at most 80 requests, one thread, 15 second timeout, no retries. GET only, and only the parameter you name.',
    never: 'No dump, no --sql-shell, no --os-shell, no file read or write, no time-based or UNION extraction, no tamper scripts, no forms, no credential testing.',
    maxRequests: 80,
    writes: false,
    cleanup: 'Nothing to undo: sqlmap only asks. MacSec deletes its session folder for the run.',
    risk: 'Medium. sqlmap sends real injection payloads to the one parameter. A firewall will log them, and a fragile app may answer with errors. It is the standard way to prove an injection without taking data.',
    needs: ['url', 'param']
  },
  {
    id: 'replay-request',
    name: 'Send the exact request you paste',
    what: 'Sends one request you wrote or copied from Burp: method, address, headers and body. A proof is a string you name appearing in the answer. This is the escape hatch for anything the built-in proofs do not cover.',
    impact: ['confidentiality', 'integrity'],
    sends: 'Exactly one request, once. Nothing is retried or varied.',
    never: 'No loops, no fuzzing, no payloads MacSec invents. What you paste is what is sent.',
    maxRequests: 1,
    writes: true,
    cleanup: 'You say how to undo it before it runs. If it changes data, the run records that it did and asks you to confirm the undo step was done.',
    risk: 'High. It does exactly what you paste, so what it changes is your responsibility and the engagement has to allow integrity.',
    needs: ['request', 'expect']
  }
]

const BY_ID = new Map(IMPACT_ACTIONS.map((a) => [a.id, a]))

export const actionInfo = (id: ImpactActionId): ImpactActionInfo => {
  const a = BY_ID.get(id)
  if (!a) throw new Error(`Unknown controlled proof: ${String(id)}`)
  return a
}

export const actionIds = (): ImpactActionId[] => IMPACT_ACTIONS.map((a) => a.id)
