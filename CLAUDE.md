# Notes for AI coding assistants

MacSec is a macOS security workbench (Electron 45, electron-vite, React 18, TypeScript). It reviews code
with free scanners plus an AI reviewer, and keeps every run as a session. Read MAINTAINING.md first.

## Rules

- Security first. The window is untrusted: every IPC handler in `src/main/index.ts` validates input. Project paths must be inside the www folder or picked in a dialog (`allowedProject`). Never pass user text to a shell; use `spawn`/`execFile` with argument arrays.
- Tokens live in the Keychain (`secrets.ts`), are sent only to their own service, and are redacted from logs (`logs.ts`). Clone with a one-off auth header, never a token in the URL.
- Everything MacSec writes goes under `~/MacSec` (`paths.ts`). Scanners run with `toolEnv()` so their caches stay there. Do not write anywhere else on the Mac.
- Downloads are checked against the publisher's checksum when one exists.
- AI agents run read-only. Secrets found by scanners are never stored in findings (only the kind, file and line).
- Only test what the person owns or is allowed to test; anything not on this Mac needs their confirmation. Ordinary web and API scans only read. Keep Nuclei's `NOT_READ_ONLY` tags excluded. Never run Nmap scripts (`-sC`, `--script`), and never let WPScan guess passwords or list users.
- Control confirmations (`confirmtests.ts`) are the one exception, and only when the person turns them on for that scan. They prove a problem is real so reports have no false positives: content and parameter discovery, login and authorization checks, and WAF control tests. They must always: go through `ConfirmClient` (same host only, no redirects off the host, a request cap, a pause between requests, a stop when the server struggles); send only harmless markers, never a payload that runs code or reads other people's data; never change data (GET, plus a login form POST with a made-up user); never guess real passwords or lock a real account; confirm every finding a second time before reporting it; and keep the proof (the request, a command to repeat it, what in the answer proves it). A finding that cannot be repeated is dropped, not reported.
- Business logic checks (`bizlogic.ts`) are part of the control confirmations and follow all of their rules. They send only GETs with harmless markers (a made-up address in redirect parameters, a made-up host in `X-Forwarded-Host`) signed out (`headers: 'none'`, so a link like logout cannot sign anyone out), plus ten made-up six-digit codes to a code form with no session and no real account. Prices, coupons, races and anything else that needs a data change are never tried: they are leads that say `possible`, with no proof. Proven findings are repeated once.
- Re-test (`retest.ts`) repeats only a plain GET from a proof, signed out, without following redirects, and reports what it saw; it never marks a finding fixed. Tickets (`tickets.ts`) carry no secrets; a GitHub issue uses the Keychain token, only against `api.github.com`, only for a repository the person names.
- The self-test (`selftest.ts`) listens on 127.0.0.1 only, on a random port, writes nothing to disk, and must find every planted weakness and report nothing on its decoy. Pause (`engine.ts`) stops only MacSec's own child tools and requests.
- The live phone test (`mobilelive.ts`) is the second exception, only for an Android `.apk` and only when the person picks a test phone and confirms. It may install the app on that phone, start it, and watch it with Frida, then remove it again if MacSec installed it. It must always: use `Exec` with argument arrays and validated serials and package names (`validSerial`, `validPackage`); only observe (every Frida hook calls the original and returns its answer, no bypass scripts); send no taps, typing or intents beyond launching the app; touch only the app under test; never save a secret's value (kind, file and key name only); and download Frida's server only after its SHA-256 matches the one GitHub lists. A real phone needs the person's confirmation for that phone.
- Built-app static checks (`mobilestatic.ts`) only read the file. Its online checks are opt-in, one read-only GET per Firebase, S3 or Google Storage address found (at most six of each), no redirects, names validated, and file or key names never saved.
- Ordinary scans may also run `webposture.ts` (firewall and hosting hints, DNS, and the DevOps probe list), `jsdeep.ts` (the site's own scripts and their public source maps) and `cvelive.ts` (NVD, CISA and EPSS lookups). They only GET, go through `ConfirmClient` or a same-site `allowed` check, recognise a hit by what the answer contains (never the status code alone, never an HTML page for a data probe), repeat every hit once, and keep the proof. Rebuilt source stays under the session folder, and keys found in it are stored as kind, file and first four characters only. A version match is always "possible".
- A finding may say `confirmed` only with a `proof` (`risk.ts` turns it into `possible` otherwise), and `exploit` labels (Proven, Known exploited, Likely, Not proven) are worked out there, never set by hand.
- Other attack tools (Metasploit, sqlmap, Hydra, drozer and the rest in `optional.ts`) are listed only: never install, run or control them from MacSec.
- UI and docs: plain, friendly English for non-experts. Never use em dashes; use a colon and a space instead.

## Checks before committing

```sh
npm run typecheck
npm test
npm run build
```

Add tests with real tool output for every new parser.
