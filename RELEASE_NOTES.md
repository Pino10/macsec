## 1.15.0

- **ffuf is in the toolbox.** On the Web scan page, "Content discovery with ffuf" asks for 200 to 435 common paths at 20 a second, signed out, with ffuf's own calibration. Every path that answers is asked again by MacSec and reported only with a proof, and each one joins the pages the scan tests next. Your own lists in `~/MacSec/extensions/wordlists/*.txt` are used first. ffuf is free, comes from its own GitHub release and is checked against the checksum its authors publish.
- **The ladder: read, then write, then proof.** Controlled proofs now plan as a chain: a write step is marked to run only after a read on the same site is proven, and the run still stops at the first proof of each goal. Two new rungs: content discovery under an engagement, and an anonymous read that proves a private page opens with no cookie and no token.
- **Fill in what only you know.** A plan step can be edited before it runs: the string that proves it, the address to read an uploaded file back from, the method, headers and body of a request you paste, and the undo sentence. MacSec re-validates every field on the server, so the plan a run uses is the plan you approved.
- **Request caps stay true.** Requests ffuf sends on your behalf are counted against the engagement in one audited line, so a discovery run cannot hide inside a proof.
- **Tests.** 35 in the controlled-proof suite now, including discovery with an injected ffuf, the anonymous read, the ladder ordering, and the refusals.

Limits, on purpose: still no shells, no data dumps, no password guessing, no persistence and no evasion. Metasploit-driven exploitation and a headless CLI for CI are the next pieces.

## 1.14.0

- **Controlled proofs.** A new page proves what someone could actually do on a site you are engaged to test, and stops at the first result. It needs a written engagement first: client, authority reference, who gave it, the hosts it covers, the window, and caps for requests and writes. Every step says in advance what it sends, what it aims to prove and what it will not do. You tick the steps, type `EXPLOIT <host>`, and the run sends requests one at a time, logs each one with the values hidden, and stops when the goal is proven. Four built-in proofs: read a system file through a parameter (confidentiality), template arithmetic (integrity), write one file and read it back (integrity), and time one request against three (availability). The fifth is the escape hatch: paste any request and name the string that proves it.
- **CIA, said out loud.** Every proof aims at confidentiality, integrity or availability. The run reports which of the three was proven, and says which was not. A report can no longer imply impact it did not show.
- **Chaining and escalation, planned cheaply.** Planning uses the findings already on this Mac, with no AI call at all. The optional AI planner sees only a short digest of findings, is called once, and can only pick steps from the catalogue: MacSec validates every field, so a model cannot invent a payload or a host. A step can chain from another, a read before a write on the same page, and the run stops as soon as each goal is proven.
- **The engagement is the gate.** No engagement, no run. Revoking one stops everything. The caps are counted from the runs stored on disk, so restarting the app does not reset the budget. Write steps also need the leftover acknowledgement, and every write is removed again or listed with exactly where it is.
- **Metasploit's check list is scanners only now.** The exploit modules were removed from it: several of them run code during their check (Shellshock and Struts2 do), so calling it "check only" was not true. A test now refuses exploit names in both lists.
- **Smaller fixes.** A window that fails to draw shows an error panel with a copy button instead of going blank. Deleting a session takes two clicks. The input validators moved to `src/main/validate.ts`, so they can be tested without Electron.

Limits, on purpose: no shells, no data dumps, no password guessing, no persistence, no evasion and no concurrency. The availability proof is a measured slowdown, never a flood. Metasploit-driven exploitation (approved modules with command payloads, a callback for the proof) and a headless CLI for CI are the next pieces.

## 1.13.0

- **Watch an app's network traffic.** On the Mobile apps page, install mitmproxy with one button (free, stays inside MacSec), start listening, point your own test phone or emulator at it, use the app, and press Stop. MacSec then lists plain http, passwords and tokens sent in the clear, secrets in web addresses, cookies without the Secure flag and every server the app talked to, each with proof. You can also check a .har file you already have (from Burp, Charles or a browser).
- **Safe by design.** MacSec only listens on this Mac or its own local network address, never changes your phone, deletes the capture file as soon as it has been read, and keeps only names, never values.
- Limits: an empty capture does not prove certificate pinning, and Android apps from Android 7 on may ignore the capture certificate unless the test build allows it.

## 1.12.0

- **DKIM checks.** For a domain that sends mail, MacSec looks up the common DKIM selectors and reports keys that are too short (under 1024 bits), keys of 1024 bits, withdrawn keys and keys left in test mode. Each comes with the DNS record as proof. A selector that is not found says nothing, because DKIM has no public list of selectors.
- **DNSSEC check.** MacSec asks Cloudflare's public DNS service (the domain name only) whether the domain is signed. An unsigned domain is shown as an information note, never as a confirmed problem.

Still not built: KICS and Amass (their download files could not be checked here, so they are not added blind; Checkov and Hadolint already cover infrastructure files), LinkFinder and SecretFinder (the script scan already reads a site's own scripts), SQLFluff (a style linter, not a security tool), virtual host discovery, and the bigger AI items.

## 1.11.0

- **Safer scans.** A network guard now sits in front of every confirmation test. It stops a scan if a site name points at a cloud metadata address, answers with a mix of public and private addresses, or switches from public to private halfway through (DNS rebinding).
- **One finding, not three.** When two tools report the same problem in the same place, MacSec shows it once and says "Also found by" the others. Proofs are never merged away.
- **How sure are we?** Every finding now says Confirmed, Likely, Suspected, Unverified or Ruled out, and shows its OWASP ASVS chapter when the weakness type is clear.
- **Accuracy score.** A small scorer counts hits, misses and false alarms (precision and recall) for a check against a known bad and a known good sample. It is used in tests.

Not in this release: CodeQL (its licence does not allow free use on private or commercial code), Joern, KICS, Amass, LinkFinder, SecretFinder, SQLFluff, DNSSEC and DKIM checks, virtual host discovery, source-to-sink data flow, AI agents for IDOR and business logic, an AI verification agent, patch generation, and one database with attack paths across all engines. The guard covers confirmation tests; the web posture and script checks do not use it yet.

## MacSec 1.10.0

DeepSeek is now a choice in every reviewer list, and mobile checks can produce a full report.

### What is new
- **DeepSeek in the reviewer lists.** Once the DeepSeek servers and your key are saved (Tools, Model servers), "Claude Code on DeepSeek" and "DeepSeek (API)" appear in the reviewer choice of code review, web scan, API scan, mobile and recon. One click sets the server and the model, so nothing else has to be chosen first. Both say that the code or findings are sent to DeepSeek.
- **MASVS report.** On a mobile check, Export now has "MASVS report". It is one page you open and save as a PDF (Print, then Save as PDF): the summary, what was checked, all 24 MASVS controls with their status and the OWASP Mobile Top 10 category, every finding with its confidence, evidence, steps to see it again and how to fix it, and a list of what a person must still test by hand. Values of keys and passwords are never in it.

### Not in this release
- JADX, Apktool, Ghidra and LIEF, iOS and Android runtime testing (emulator, Simulator, Frida, Objection, traffic capture), the Burp connection and the AI that investigates decompiled code. These need tools and devices that MacSec cannot try here, and several would need new safety rules first. They come one at a time, each tested before it ships.

## MacSec 1.9.0

Mobile checks now cover more file types and more of the app, and the app shows which OWASP MASVS controls are met.

### What is new
- **OWASP MASVS 2.0 checklist.** On every mobile check, the OWASP tab now starts with all 24 MASVS controls (storage, crypto, authentication, network, platform, code, resilience, privacy). Each one says **Needs work** (with the findings), **Clear** (the checks that can see it ran and found nothing), **Partly clear** (nothing found, but a person must still test part of it) or **Needs a person** (no automatic check can see it, such as biometrics, PIN and OTP flows, session handling and business logic). Controls a person must test say what to do by hand. "Clear" is not a pass mark for the app.
- **More app files.** Besides .apk and .ipa: Android App Bundles (.aab), .apks sets (the base .apk is read) and Xcode archives (.xcarchive). An Xcode project folder works as source.
- **Deep links.** Custom link schemes that other apps can claim, and web links that open the app without verification.
- **Entitlements and privacy.** A Keychain group shared with every app of your team, universal links and shared sign-in domains, and the iOS privacy manifest (missing, or declaring tracking).
- **Third-party SDKs.** The SDKs found in the app (analytics, advertising, crash, payments, support, session replay), with a warning for tracking ones in a banking app.
- **Addresses in the app.** The full web addresses written into the code, with the API-looking ones first, as the starting map for API testing.
- **Vulnerable libraries in source.** Source projects now also run osv-scanner on their library lists.

### Limits
- The .aab manifest reader was tested on a manifest built by hand to the aapt2 format, not on a real store bundle. If a bundle's manifest cannot be read, the check says so.
- For an .aab or .apks, signing is not checked (the store signs a bundle itself) and the network rules file is not decoded.
- SDK names are found from names in the code: an obfuscated app can hide some of them.
- Not in this release: running the app on an Android emulator or the iOS Simulator, Burp traffic interception, Objection and a PDF report. The live test is still Android only, on a phone you confirm.

## MacSec 1.8.1

DeepSeek works with Claude Code, and online models are shown as online.

### What is new
- **DeepSeek for Claude Code.** A new ready-made server, "DeepSeek for Claude Code" (Tools, Model servers), uses the same DeepSeek key in the format Claude Code speaks. Add it, pick its model, then choose the reviewer "Claude Code on your model". The key stays in the Keychain and is handed to Claude Code only for that run. The existing "DeepSeek" server still works for the reviewer "Your model" (the API).
- **Online models are labelled.** When the chosen model is not on this Mac, the reviewer list moves it to the online group and says that the code is sent to the provider, instead of "Nothing leaves this Mac".

### Limits
- Not tried against a live DeepSeek account here. The model names (deepseek-v4-pro, deepseek-v4-flash) come from DeepSeek's documentation; if DeepSeek renames them, pick another name in the list.

## MacSec 1.8.0

MacSec now knows what firewalls do to confuse a scanner, remembers what you tell it is not a problem, and checks library versions more carefully.

### What is new
- **Firewall and decoy knowledge.** Shields such as Imperva, Cloudflare, Akamai, F5, AWS, Sucuri and Wordfence are recognised by their headers, cookies and block pages. When one address shows a crowd of open ports (or many database, mail and remote-access ports at once), MacSec reports one info finding instead of dozens, keeps only the web ports and does not run service checks on the rest. When four or more sensitive file names answer at once (trace.axd, db.sql, .env and so on), they are turned down to info as "probably a decoy" and one summary says why. Nothing is hidden: you can still read each one.
- **See it, then say "this is not it".** Keys found in a site's scripts now show the line they were found on, with every value cut to its first four characters and its length. Example values (YOUR_API_KEY, xxxx, AKIA...EXAMPLE and the like) are turned down to info on their own. Source maps and keys that belong to public libraries (jQuery, Bootstrap, files from a public CDN, node_modules) are turned down to info too.
- **Not a problem, remember.** On any finding, choose "Not a problem, remember" (this site) or "on every site". Later scans mark it "Not a problem" and stop counting it. The list is in Settings, with a button to report it again. Only the finding's id or title and place are kept, never a secret value.
- **Library versions and series.** A version is only checked against known flaws if it fits a series that exists (Bootstrap 1 to 5, jQuery 1 to 4 and so on). When a file name and the code's own banner disagree, MacSec says so and uses the code. Each library says which series it belongs to and whether that series still gets fixes.
- **Find My Mac.** MacSec now reads your iCloud account settings as well as the system flag, and says "could not tell" instead of "off" when the two do not agree. The account format is written from documentation, not tested on every Mac.
- **This Mac.** The "Fix these first" panel is now a tidy numbered list, in the same style as the rest of the page.
- **AI helpers no longer load your own tools.** The AI helpers MacSec starts now run with `--strict-mcp-config`, so Claude Code does not start the MCP servers from your own setup. This is the most likely reason a tool such as Serena opened its dashboard in your browser while MacSec ran an AI review. It is not proven: another program can start it too.

### Limits
- Decoy detection is by pattern. A real server with many open ports, or a real site with several backup files, can look like a decoy: those are listed as info with the reason, not hidden.
- MacSec still never installs Metasploit or other attack tools. If it is installed, the checks run as before.

## MacSec 1.7.0

Sign-in protocols, tokens, GraphQL and cross-site checks, an AI autopilot, and Metasploit with approval for every module.

### What is new
- **OAuth and OpenID Connect checks** (a new switch in the web scan's control confirmations). MacSec reads the sign-in links a site sends and the provider's own settings page, and reports: no state value, a state that never changes, the implicit flow, no PKCE, an http callback, tokens in addresses, "none" signatures, "plain" PKCE and open client registration. On a provider that is on the site itself, it also sends made-up callback addresses (ending in .invalid, which cannot exist) and reports a server that redirects to them. Nothing is signed in and no outside provider is contacted.
- **Token (JWT) checks.** Tokens from your own sign-in are read for a missing signature, a weak signing secret (the secret is never written down), no expiry or a very long one, secrets in the claims, a token cookie without HttpOnly, tokens in addresses and in public pages. MacSec also sends your own token back with its signature removed and with "alg: none" (claims unchanged, GET only) to a page that treats you differently from a visitor, to see whether the server checks signatures.
- **GraphQL checks.** Finds endpoints, an open schema (introspection), an open IDE (GraphiQL, Playground), field suggestions when introspection is off, stack traces in errors, mutations accepted over GET, form content types that skip the CORS check, and batching. It only asks questions: mutations are refused in code, and nothing deep, wide or long is sent.
- **CORS, CSRF and session ids.** CORS that repeats a made-up origin with credentials allowed (higher when signed in), forms with no anti-forgery token (a lead, never submitted), session ids in links, and a server that keeps a session id the visitor made up.
- **Autopilot.** After the normal steps, the AI reads what was found and picks up to 14 more checks from a fixed menu, in up to three rounds, following leads as they appear. MacSec validates and runs each one with its own rules and proof. The AI never sends a request or writes a finding.
- **Metasploit with approval.** The server scan now lists every module with what it sends and what could go wrong, and nothing runs unless you tick it. There are two kinds: Metasploit's own checks for known flaws, and look-only scanners that read a version, banner, title, methods or certificate. No exploit, login, brute force or flood module exists in the lists.
- Your checklist now marks OAuth, JWT, GraphQL and CORS items from these checks. Items these checks can only find (CSRF, session ids) are never marked "clear" for you.
- New check ids: MS-OAUTH, MS-JWT, MS-GQL, MS-CORS, MS-CSRF, MS-SESS and MS-AI.

### Honest limits
- Only providers that are part of the site itself get callback tests: a site that signs in with Google, Microsoft or Okta is tested for what it sends, not for what the provider does.
- CSRF and session fixation after a login need a form to be submitted or a login to be made, so they are leads for you to test by hand.
- GraphQL depth, size and batching limits are left for you to test on a copy: they can bring a server down.
- The Metasploit module names and output lines were written from its documentation and not tried against a real install here. A module that is missing or prints something unexpected gives no finding.
- None of this was run against a real third-party site. It was tested against local servers with a weak and a hardened version of each case.

## MacSec 1.6.0

Deeper testing everywhere: web scan with black box and white box, a checklist walk, injection tests, a deeper This Mac, deeper recon, deeper server scans and a safe Metasploit check.

### What is new
- **Web scan: black box or white box.** Black box tests the site from outside. White box also reads the code folder you pick, finds every route and parameter, and tries the private routes signed out to prove which ones are open.
- **Injection tests on every page and form.** After a login, MacSec reads the pages it can reach and tries each input with harmless markers: unescaped output, a database error from a lone quote, a server that calculates a sent expression, and a line break reaching a header. Every hit is repeated and keeps its proof. POST forms are listed, never submitted.
- **Walk my checklist.** Your own checklist (52 sections, 638 items) is walked item by item. MacSec marks what it tested itself, the AI reviewer you chose (including your Claude login) judges the rest using only the evidence found, and anything unproven stays manual. A new Checklist tab shows it all.
- **This Mac, much deeper.** Root and admin accounts, screen lock, login window, secrets in files and shell history (never shown), .env files, XProtect age, third-party extensions, rejected apps, outdated Homebrew packages, SSH server settings, cron jobs, Wi-Fi security, saved open Wi-Fi, internet sharing, DNS servers, and a "Fix these first" panel.
- **Deeper recon.** Each host gets its own headers, TLS, protection and banner checks, DevOps probes, DNS takeover signs and live CVE lookups.
- **Server scans with depth.** Each open service is asked for its version and checked against live CVE data, data stores that answer without a password are proven, and web services behind other ports are tested as web apps.
- **Metasploit, check only.** Optional switch on the server scan. A fixed list of modules, only the module's own `check`, never run or exploit. Proven results keep the command as proof.
- **Removed the self-test** from the app (it was confusing). It now lives only in the test suite.

### Honest limits
- POST forms and bugs that need a data change are listed as leads, not proven.
- The Metasploit module names were not tried against a real install here: a module that is missing is reported as unsupported, never as a finding.
- The This Mac checks were tested with sample output, not on a real Mac.
- Real WAF and real phone behaviour are still unverified.

## MacSec 1.5.0

Business logic checks, a risk score for everything you test, and ways to hand findings on.

### What is new
- **Business logic checks** (a new switch in the web scan's control confirmations). It proves what can be proven without changing anything: an open redirect (a made-up address in "next" or "return" is followed), a site that writes a forwarded host name into links (password reset poisoning), and a code or PIN form that accepts ten wrong codes in a row. It also lists leads for you to test by hand: prices, roles and ids sent as hidden form fields, late steps of a checkout that open on their own, and numbered records. A lead says "possible" and has no proof, and nothing that would change data is ever tried.
- **Quick choices** for the control confirmations: public site, login and accounts, shop or booking flow.
- **Assets.** A new page with one line per site, API, domain, app or project: a risk score from 0 to 100, how it moved scan by scan, how many days fixes took, and what to fix first.
- **Fix these first.** On every result: the few actions that take off the most risk, with the score before and after.
- **How these connect.** Small problems that become serious together (an open Git folder and a key in it, a way to find accounts and no limit on guesses) are shown as a chain, only when every part was found.
- **Check ids.** Every kind of finding has a stable id (for example MS-WEB-001) shown on the finding, so reports and re-tests can name it.
- **Re-test one finding** without running the whole scan: it repeats the proof request and tells you if it is still there, changed or gone. It never marks anything fixed by itself.
- **Copy as a ticket** (Markdown or Jira text) and **create a GitHub issue** with the token already in your Keychain.
- **Pause and resume** a running test.
- **Quiet hours** for automatic checks.
- **A one-page summary PDF** for people who decide.
- **A self-test** on the Tools page: MacSec starts a deliberately weak local app and a correct look-alike, and every planted weakness must be found with nothing reported on the correct one.

### Honest limits
- Real business logic bugs that need a data change (a price changed in transit, a coupon used twice, a race) are never proven by MacSec. You get leads and a test plan.
- Jira is copy-as-text only. Recorded login replay is not built.
- Pause stops the tools and MacSec's own requests, but a tool's own timeout keeps counting.

## MacSec 1.4.0

A JavaScript analyzer, the setup behind a site, live vulnerability counts, and an honest label on every finding.

### What is new
- **Every finding says how far it is proven.** Proven (a harmless request showed it, and the proof can be repeated), Known exploited (the version is on CISA's list), Likely (a high chance of use) or Not proven (a lead). Each has a risk score from 0 to 100 and a one-line reason, and the report header counts them. Nothing runs an exploit: "proven" means the problem itself was seen and you can repeat it with the command in the proof.
- **A guard against over-claiming.** A finding that says "confirmed" without proof is turned into "possible" before it is saved.
- **The JavaScript analyzer.** For web scans and recon: it reads every script the site serves, follows lists of hidden chunks (lazy admin screens), and names the routes, API endpoints, GraphQL operations and build variables. It finds public source maps, rebuilds the original source into the session folder (with an "Open the rebuilt source" button) and looks for keys in it. It also flags message listeners that never check the sender, internal addresses, developer comments about security, and cloud storage names. A new "JavaScript map" tab shows it all.
- **The setup behind a site.** Which firewall or CDN answers, what hosts it, SPF, DMARC and CAA, and a CNAME that points at a service nobody owns any more. DevOps and infrastructure left open: Jenkins, Grafana, Prometheus, Kibana, Elasticsearch, Consul, etcd, Kubernetes, Docker, container registries, Traefik, Argo CD, Portainer, RabbitMQ, SonarQube, Terraform state, cloud credentials and CI files. The public .git folder is read for the GitHub repository it names and for a password in its address. API scans get the same checks around the API.
- **Live vulnerability counts.** Versions found in server banners, scripts and the DevOps tools are looked up in the public NVD database, marked when they are on CISA's known-exploited list, and given FIRST's EPSS chance of use. The count is always a version match, so it says "possible".
- **A test plan for APIs**, like the one web scans already get, and the same expert notes in the AI report.
- **A cleaner AI choice.** Grouped as "On this Mac", "Cloud AI" and "No AI", one line each, with the detail of the chosen one shown below.

### How it stays safe
- All of it is GET requests, to the site itself, with a request cap, a pause between requests and a stop when the server struggles.
- A hit is recognised by what the answer contains, never by the status code, and a data probe refuses an HTML page. Every hit is repeated once, and one that does not repeat is dropped.
- Tests build sites designed to fool the checks (random content on every page, everything forbidden, everything sent to login, everything echoed back) and make sure nothing false is reported.

## MacSec 1.3.0

Deeper app checks from the file alone, a test plan from your own checklist, and Invariant's knowledge in the AI report.

### What is new
- **Apps are checked from the file, with no phone needed.** For an `.apk` or `.ipa`, MacSec now reads the app's compiled code and signing: certificate pinning present or missing, root and jailbreak checks, certificate checks that accept everything, weak encryption (ECB, DES, RC4, MD5, SHA-1), WebView risks, old TLS, plain `http` addresses, every server the app names, the old v1-only signature, and the Android debug certificate. Facts such as signing are confirmed with proof. What the code merely names is marked "possible", because it may be unused. The live phone test is still there for what only a running app shows.
- **Online checks for cloud addresses (optional).** Tick the box on the Mobile apps page and MacSec asks once, read only, about each Firebase database, S3 bucket and Google Storage bucket found inside the app. An open database or a listing bucket is confirmed with a command you can repeat. File and key names are never saved.
- **A test plan for every web scan.** Your web assessment checklist is built in (52 sections, 638 items). After the crawl, MacSec works out what kind of site it is (login, sign-up, one-time codes, password reset, profile, upload, checkout, GraphQL, API, admin and more) and writes a plan of what to try by hand, in order, with the items it already tested marked. It is saved with the session and shown under the report.
- **Invariant's knowledge and skills in the AI report.** 151 expert notes (authorization, authentication, business logic, APIs, mobile and more) are matched to what was found and given to the AI, together with four method skills: verify with proof, find hypotheses from invariants, check novelty and impact, and write the report. The report now ends with "What to try next".

### How it stays safe
- The static checks only read the file. The online checks are off by default and make at most six read-only requests per kind, never following a redirect.
- Nothing from the checklist or notes is sent anywhere by MacSec: they are only text given to the AI you chose.

## MacSec 1.2.0

The live phone test: run an Android app on a test phone and watch what it really does.

### What is new
- **Run it on a test phone (optional, Android .apk).** On the Mobile apps page, tick "Also run this app on a test phone", choose an emulator or a phone you own, and confirm you may test the app. MacSec installs the app, starts it, watches it for about half a minute, and removes it again if it installed it.
- **What it proves.** Servers the app talks to, and any request sent over plain HTTP. Whether certificate pinning is in use. Whether the app checks for a rooted phone. Passwords and tokens written to the phone's log, and passwords and tokens kept in plain text in the app's own files. Each finding has proof you can repeat with an `adb` command, and secret values are never saved, only the kind, the file and the name.
- **Frida only watches.** Every hook calls the original and returns what it returned, so the app behaves as normal. Frida is installed into MacSec the first time it is needed, and its server file for the phone is only used after its checksum matches the one GitHub lists.
- **Test phones.** MacSec lists your emulators and starts one with a click. If Android's tools are installed, "Build a test phone" makes one from a Google APIs image (which allows root, needed for Frida), downloading the image if it is missing.

### How it stays safe
- Off by default. You confirm per app and per phone.
- No taps, typing or buttons are sent to the app, so nothing is bought, posted or deleted. Only the app under test is touched.
- A real phone must be confirmed as yours. Without root, only the log is read and Frida is not used.

### Good to know
- Only the first seconds of the app are watched, because nothing is tapped. Pinning that happens later is not seen, so "no pinning seen" is marked as possible, not confirmed.
- Not in this release: iOS live testing, and testing whether pinning can be bypassed (which needs a proxy). One-time codes, session fixation and sign-out replay are also still to come.

## MacSec 1.1.0

Control confirmations: optional checks that prove a problem is real, so a finding is never a guess.

### What is new
- **Hidden pages and parameters.** Tries a list of common names to find pages and settings that are not linked from the site. A site that answers "found" to everything is detected and ignored. Every hit is asked for twice, and secret values in files such as `.env` are never copied into a finding, only the names.
- **Web firewall tests.** Names the firewall that answers, shows what it blocks, and sends harmless look-alike strings to see if one gets past it. A bypass is only reported when the string comes back in the page unchanged, so the owner can tighten the rule. Input that comes back unescaped is reported as confirmed cross-site scripting risk.
- **Login checks.** Eight wrong guesses for a user that does not exist (so no real account is touched) to see if anything slows them, and whether the login or the "forgot password" form reveals which accounts exist. Your own account is tried with two wrong passwords at most.
- **Two-account access check.** With a second account's cookie, compares what each account can open. A finding is "confirmed" when the first account's own details show up in the page the second account received, and signed out the page is refused.
- Every finding keeps its proof: the request, a command to repeat it, and what in the answer proves it. Cookies and tokens are never put in a proof or saved.

### How it stays safe
- Off by default. You switch each check on for one scan and confirm you may test the site.
- Same site only, no redirects followed to other sites, a request limit, a pause between requests, and an automatic stop if the server starts to struggle.
- Only harmless markers are sent. Nothing is changed, nothing is guessed at scale, and links that could sign you out or delete something are never opened.
- A finding that cannot be repeated is dropped, not reported.

### Not in this release
- Checks for one-time codes, session fixation and sign-out replay, and the live phone-app tests (SSL pinning and similar). These need a test device or more care, so they come next.

## MacSec 1.0.0

Version 1.0: a full review of every screen, with the app made clearer and more honest about what it knows.

### An honest score
- Under the score, MacSec now says what it is based on and what was never tested, with a link to each missing test. A good score only covers what was tested.
- **Fix these first**: the three most serious open findings sit next to the score.
- **Getting safer?**: a small line for each project you tested more than once, showing whether its score went up or down.
- The number of open findings now matches the list. Findings the AI ruled out are left out of that number, and hidden info notes are named with a link to show them.

### Clearer findings
- **Explain simply** (Settings): leads with what could happen and what to do, in everyday words, with the technical detail folded away.
- **Fix this one with Claude Code** on each finding, and **Copy as an issue** for GitHub, Jira or wherever you track work. Secrets are never copied.

### First run, and nothing downloaded without asking
- A welcome step explains what will be installed. Skill sets from other security teams are a tick box: they are no longer downloaded on their own.
- The badge at the top no longer says "Engine ready" when no scanner is installed.

### Shorter pages
- Tools is now four tabs (Scanners, AI, Skills, Extras) and the 43 skills are one line with "Show all".
- Sessions is now called Results. Logs moved into Settings as "Logs for support".
- Deep audit is a choice card next to Standard review.
- This Mac runs its check the first time you open it.
- Test a project fully: its code and its live site in one go, from the Overview.

### Look
- A light look, five accent colours and a larger text size, in Settings.
- MacSec in the menu bar: the score, and any test that is running.
- The progress pop-up no longer covers the Start button.

