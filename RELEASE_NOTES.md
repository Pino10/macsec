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

