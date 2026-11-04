## MacSec 0.5

### Recon (new)
Map what a domain exposes before you test it:
- subdomains from certificate logs, subfinder and the Wayback Machine
- DNS, with possible subdomain takeovers
- which hosts answer and what they run
- old URLs and their parameters
- every script checked for **source maps** (indexed maps too), endpoints and keys (masked)
- a few files that should never be public

Choose Passive (nothing is sent to the site), Standard or Deep. The AI write-up is an attack surface map with leads for manual testing. A **Hosts and scripts** tab keeps the whole map. Read-only, and domains that are not on your Mac need your confirmation.

### More reviewers
- **Claude Code on your own model:** Claude Code with all its tools and MacSec's skills, talking to your LM Studio model through its Anthropic-compatible API (LM Studio 0.4.1 or newer). Nothing leaves your Mac.
- **Gemini CLI**, in read-only plan mode.

### Skills everywhere
The skills now include recon, JavaScript recon, attack surface reports and reviewing with local models. They are shared with Laramac. **Install for Claude** on Tools copies them into ~/.claude/skills, so Claude Code in Terminal and in the Claude desktop app can use them in any session.

## MacSec 0.4

### Watch every test as it runs
A running test now shows the step it is on, how long it has taken, a progress bar with the real percentage when the tool reports one (Nuclei, for example), the tool's latest line in plain words, and a live output panel. The top bar and the session list show the step and percentage too. When a tool has to be installed first, the step says so.

### Mobile apps
A new **Mobile apps** page, and a Mobile app option in Special audits. Check Android and iOS apps from source or a built .apk or .ipa:
- **mobsfscan** (MobSF's rules) on source code
- the Android manifest: debuggable builds, backups, plain HTTP, very old Android, and activities, services and providers any app can open (a built .apk is decoded with **Androguard**)
- Info.plist: App Transport Security turned off, file sharing, URL schemes
- how the compiled code is hardened: PIE, stack canaries, NX, RELRO, ARC and App Store encryption
- keys and passwords left in the app

### Cloud accounts and servers
- **Cloud account** audit for Azure or AWS: **ScoutSuite** against best practice, **CloudFox** for what the account exposes and, on AWS, **PMapper** for users and roles that could raise their own access. Only reads. Sign in to Azure from MacSec; the sign-in stays in your MacSec folder.
- **Server and ports** check: **naabu** finds the open ports, **Nmap** (when installed) names the service on each, and MacSec says which ones should not be reachable from the internet. Servers that are not on your Mac need your confirmation.

### WordPress
Web scans of WordPress sites add **WPScan** when you have it installed: the version, plugins and themes, with their known problems and exposed backups. Passive only.

### Every inspect-only tool from T3MP3ST
New on Tools: mobsfscan, Androguard, ScoutSuite, Azure CLI, AWS CLI, CloudFox, PMapper, naabu, plus Nmap, WPScan and the Google Cloud CLI when you have them. radare2 and Ghidra are listed for reading compiled apps by hand.

### The attack tools, listed
Tools now lists the attack tools that were in the T3MP3ST pack (Metasploit, sqlmap, ffuf, Dalfox, Hydra, hashcat, John the Ripper, Pacu, Frida, objection, drozer, GDB with pwndbg) with their official sites. MacSec does not install, run or control them: install one yourself if you need it for a test you are authorised to do.

### A new logo
A glass shield with a radar and the engine's iris. It sweeps in the sidebar while a test runs.

### Safer
An audit of MacSec itself:
- tool output is redacted before it is shown live or saved with the session
- built apps are unpacked with macOS's tar, which refuses paths that escape the session folder, and links inside an app are never followed
- an app's own file names cannot point MacSec at files outside it
- server names are checked so they can never be read as tool options
- a session deleted while it is finishing stays deleted

## MacSec 0.3

### See exactly what was found
Every finding now shows the code behind it: the lines around the problem, numbered, with the problem line lit up. Keys and passwords are masked after their first four characters, so you can tell which key it is without it being shown. The PDF has the same evidence.

### A real report
The AI reviewer now reads the code and every scanner result, and writes a tailored report: an executive summary, a risk table, and for each finding the evidence, **why it has that severity**, what could happen, the fix with corrected code, and how to check it. Its verdict on each scanner finding comes with a reason. A new **Report** tab shows it with your posture at the top.

### Claude Code, as your own session
- Reviews run as normal Claude Code sessions with your usual sign-in. No API key needed; you can add one on Tools if you prefer.
- **Fix with Claude Code** resumes the exact conversation that did the review.
- MacSec's own security skills (code review method, secrets triage, dependency triage, report writing) are loaded for its reviews only. Add your own skills too.

### Web scan
- **Sign in through MacSec:** a private window opens your site; sign in and close it. The scan then covers members-only pages and checks that private pages really need the login.
- Checks the certificate and TLS versions.
- Looks for keys left in the site's public JavaScript.

### Special audits
Full audit (code and site together, one report), Portfolio sweep (every project in www), and Change review (Claude Code's /security-review of a branch).

### A cleaner, rounder interface
Poppins throughout, more space, rounder detached cards, a sidebar with tonal icons, and step-by-step setup for every test.

## MacSec 0.2

### A new look
A completely new interface built for security work: dark glass lit in cyan, violet and magenta, and a live **threat core** on Overview that shows your posture at a glance and sweeps while tests run. Findings open in a split view, with the fix next to the problem.

### Web scan
Point it at a Laramac site or any address you own. It fingerprints the server, checks security headers, cookies and HTTPS, maps the site, looks for files that should never be public, and runs every read-only Nuclei check. Quick, Standard and Thorough, and it can scan behind your login. Every check only reads.

### API security
Load a Postman collection, OpenAPI or Swagger file, or HAR recording. MacSec reviews the file (open endpoints, secrets in addresses, saved tokens, plain HTTP) and makes ordinary GET requests signed in as you to check what the API gives away: open cross-origin access, sensitive fields, error details, missing headers.

### Tools
- **Updates:** MacSec looks for newer scanner versions once a day; update them all with one button.
- **Your apps:** finds Burp Suite Professional, the Claude desktop app, Codex and LM Studio wherever they are installed.
- ZAP is no longer included.

## MacSec 0.1

The first release: deep code review.

- **Projects** from your www folder (shared with Laramac), GitHub and Azure DevOps (enter your organization or organization/project and see every repository), or any folder.
- **Code review** with Semgrep (up to 20 rule sets), Bearer, Bandit, gosec, Gitleaks, TruffleHog, OSV-Scanner and Trivy, chosen to fit your code, at three depths.
- **AI reviewer:** Claude Code, Codex or your own model in LM Studio. It checks every scanner finding (real or false alarm) and looks for access-control and logic flaws scanners miss.
- **Sessions** you can come back to, with a PDF export and **Continue in Claude Code** (Remote Control on, so you can carry on at claude.ai/code or on your phone).
- **One folder:** everything in ~/MacSec. Scanners keep their caches there too.
- **Logs** of everything MacSec does, with tokens hidden.

Next: Web scan (Nuclei with every template, Katana, httpx, ffuf, Dalfox, ZAP), API security (Postman and OpenAPI), and Special tests.
