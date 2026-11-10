## MacSec 0.14.0

### This Mac: many more checks, in sections
Settings are now grouped and about a dozen new read-only checks were added: password after the screen locks, guest user, automatic login, Find My Mac, backups, AirDrop visibility, sharing services (SSH, screen sharing, file sharing), databases open to the network, network proxy, the hosts file, extra trusted certificates, last update check, device management, and PATH folders others can write to. All of them only read. Each says what it found and how you can fix it yourself in System Settings.

### Mobile apps: more checks
Android network security config (plain HTTP, certificates the phone owner added, expired pins), old target Android version, iOS development builds (get-task-allow, development push), and Firebase addresses (noted, never read). New Android, iOS and MASVS review skills guide the AI report.

### Servers and networks
The server check now takes a list, a range (192.168.1.10-20) or a small network (192.168.1.0/28), up to 64 servers at a time, with each server's open ports and services named separately. Only connections are opened.

### Only what is installed
The list of who writes the report now shows only the AI tools that are ready to use (Claude Code, Codex, Gemini CLI, your model). Others appear by themselves once they are set up. The default reviewer in Settings follows the same rule.

### Skills
Six new review skills: mobile apps, Android, iOS, GraphQL, servers and networks, and cloud accounts. The AI report for web, API, mobile, cloud and server checks now follows the skills that fit it.

## MacSec 0.13.0

### Recon now shows proof
Recon no longer only points at things that might be wrong. When it can, it **confirms** them by reading the real file or page, and keeps the proof with the finding.

- **Confirmed** means the problem itself was seen: a folder listing, a real .git or .env file, a readable source map, an error page that shows code details, a site that accepts a made-up origin, or a CDN or firewall answering. **Possible** means the evidence points at it but does not prove it, such as a version that matches a known issue.
- Each proof shows the request, the answer's status and size, a fingerprint of what was read, the time, and a command you can copy to repeat it. Secret values are never stored: a .env file shows only the setting names.
- New checks: folder listings, about 40 more risky files (Git, Subversion, backups, dumps, keys, debug pages), CDN and firewall detection, error pages, cross-origin sharing, advertised methods, and versions of web servers and scripts matched against the public NVD list.
- Version matches are always "Possible", never critical, and a Linux package may have been fixed without changing its version number.
- Sessions has a "Confirmed only" switch, and reports show a Confirmed or Possible badge with the proof.

Nothing is exploited. Recon only reads, with short fixed lists of paths, and never guesses passwords or sends data that changes anything.

## MacSec 0.12.0

### Deep audit
A new **Deep audit** option in step 2 of Code review, for projects on this Mac, in GitHub or in Azure DevOps. Pick the Cloudflare security audit, Claude Code security review or both, then the AI to run it with: Claude Code, Claude Desktop (MacSec copies the request and opens the Claude app), claudelm (your model in LM Studio) or claudefree (Free LLM API). Before it starts, MacSec lists which AI, which method and version, what it reads, what it writes and where your code goes.

The audit is read-only and MacSec checks that: your project is measured before and after, every finding is checked against Cloudflare's report format, and each file and line it cites must exist, otherwise it shows as "needs checking". Results are saved as a normal session, and leads are never stored with secrets in them.

### Claude Desktop
**Connect** in Extras adds MacSec to the Claude app with a small helper that only needs curl. It reads MacSec's private key when it runs, so the key is never copied into the app's settings. Restart the Claude app afterwards.

### Skills you can update
Skill packs say when a newer version exists, link to what changed and have an **Update now** button. MacSec checks once a day, tells you once, and never updates anything until you press it.

### Messages you can see
Notifications now pop up at the top right and errors stay until you close them. Click one to read it full size, and the **Messages** button in the sidebar keeps the history with a count of unread ones.

## MacSec 0.11.0

### OWASP Top 10 for everything
Every session now has an **OWASP Top 10 (2025)** tab: code reviews, web scans, API scans, recon, audits and more. Each of the ten says whether it had problems (and how many, and the worst), was checked and looked fine, or was not checked by that run, with what would check it. Findings are sorted by their CWE when they have one and by what they say otherwise, and findings you marked as not a problem do not count. The checklist is in the PDF report too.

### Stop leaking keys
On the Code review page, a kit that catches keys and passwords before they are committed, and again on GitHub before they are merged: a Git **pre-commit hook** (it uses MacSec's Gitleaks if it is not installed elsewhere), a **pre-commit** config, and a ready-made **GitHub Action** that is free and needs no licence key. The Action checks the Gitleaks download against its SHA-256 and pins its checkout to a commit. Copy them, or save all three in ~/MacSec/kits: MacSec does not change your projects.

### Recon, page by page
Recon now breaks down **every page it reads**, one by one: its status and title, its forms (where they send, their fields, and whether a POST form has a CSRF token field), the parameters in its links, its scripts and where they come from (and which lack an integrity check), its cookies (names and flags only, never values), its security headers and what it runs on. What stands out on each page is listed worst first, and the pages worth a look come first. It only reads what the site already sends.

## MacSec 0.10.2

### A score you cannot misread
The number in the middle of the core is your posture score, out of 100 (higher is better), not a count of findings. It now says "Score" and "/100", and the lowest posture is called "At risk" instead of "Critical", so it is never mixed up with the number of critical findings next to it.

## MacSec 0.10.1

### Laravel's own skills
Code reviews can now use Laravel Boost's free skills from Laravel (MIT): Laravel best practices with a rule for each topic (security and authorization, Eloquent and N+1 queries, validation, queues, caching, routing), Tailwind CSS 4 and Pennant. They install by default with the other skill packs and are switched on for Laravel projects in the skill picker. The paid Flux UI Pro and Laravel Cloud skills are left out.

## MacSec 0.10.0

### Choose the skills for each review
The skills that fit your project are switched on (MacSec reads the stack: PHP, Laravel, React, Electron, Docker and more). Switch any on or off, and see about how long the review will take. The review then loads exactly those, and nothing else.

The best skill packs now come by default: Trail of Bits, Sentry, Cloudflare and Anthropic. Remove one on Tools and it stays removed.

### I leaked a key: what now?
Every key a scanner finds comes with the steps for its provider (AWS, GitHub, GitLab, Stripe, Google Cloud and Firebase, Azure, Slack, OpenAI, Anthropic, Twilio, SendGrid, databases and private keys): revoke it first, with a button to the right page, check whether it was used, then take it out of the code. When it is in the Git history, how to clean that too.

### Fixes you can read
The AI's suggested fix is shown as a change to your code: the old line in red, the new lines in green, in place. Copy the fix, or copy it as a patch. MacSec still never changes your code.

### Keeping watch
- **New flaws in your packages, daily.** OSV-Scanner checks the lock files of the projects you reviewed on this Mac, and you get a notification when a new critical or high flaw appears. Only package names and versions leave the Mac. On by default.
- **Test again every week.** The newest review of each project runs again while MacSec is open, and you hear about it only when it finds serious problems that were not there before. Off by default: switch it on in the Overview.

### Fixed
- Choosing Claude Code on your own model, Claude Code on Free LLM API or Gemini CLI for a code review now uses that reviewer. Before, the review quietly used Claude Code with Anthropic's models instead.

## MacSec 0.9.0

### Updates you can see
A new **Updates** page, like Laramac's: MacSec's newest version with its notes inside the app, a progress bar while it downloads, the scanners that have a newer version (update them all at once), a refresh for the vulnerability databases, and every past release with its notes. The sidebar shows when a new version is ready.

MacSec never offered updates before, because every release was published as a pre-release and MacSec skipped those. It now reads them, and new releases are published as normal ones.

### Counts you can trust
A full audit runs its own code review and web scan and holds their findings, and the Overview counted those findings twice. Each finding now counts once, in the Overview and in "Test everything again".

### Special audits, put where they belong
- **Cloud and servers** is its own page: your Azure or AWS account, and the open ports of a server you own.
- **Code review** offers "Just my changes" (Claude Code's /security-review of your branch) and "Code and its live site" (a code review and a web scan joined in one report).
- **Projects** has "Check every project" (keys and vulnerable packages across your www folder).
- Mobile apps already had its own page.

### Your own editor
"Open in editor" uses the editor or IDE you choose in Settings (VS Code, Cursor, Zed, Sublime Text, the JetBrains IDEs, Nova, Xcode and more, or any app), at the line of the finding.

### Also
- The default reviewer in Settings now saves every reviewer, not only some.
- Each release carries only its own notes.

