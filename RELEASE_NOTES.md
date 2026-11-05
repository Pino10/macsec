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

