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
