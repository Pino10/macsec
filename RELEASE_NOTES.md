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
