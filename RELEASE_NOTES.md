## MacSec 0.1

The first release: deep code review.

- **Projects** from your www folder (shared with Laramac), GitHub and Azure DevOps (enter your organization or organization/project and see every repository), or any folder.
- **Code review** with Semgrep (up to 20 rule sets), Bearer, Bandit, gosec, Gitleaks, TruffleHog, OSV-Scanner and Trivy, chosen to fit your code, at three depths.
- **AI reviewer:** Claude Code, Codex or your own model in LM Studio. It checks every scanner finding (real or false alarm) and looks for access-control and logic flaws scanners miss.
- **Sessions** you can come back to, with a PDF export and **Continue in Claude Code** (Remote Control on, so you can carry on at claude.ai/code or on your phone).
- **One folder:** everything in ~/MacSec. Scanners keep their caches there too.
- **Logs** of everything MacSec does, with tokens hidden.

Next: Web scan (Nuclei with every template, Katana, httpx, ffuf, Dalfox, ZAP), API security (Postman and OpenAPI), and Special tests.
