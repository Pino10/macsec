## MacSec 0.7.0

### This Mac
A new page that checks the Mac you are using, only reading: disk encryption, firewall and stealth mode, Gatekeeper, System Integrity Protection, automatic security updates, programs that start on their own (and who signed them), ports open to your network, SSH keys without a passphrase or with loose permissions, and browser extensions that can read every site. You get a score out of 100 and how to fix each item. It also lists your Docker images and scans any of them with Trivy.

### Findings over time
A session now shows **Since last time**: what is new, what was fixed and what is still there compared with the previous session on the same target.

### Exports
Export a session as **SARIF** (GitHub code scanning and editors), **DefectDojo**, its **SBOM** (CycloneDX) or JSON.

### More free scanners
- **Syft** lists every package (the SBOM, kept with the session) and flags copyleft licences worth knowing about.
- **Grype** gives a second opinion on package flaws in Deep reviews, with the chance each gets exploited (EPSS).
- **Checkov** checks Terraform, Bicep, ARM, Kubernetes, Helm, Dockerfiles and CI workflows.
- **ZAP baseline** joins Thorough web scans when Docker is running: it browses and only reads, it never attacks.
- garak and promptfoo are listed (not installed or run) for testing your own AI models.

### Keep projects safe between reviews
On Projects: save a **pre-commit hook** that stops commits with keys, and a **CI workflow** (GitHub Actions or Azure Pipelines) that runs the same scanners. MacSec asks where to save each file. Laramac sites show their .test address.

### Skills
29 built-in skills (9 new: audit context, entry points, threat model, variant analysis, false-positive checks, change review, insecure defaults, sharp edges, fix verification), and the **Trail of Bits** and **Sentry** skill sets can be added from Tools.

### Use MacSec from everywhere
- **MCP**: turn on “Let AI tools use MacSec” and Claude Code, Claude desktop or Cursor can read sessions, compare them, start a code review and run the Mac check-up.
- The **macsec** command (in MacSec's folder), **Raycast** script commands and **Apple Shortcuts**.
- **Messages to Slack, Teams or Discord** when a session finds something critical or high, and a macOS notification when MacSec is in the background.

