## MacSec 0.6.0

### Code reviews cover far more
- Twelve new review skills: API security (OWASP API Top 10, GraphQL, webhooks), sign-in and sessions (JWT, OAuth, password reset, MFA), every kind of injection, browser-side issues, business logic and races, Docker and CI configuration (GitHub Actions, Azure Pipelines), supply chain, personal data, Supabase and Firebase rules, AI features, and Electron apps.
- A **review-vectors** plan starts every review, so the report says which areas apply to your project and which do not.

### Two more free scanners
- **zizmor** checks GitHub Actions workflows: script injection, pull_request_target misuse, unpinned actions and leaked credentials. It runs offline.
- **Hadolint** checks Dockerfiles: running as root, unpinned images and risky steps.
- Both run on their own when a project has workflows or Dockerfiles, and install into MacSec the first time.

### Reviews on your own model
Before a review on your model in LM Studio, MacSec checks the context the model was loaded with. When it is too small for Claude Code, MacSec loads it again with enough (64k tokens, or the most the model allows). No more "context too small".

### Recon
Five more free public sources for subdomains: CertSpotter, AlienVault OTX, HackerTarget, urlscan.io and Anubis. None of them contacts the target.

