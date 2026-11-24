# Maintaining MacSec

The owner's manual. Everything needed to build, release and fix MacSec is in this repository and
on GitHub, so nothing depends on a chat or on one computer.

## Releasing

1. Change `version` in `package.json` (no `v`).
2. Add a `## MacSec X.Y` section at the top of `RELEASE_NOTES.md`.
3. Commit and push to `main`; wait for **CI** to pass.
4. **Actions › Build and release › Run workflow**, tag `vX.Y.Z`. Or from a terminal:

   ```sh
   gh api -X POST repos/Pino10/macsec/actions/workflows/release.yml/dispatches -f ref=main -f 'inputs[tag]=vX.Y.Z'
   ```

5. About 10 minutes later the release has a DMG for Apple Silicon, one for Intel, and `SHA256SUMS.txt`.

Builds run on GitHub's own Macs. The app is ad-hoc signed (no Apple Developer account needed).

## How it fits together

| Folder | What is there |
| --- | --- |
| `src/main/toolbox.ts` | The catalog of scanners and how each is installed: from its GitHub release (checked against its checksum file) or with uv for Python tools. `toolEnv()` gives every tool a private home inside `~/MacSec/tools/home`. |
| `src/main/scanners/plan.ts` | Which scanners run for a project and depth, with their arguments. |
| `src/main/scanners/parse.ts` | Turns each scanner's JSON into one `Finding` shape, and merges duplicates across tools. |
| `src/main/aireview.ts` | The AI review: Claude Code, Codex or a model, the prompt, and reading its answer. |
| `src/main/review.ts` | A review session from start to finish. |
| `src/main/sessions.ts` | Session folders in `~/MacSec/sessions`. |
| `src/main/projects.ts` | www folder, GitHub and Azure DevOps listing, and cloning with a token. |
| `src/main/report.ts` | The HTML that becomes the PDF. |
| `src/main/engine.ts` | Runs tools for any session, stops them, and records each step (`SessionRun`). |
| `src/main/webscan.ts` | Web scan: httpx, header checks, Katana, the exposed-files check and Nuclei (read-only tags only, see `NOT_READ_ONLY`). |
| `src/main/apispec.ts`, `src/main/apiscan.ts` | Reading Postman, OpenAPI, Swagger and HAR files, and the API review. |
| `src/main/evidence.ts` | The code lines behind each finding, with secrets masked (`maskSecrets`). |
| `src/main/skills.ts` | MacSec's Claude Code plugin (written to `tools/claude-plugin`) and your skills (`extensions/claude`). A review loads only the skills you picked (`chosenPluginArgs`, built in the session's `skills` folder and removed when it ends). |
| `src/main/watch.ts` | Keeping watch: the daily package check (OSV-Scanner on the projects you reviewed) and the weekly re-test, which only reports serious findings that are new (`newSerious`). State in `config/watch.json`. |
| `src/shared/leaked.ts`, `src/shared/fixdiff.ts` | "I leaked a key" steps per provider, and the AI's suggested fix as a diff (shown only: MacSec never changes your code). |
| `src/main/webextra.ts` | TLS check, keys in public JavaScript, signed-in versus signed-out comparison. |
| `src/main/audit.ts` | Special audits: full audit, portfolio sweep, change review. |
| `src/main/mobilescan.ts`, `src/main/scanners/mobile.ts` | Mobile app checks: mobsfscan, the Android manifest and Info.plist checks, and binary hardening (`hardening()` reads Mach-O and ELF headers). |
| `src/main/infraaudit.ts`, `src/main/scanners/infra.ts` | Cloud account audits (ScoutSuite, CloudFox, PMapper) and server checks (naabu, Nmap); also the WPScan parser. |
| `src/main/seckit/` | Shared with Laramac: the recon engine, the reviewers' command lines, the skills, the skill packs, Free LLM API and the GitHub client (ghapi.ts: never call GitHub's API with plain fetch). Change one copy, then copy it to the other app. |
| `src/shared/latest.ts` | The newest test of each target, for the Overview: an audit's own child sessions are not counted twice. |
| `src/renderer/src/pages/Updates.tsx` | The Updates page. |
| `src/main/freellm.ts` | Free LLM API's settings and key (a secret) for Claude Code reviews. |
| `src/main/reconscan.ts` | Recon as a session. |
| `src/main/optional.ts` | The attack tools from the T3MP3ST pack, listed only. Never add an install or run for these. |
| `components/LiveRun.tsx` | The live progress panel. Tools' output reaches it through `SessionRun.line()` (redacted, then `friendly()`), and `percentOf()` reads percentages. |
| `src/main/aisummary.ts` | The AI summary for web and API scans (it reads the findings only). |
| `src/renderer/src/macsec.css` | The whole design: colours, glass, controls. `components/ThreatCore.tsx` is the posture orb. |
| `src/main/validate.ts` | Every input rule as a pure function: hosts, scope hosts, windows, caps, impacts, the `EXPLOIT host` phrase. No Electron import, so it is unit tested. |
| `src/main/engagement.ts` | The written authority a controlled proof stands on, and the one function that says why a run may not happen. |
| `src/main/wordlistfiles.ts` | The discovery word list: yours from `extensions/wordlists/*.txt` first, then MacSec's, validated to plain paths and written where ffuf can read it. |
| `src/main/impact/` | Controlled proofs: `catalog.ts` (what each proof sends and never does), `client.ts` (the only client that can send a real request), `actions.ts` (the bounded runners), `planner.ts` (rules first, one optional AI call), `campaign.ts` (the gate, the run, the cleanup, the record). |
| `src/shared/types.ts` | Every message between the window and the main process (`Channels`). |
| `src/renderer/src/pages/` | One file per page. Styles are in `macsec.css`. |

**Adding a scanner:** add it to `CATALOG` in `toolbox.ts`, add a parser in `parse.ts` (with a test using real output), and add it to `planScanners` in `plan.ts`. If its release files are named oddly, add a case to the "picking the right download" tests.

**Adding a Semgrep rule set:** add its `p/...` name in `plan.ts`. If a pack ever disappears, Semgrep falls back to `p/default` on its own.

**Tool updates:** `toolbox.ts` records the version installed in `tools/versions.json` and checks GitHub and PyPI daily (`checkUpdatesDaily`). Installing again is how an update happens.

### Added in 1.36.0

- `plugins.ts`: declared binary/args/parser, no shell, manual run, engagement for remote hosts, findings appended as possible; `plugins:*` IPC and the Plugins page.
- `bountyReport` in `exports.ts` and the `bounty` export format.

### Added in 1.35.0

- Engagement profiles (`EngagementProfile` in `shared/impact.ts`, normalised in `engagement.ts`, select in the Impact form).
- Review loop evidence adapters for code, web, API and recon; the Review desk is available on every session kind.
- Raw evidence file and no-hidden-findings behaviour from the unreleased 1.34.2 are included.

### Added in 1.34.2

- `reviewloop.ts` keeps `evidence.raw.txt` (0600, local only), keeps no-location AI findings as `not stated`, and combines `info` notes; the findings view starts with `info` on.

### Added in 1.34.1

- The Review desk allows a single-source combine when blind AI is skipped; `loopReport` states whether the blind stage ran.

### Added in 1.34.0

- `reviewloop.ts`: evidence pack, blind prompt/parser, merge with provenance, source-blind verifier and report; `loop:*` IPC and the Review desk tab.
- Mobile scans write `evidence.txt`; loop files live in the session folder.

### Added in 1.33.2

- `startMobileScan` saves the session after setting `reviewer`; without it the AI step ran but the UI said "No AI". Regression test in `tests/v52-mobile-reviewer.test.ts`.

### Added in 1.33.1

- Mobile/Web forms sync the saved reviewer after settings load; `ReviewerChoice` waits for all AI lists before resetting a choice. Regression: a cold start must not leave the mobile check on "none".

### Added in 1.33.0

- `mobilegaps.ts`: task hijacking, backup rules, pinning evidence, resilience, WebView, screenshot indicator and iOS Keychain classes; wired into `mobilescan.ts` manifest and deep steps.
- `MOBILE_COVERAGE.md`: the MASVS-mapped coverage and the live-test gaps.

### Added in 1.32.0

- `ioschecks.ts`: signed-entitlement checks, provisioning/adhoc/team/expiry, Info.plist keys and permissions, bundle test-host/key/pinning checks; wired into `mobilescan.ts` with `security cms` and `codesign`.
- The Android Hermes bundle (`assets/index.android.bundle`) is included in the deep string pass.

### Added in 1.31.0

- `patch.ts`: scratch copy, AI edit of the copy only, test detection and run, diff, typed apply, backup and rollback; `patches:*` IPC and the finding panel.
- `git.ts`: prefer the Command Line Tools git when the Xcode licence is unaccepted.

### Added in 1.30.0

- The Amass decision: 5.1.3 against subfinder 2.17.0 on `owasp.org`; Amass timed out at seven minutes with no result, subfinder returned 158. Do not add it.
- Xcode 27.2 is selected; its licence must be accepted before `xcodebuild` or the system git work (`sudo xcodebuild -license accept`).

### Added in 1.29.0

- `corpus/sql/joern.md`: the Joern 4.0.691 commands and the Java-pair result.

### Added in 1.28.0

- `tests/fixtures/mobile/red-screen.apk` (8,649 bytes, MIT, F-Droid) with its provenance, and `tests/v48-mobile-fixture.test.ts` covering the zip central directory, the AXML header and the dex magic.

### Added in 1.27.1

- `Sessions.tsx`: the early return for an open result is after the search effect, restoring a constant hook count. When adding a hook to that component, keep it above the return.

### Added in 1.27.0

- `vhosts.ts`: bounded Host-header probing with a cannot-exist baseline; `recon:vhosts` and the Surface card; tests against a local server.
- Interface pass in the shared stylesheet: radii, controls, rail spacing, scrollbars, focus ring, and the traffic-light position.

### Added in 1.26.1

- `parsePsalm` accepts both Psalm 6 (`{issues}`) and Psalm 7 (bare array) output.
- `corpus/sql/measurements.md`: the engine table, versions and the commands to repeat it.

### Added in 1.26.0

- The corpus grew to 33 cases across eight languages, with marker lines and a language-level holdout split; `corpus/sql/report.json` holds the measured run.
- The Joern decision rule is in `RELEASE_NOTES.md` 1.26.0 and `ROADMAP.md`.

### Added in 1.25.1

- `corpus/sql/`: eight labelled samples, a holdout split, `cases.json`, and the generated `report.json` from the Semgrep run.
- `qa/sqlcorpus.ts`: the loader, the scorer (tolerance, dedupe by place, holdout split), the Semgrep runner with a private home, and the Joern parser. `scripts/joern-sql.sc` is the query template.
- `npm run corpus:sql` measures Semgrep; Joern is measured only when it is installed, never from a claimed number.

### Added in 1.25.0

- `qa/installcheck.ts`: the static catalogue rules and the live GitHub release check; `qa/crossengine.ts`: recorded output through the real parsers with precision and recall.
- `tests/v45-harness.test.ts` and `tests/fixtures/crossengine/`: the fixtures and the gate.
- `.github/workflows/harness.yml`: weekly and on demand; `npm run harness` / `harness:offline`.
- `scripts/` and the SQL corpus follow in 1.25.1.

### Added in 1.24.1

- `.github/workflows/release.yml`: the tag path now sets the release body from the top section of `RELEASE_NOTES.md`, after attaching the files.
- `ROADMAP.md`: reconciled to the 1.25 order.
- Every existing release page was backfilled from `RELEASE_NOTES.md` (1.0 to 1.24); the 0.x pages have no sections in the file.

### Added in 1.24

- `scanners/parse.ts`: `parsePhpstan` (security messages only) and `parsePsalm` (taint issues); `plan.ts` runs them only from the project's own `vendor/bin` and config, through `review.ts`'s absolute-path spawn.
- `secondopinion.ts`: the independent verifier, with the masked excerpt, the fixed two-line answer, its own settings file and the `findings:second-opinion` channel; it never changes confidence.
- `SurfaceGraph.tsx`: the offline SVG graph in the Surface tab.
- `apispec.ts`: Burp XML import (raw request lines and Host header, no stored credentials), plus the format in the API page and the picker.

### Added in 1.23

- `profiles.ts` + `ProfileBar`: saved choices for web scans and code reviews, with the secret-key refusal and a 50 profile cap.
- `findings:triage-bulk` + the bulk bar in a result: one write for several findings, with an owner and a due date.
- `sessionCsv` in `exports.ts`, the CSV export entry, and `SessionInfo.estimate` filled by `startReview`.
- `ROADMAP.md` for the agreed 1.24 set.

### Added in 1.22

- `shared/estimate.ts`: the scan and review estimators, used by the Web scan and Code review pages and tested in `tests/v42`.
- Web scan: `pacing: 'gentle'`, a sticky summary bar, host-bound consent, stateful presets, the AI extras beside the reviewer, and sign-in expiry detection in the signed-in walk.
- Code review: special audits moved out, the deep audit behind an advanced disclosure, scanner checkboxes and `skipHistory` (threaded through `ReviewRequest`, `validReview`, `planScanners` and `review.ts`).
- Navigation: a `new` page (Start a test), the `CommandPalette` (Cmd+K), and session tabs filtered by kind.

### Added in 1.21

- `indexdb.ts`: the SQLite session index (`node:sqlite`, with a clean fallback), updated from `sessions.ts` saves and deletes, used by `search.ts`, pruned by `storage.ts`.
- `RELEASE_NOTES.md`: every version from 1.14 written out in full; the README carries a release history table. When cutting a release, write the section in the same shape: what is new, under the hood, limits, and what is still open.

### Added in 1.20

- `cli.ts` + `baseline.ts`: the headless door (`--headless` in `index.ts`, before any window), argument rules, baseline identity (`checkId|place`), exit codes and `--json`.
- `benchmarks.ts` + `benchmark` script: four scored checks against labelled samples, a CI step, and a floor of 0.8 precision and recall.
- `search.ts` (cross-session finding search) and `storage.ts` (folder size, session count, delete by age), with the Settings controls.
- Accessibility: contrast on faint text, tooltips on focus, arrow keys in the findings list and the tabs.

### Added in 1.19

- `netclient.ts`: a request that connects to the approved address (lookup pinned), used by `ConfirmClient`. `NetGuard.addressFor()` keeps it. Tools get no session credentials; `webscan.ts` has its own signed-in walk.
- `releasekey.ts` + `releasesign.ts`: the release public key and `verifyChecksums()`. `.github/workflows/release.yml` signs `SHA256SUMS.txt` with the `MACSEC_SIGNING_KEY` secret and fails without it. To rotate: generate a new Ed25519 pair, replace `build/release-signing.pub` and `releasekey.ts`, set the secret, and remember that old releases can no longer be verified by new apps.
- `impact/link.ts`: `attachProof()` puts the proof on the finding; `index.ts` links proven steps to the session that holds the finding.
- `SECURITY.md` and `THREAT_MODEL.md`.

### Added in 1.18

- `chains.ts`: 16 path rules, `impact` and `breakAt` on every chain; rendered in the Attack paths tab, the fix plan, the executive PDF and Assets.
- Four skills used by the AI flows: `attack-chains`, `api-authorization`, `js-deep-analysis`, `privilege-escalation` (see `METHOD` in `aisummary.ts` and `reviewPrompt` in `aireview.ts`).
- `scanners/web.ts`: `parseKatana` also reads jsluice results; `webscan.ts` passes `-jsluice` to Katana in Standard and Thorough.
- `pages/Assets.tsx` rebuilt: legend, filters, sort, per-asset fix list and attack paths.

### Added in 1.17

- `src/main/wafdeception.ts`: the deception checks (structure, not size), the port-mimic check, the one note, the AI note, and the `waf-deception` skill (in `seckit/skills.ts`, kept out of code-review plans).
- `msf.ts`: `RUN_MODULES` (the run-only allowlist) and `runArgs`; `impact/actions.ts`: `msf-run` with a callback listener (`setMsfRunRunner` for tests). Run modules are never on the check list.
- `updater.ts`: three ways to check for a release (API, feed, github.com redirect), and a failure shown on the page instead of thrown at the button.
- `apiscan.ts`: a secured endpoint that answers with no token is reported. `webscan.ts`: new endpoints and routes compared with the previous scan of the same host.

### Added in 1.16

- Tools: `gau` (release), `wafw00f` and `sqlmap` (python), Homebrew installs for app tools (`installApp`, `brewPath`, `ToolInfo.formula`) and versions for app tools (`toolVersion` now runs an installed app's `versionArgs`).
- `reconscan.ts`: a gau step and `parseGau`; `recon:handoff` starts a web scan with `seedUrls` from the recon's own `urls.txt`.
- `apiscan.ts`: `loadSpecText(text, name)`, used by `api:load-url`.
- `impact/actions.ts`: `sql-injection-proof`, `parseSqlmap`, `setSqlmapRunner`, and `client.reserve()` for tools that send their own requests (ffuf, sqlmap).
- `tests/v33-tools.test.ts`: the new tool parsers and the sqlmap bounds.

### Added in 1.15

- ffuf in `CATALOG` (release asset plus published checksums), `parseFfuf` in `scanners/web.ts`, the optional `discover` step in `webscan.ts`, and the engagement-gated `content-discovery` and `auth-bypass` runners.
- `impact:update-step`: a plan step can be filled in by the person and is re-checked by `checkStep()` before it is saved.

### Added in 1.14 (controlled proofs)

- `src/main/impact/` and `src/main/engagement.ts`: the engagement gate, the catalogue, the bounded runners, the planner and the campaign. The rules that must not be broken are in CLAUDE.md under "Controlled proofs".
- `src/main/validate.ts`: the input rules, extracted from `index.ts` so they can be tested without Electron.
- `tests/v31-impact.test.ts`: the refusals first (no engagement, revoked, outside the window, wrong phrase, no approval, a write without integrity, a write without the leftover acknowledgement, off-site steps, the kill switch), then the proofs with injected fetch.

### Added in 0.11

- `src/main/seckit/owasp.ts` (shared with Laramac) and `src/main/owaspmap.ts`: every session's OWASP Top 10 (2025) checklist (`sessions:owasp`), also in the PDF report.
- `src/main/leakkit.ts`: the "Stop leaking keys" kit (pre-commit hook, pre-commit config, GitHub Action with Gitleaks pinned by SHA-256). Only shown, copied or saved under ~/MacSec/kits.
- `pageInfo` in `src/main/seckit/recon.ts`: each crawled page broken down (forms, CSRF fields, cookies by name and flags, security headers, scripts, parameters), shown in `components/ReconPages.tsx`.

## Tests

```sh
npm run typecheck
npm test
```

`tests/v04.test.ts` uses real output from mobsfscan, Androguard, naabu and Nmap (in `tests/fixtures`), and `tests/e2e-v04.test.ts` runs a real mobile check and port check when mobsfscan is in `/tmp/scanvenv`, a sample app is in `/tmp/mob` and naabu is at `/tmp/nb/naabu`.

`tests/core.test.ts` checks download picking, every parser, merging, the AI output and the PDF HTML. `tests/e2e.test.ts` runs a real review with real Semgrep and Bandit when they are installed in `/tmp/scanvenv` (`python3 -m venv /tmp/scanvenv && /tmp/scanvenv/bin/pip install semgrep bandit`).

## When something breaks

1. **A scanner fails in a review:** open the session's folder; `raw/<scanner>.log` has its error output. Logs in the app show the same.
2. **A scanner will not install:** its release files may have been renamed. Check them on GitHub and update `pickAsset` (and its test).
3. **A release did not build:** open the failed run in Actions and read the red step.
4. **Undo a change:** `git log`, then `git revert <commit>`.
