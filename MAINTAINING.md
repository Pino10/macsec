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
| `src/main/skills.ts` | MacSec's Claude Code plugin (written to `tools/claude-plugin`) and your skills (`extensions/claude`), loaded with `--plugin-dir`. |
| `src/main/webextra.ts` | TLS check, keys in public JavaScript, signed-in versus signed-out comparison. |
| `src/main/audit.ts` | Special audits: full audit, portfolio sweep, change review. |
| `src/main/mobilescan.ts`, `src/main/scanners/mobile.ts` | Mobile app checks: mobsfscan, the Android manifest and Info.plist checks, and binary hardening (`hardening()` reads Mach-O and ELF headers). |
| `src/main/infraaudit.ts`, `src/main/scanners/infra.ts` | Cloud account audits (ScoutSuite, CloudFox, PMapper) and server checks (naabu, Nmap); also the WPScan parser. |
| `src/main/seckit/` | Shared with Laramac: the recon engine, the reviewers' command lines and the skills. Change one copy, then copy it to the other app. |
| `src/main/reconscan.ts` | Recon as a session. |
| `src/main/optional.ts` | The attack tools from the T3MP3ST pack, listed only. Never add an install or run for these. |
| `components/LiveRun.tsx` | The live progress panel. Tools' output reaches it through `SessionRun.line()` (redacted, then `friendly()`), and `percentOf()` reads percentages. |
| `src/main/aisummary.ts` | The AI summary for web and API scans (it reads the findings only). |
| `src/renderer/src/macsec.css` | The whole design: colours, glass, controls. `components/ThreatCore.tsx` is the posture orb. |
| `src/shared/types.ts` | Every message between the window and the main process (`Channels`). |
| `src/renderer/src/pages/` | One file per page. Styles are in `theme.css`. |

**Adding a scanner:** add it to `CATALOG` in `toolbox.ts`, add a parser in `parse.ts` (with a test using real output), and add it to `planScanners` in `plan.ts`. If its release files are named oddly, add a case to the "picking the right download" tests.

**Adding a Semgrep rule set:** add its `p/...` name in `plan.ts`. If a pack ever disappears, Semgrep falls back to `p/default` on its own.

**Tool updates:** `toolbox.ts` records the version installed in `tools/versions.json` and checks GitHub and PyPI daily (`checkUpdatesDaily`). Installing again is how an update happens.

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
