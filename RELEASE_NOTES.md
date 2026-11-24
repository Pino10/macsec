## 1.34.2

Evidence is now kept in full locally, and nothing that was seen is silently dropped from the list.

- **No-hiding in the findings view.** `info` findings are shown by default; the old filter started
  with them hidden. The severities remain toggleable.
- **AI findings without a location are kept**, with the location shown as `not stated`. They are
  marked possible and cannot merge with a tool finding, but they are no longer thrown away.
- **Raw evidence stays local.** The session now keeps `evidence.txt` (masked, sent to the AI) and
  `evidence.raw.txt` (unmasked, mode 0600, for the reviewer, never sent to the AI or the report).
  The desk says where it is.
- **The report masks only the secret value**, not the finding. The location, the host, the plist key,
  the manifest attribute and the evidence excerpt remain; a key value is shortened, with its length
  or fingerprint available where the finding records it. Dumping a live key or cookie into a report
  that gets emailed to a bank or an assessor is not robustness, it is a second incident.
- The combined list now includes `info` notes from the tools, not only problems.

The rule is: the report must show that the thing exists, where it is, and what proves it, without
becoming a secret store. The full value lives in the local session for the person who owns it.

648 tests (643 passed, 5 skipped).

---

## 1.34.1

The review loop can now be used in a **single-source** mode, and it says so.

- **Fast pass:** tools plus the normal AI summary, without opening the desk. This is what the scan
  already does.
- **Assurance loop:** tools, blind AI, merge, source-blind verifier. Use it for pilot, external
  assessment and BoG.
- **Single-source:** if you skip the blind AI, the desk still lets you combine the tool findings and
  run the verifier. The report records "Blind AI review: not run. This is a single-source review;
  the verifier is a second opinion on tool findings, not an independent discovery pass."
- No agreement statistic is implied when only one source existed.

Why keep the blind stage: independence is about not showing the reviewer the answer, not about the
quality of the model. A strong model that has already seen the tool findings is anchored by them.
Skip blind for speed, never for an assurance claim.

648 tests (643 passed, 5 skipped). Build clean.

---

## 1.34.0

The review loop: tools first, then a blind AI review, then the merge, then a second opinion. It is
four stages in one release, each with its own tests, and a human decides at the end.

### Stage 1: tools

The mobile scan now saves a redacted **evidence pack** in the session: the manifest, Info.plist,
entitlements, provisioning details, the Hermes bundle strings and the library list. The tool findings
are kept separately; they are not in the evidence.

### Stage 2: blind AI review

- A new **Review desk** tab on a mobile result runs the chosen AI against the evidence only. The
  prompt says it has not seen the tool findings and does not include them.
- The AI must return JSON with a location for every finding; a finding with no location is dropped,
  not guessed. Every answer is `possible`.
- Malformed JSON or a missing answer is an error, never an empty "all clear".
- The blind findings are stored in `blind-findings.json`; the tool findings are untouched.

### Stage 3: combine

- Matching is by **place** plus title similarity, with stop words removed. The same title at a
  different place does not merge.
- Each combined finding keeps `tools`, `ai` or both, the original ids, agreement, conflict and the
  evidence from each side.
- Nothing is deleted and nothing becomes confirmed. An AI-only finding stays AI-only.

### Stage 4: re-review

- An optional verifier sees the combined list **without the source labels** and answers
  supported, refuted or uncertain. A missing answer becomes `uncertain`, not silent agreement.
- The verifier is a second opinion; the reviewer makes the final call.
- The report (`review-loop.md`) records sources, agreement, the verifier's answer and the exact
  caveat: AI findings are possible, not confirmed.

### Limits, said plainly

- For an APK/IPA the blind stage is an **evidence review**, not a source review: the AI sees the
  manifest, plists, entitlements and bundle strings, not decompiled source.
- Two AI passes cost tokens and time; the desk shows each stage before it runs.
- Old mobile sessions have no evidence pack; run the scan again to use the loop.
- The verifier can be wrong; it never raises confidence by itself.

648 tests (643 passed, 5 skipped).

---

## 1.33.2

The mobile scan was recording the AI report but not the reviewer, so the session said "No AI" while
`ai-report.md` sat next to it. That is fixed.

- `startMobileScan` now saves the session after setting `reviewer`, instead of writing the file first
  and leaving the field undefined.
- A mobile session started with a reviewer now shows that reviewer in the result, and the AI report
  and the header agree.
- Existing sessions that were created before this fix still have `reviewer: undefined`; their AI
  report is in the Report tab, and a re-run labels it correctly. There is no safe way to guess which
  model wrote an old report.

1.33.1 fixed the other half: the Mobile/Web forms kept "none" when settings loaded late, and the
reviewer picker reset a DeepSeek/model choice to none while its lists were loading.

637 tests pass.

---

## 1.33.1

The mobile scan was starting with **no AI** in two situations, and both are fixed.

### Why the AI was missing

- The Mobile page initialised its reviewer to the saved setting **once**, with `'none'` as the
  fallback. If settings loaded after the page mounted (normal on a cold start), the page kept
  `'none'`, so the scan never created the AI step. The Web scan had the same pattern.
- The reviewer picker also reset a choice to `'none'` while its AI lists were still loading: the
  effect ran when `agents` had loaded but `servers` had not, so a DeepSeek or model selection looked
  unavailable for a moment and was replaced with `'none'`.

### What changed

- The Mobile and Web forms now follow the saved reviewer when settings arrive, unless the person
  has already picked one in that form.
- The reviewer picker waits for agents, Free LLM API and model servers to load before deciding a
  choice is unavailable. A DeepSeek selection is no longer reset to "Scanners only" during load.
- If the reviewer really is none, the form still shows "Scanners only" and the session says "No AI".

### Mobile coverage

The coverage map now lists the live techniques mobile testers use (TLS interception, pinning bypass,
root/jailbreak bypass, Keychain/adb extraction, exported components, task hijacking, tapjacking,
screenshots, WebView, deep links, Play Integrity) and says which ones MacSec automates and which
need a device.

636 tests pass (this is a UI state fix; the suite and build are clean).

---

## 1.33.0

The mobile scanner now covers the platform, resilience and privacy checks that the previous review
found by hand, and it says what it cannot know without a running app.

- **Android task hijacking**: an exported `singleTask` activity without `taskAffinity` is reported
  as a low finding for Android 8-9, with the reason and the platform fix.
- **Android backup**: `allowBackup="true"` without `dataExtractionRules` or `fullBackupContent`
  is a low finding, because tokens can land in a cloud backup.
- **Pinning evidence**: a missing pin-set, CertificatePinner, pin hash or TrustKit is reported as an
  informational gap; the scan no longer implies pinning exists because a string says so.
- **Resilience**: the absence of root, jailbreak, debugger or Frida checks is a low finding for a
  banking app; the presence is recorded.
- **WebView**: script or file access is a finding that asks for the host allow-list and the bridge
  to be checked, not a vulnerability claim.
- **Screenshot**: Android's missing `FLAG_SECURE` reference is an indicator with the inlined-constant
  caveat; iOS keeps the `ScreenshotBlockEnabled` check.
- **iOS Keychain classes**: `kSecAttrAccessibleAlways` (medium) and `WhenUnlocked` without
  `ThisDeviceOnly` (low) are now reported.
- **Coverage map**: `MOBILE_COVERAGE.md` maps the checks to MASVS STORAGE, CRYPTO, AUTH, NETWORK,
  PLATFORM, CODE, RESILIENCE and PRIVACY, and lists what still needs a live test.
- Carried from 1.32.0: signed entitlements (profile vs app), ad hoc/team/devices/expiry, signing
  authority, Info.plist keys and permissions, and test-host/key detection in the Hermes bundle for
  both platforms.

The assessment reports are not in this repository; they stay on the machine, as asked.

641 tests (636 passed, 5 skipped).

---

## 1.32.0

The mobile scan now reads the things that were missing on iOS, and it stops reporting a profile wildcard that the signed app never asks for.

### What changed on iOS

- **Signed entitlements, not just the profile.** The scan runs `codesign -d --entitlements` on the built app and checks what the binary actually requests. A wildcard `keychain-access-groups` in the profile is no longer a finding on its own: if the signed app does not include the entitlement, it cannot use the wildcard group. This removes the false positive in the earlier report.
- **Distribution and signing.** The profile is decoded with `security cms`; the scan reports ad hoc or development builds, the provisioned device count, the team name and ID, the profile expiry, the signing authority chain and `get-task-allow`.
- **Info.plist beyond ATS.** `GMSApiKey` and Google key patterns, always-location, contacts, microphone and photo-library usage, and a missing `ScreenshotBlockEnabled` flag.
- **The JavaScript bundle.** The Hermes bundle is included in the string pass: test, UAT, staging, demo and localhost hosts become one finding; Google, AWS and Stripe key patterns become another; an `sslPinning` mention without a pin hash becomes an informational note. The same pass now runs on Android's `assets/index.android.bundle`.

### What it still does not do

- It does not run the app. Screenshot blocking, pinning enforcement, jailbreak detection and the actual base URL at runtime still need a device and a proxy.
- It does not verify key restrictions with Google, and it does not contact test hosts.

634 tests pass (629 passed, 5 skipped). The iOS checks were run against the supplied IPA via `OMNI_IPA_DIR`: ad hoc for 25 devices, an individual team, signed entitlements without a Keychain group, `GMSApiKey` present, test hosts and keys in the bundle.

---

## 1.31.0

Patch generation, in a scratch copy, with tests, a diff, a typed confirmation and a rollback. It is
the last backlog item, and it ships with the safety rails that make it worth having.

### How a patch is made

- **A scratch copy, never the project.** The project is copied to `~/MacSec/patches/<id>/work`,
  without `node_modules`, `vendor`, `.git` or build folders; dependencies are symlinked back so the
  project's tests can run. A git baseline is committed in the copy, so a diff is exact.
- **Only the copy is edited.** Claude Code runs with `acceptEdits` and only Read, Edit and Write, in
  the scratch folder, with a settings file that denies Keychain and cloud credentials. The prompt
  names one finding, forbids touching tests, manifests, CI or dependencies, and asks for the
  smallest change.
- **The project's own tests must pass.** npm `scripts.test`, Composer `test`, or pytest. No test
  command means the patch is shown but cannot be applied, and the interface says why.
- **The diff is shown**, with the test output behind a disclosure.
- **Apply requires the exact phrase** `APPLY <patch id>`, and only after the tests passed. The
  original files are backed up first, then the diff is applied with `git apply` (or `patch -p1`
  for a project without git).
- **One-click rollback** restores the backed-up files. Discard deletes the scratch copy and record.
- Everything is in the finding's panel: prepare, read the diff, read the tests, type the phrase,
  apply, roll back.

### A git fix while Xcode is unlicensed

Selecting Xcode without accepting its licence makes `/usr/bin/git` fail through the xcodebuild shim.
The app now prefers the Command Line Tools git when it exists, and the skill-update tests do the
same, so a licence prompt cannot break cloning, skill updates or patch diffs.

### Limits, stated

- **No automatic scanner rescan yet.** The patch must pass the project's tests and be read by a
  person; re-running the security checks on the patched copy is the next step, not a claim here.
- An AI patch can be functionally correct and still be the wrong fix. The diff and the rollback are
  the control for that, not a promise.
- Applying needs a test command and a passing test run. That is deliberate.

627 tests pass (623 passed, 4 skipped), including a scratch-copy test that applies only with the
phrase and rolls back to the original bytes.

---

## 1.30.0

Two decisions, both made from actual runs rather than another deferral.

### Amass is not worth adding

- **Subfinder 2.17.0**, passive, on `owasp.org`: **158 unique subdomains**, exit 0, under three minutes.
- **Amass 5.1.3**, passive, same domain, same network: **did not finish in seven minutes** (timeout at 420 seconds, no results; an earlier run reached about 94 percent of its source queries after two minutes with nothing emitted).
- Decision: **do not add Amass**. The roadmap asked for an evaluation before another recon dependency, and the evaluation says the dependency costs minutes without a result here. Amass may be useful with API keys or active mode, but neither is allowed (passive only), so it is not the tool for MacSec.
- Limits: one domain, no API keys, one network. Enough to refuse a dependency that cannot produce a number; not enough to judge Amass everywhere.

### Xcode is selected, but its licence is not accepted

- `xcode-select -p` reports `/Applications/Xcode.app/Contents/Developer`, and `xcodebuild -version` reports **Xcode 27.2 (27B52)**.
- However, every `xcodebuild` call fails with "You have not agreed to the Xcode license agreements", and because the developer directory is Xcode, the system `git` shim now fails too.
- Fix, once, in Terminal: `sudo xcodebuild -license accept`. Or, to go back to the Command Line Tools only: `sudo xcode-select -s /Library/Developer/CommandLineTools`.
- Even licensed, dynamic iOS testing needs a signing identity and a device, and an IPA cannot be redistributed.

### Patch generation

Not shipped, and this is the one item I will not fake. It needs, in one piece: a scratch copy, the project's own test command with a time cap, a scanner pass on the patched copy, a diff the person reads, a typed confirmation, and a rollback that is tested. A patch that passes tests but adds a vulnerability is a failed fix; a path that can write into a project without those checks is worse than no feature.

The rest of the backlog is now only this.

---

## 1.29.0

Joern is measured, on the Java pair. It is a first data point, not a verdict, and the release says
so.

### What was run

- Joern 4.0.691 (macOS arm64, 1.76 GB) with OpenJDK 21. The CPG was built from
  `corpus/sql/java`, and a query selected `createQuery` calls whose argument contains `" + "`.
- It found `Hibernate.java:9` (the vulnerable concatenation) and did **not** find
  `HibernateClean.java:10` (the bound-parameter version).
- Java holdout pair: **precision 1.0, recall 1.0**. Parse plus query was about two minutes on two
  small files.
- The other 31 cases are six other languages this Java frontend does not cover, so no whole-corpus
  Joern number is claimed. The acceptance rule stands: beat 0.5 holdout recall on all 33, stay under
  one false positive in ten clean files, and justify 1.76 GB and the runtime.

### Also in this release

- The 1.28.0 MIT APK fixture and its zip/manifest/dex test.
- The 1.27.1 Results crash fix.
- The 1.27.0 interface pass and virtual-host discovery.

### Still open

- Amass versus subfinder: Amass passive did not finish inside the bounded run.
- Patch generation in a scratch copy: not shipped.
- Whole-corpus Joern: needs the other language frontends and a slower, deliberate run.

---

## 1.28.0

The first real mobile fixture, with its decode path tested, and the 1.27.1 crash fix carried in.

### The APK fixture

- **A real, redistributable APK**: `org.vi_server.red_screen` 1.1 (versionCode 2), MIT licensed,
  source at github.com/vi/redscreen.apk, downloaded from F-Droid. It is **8,649 bytes**, so it can
  live in the repository without turning it into an app store, and it is a red screen: nothing in
  it is sensitive.
- **Pinned by SHA-256** in the test, with the source, licence, size and download address recorded
  next to it in `tests/fixtures/mobile/README.md`.
- **The decode path is tested**, not just the file hash: the test walks the zip central directory,
  inflates `AndroidManifest.xml`, checks the Android binary XML chunk header (type `0x0003`, header
  `0x0008`) and finds the package name in the UTF-16 string pool, then reads `classes.dex` and
  checks its `dex\n` magic. That is the same path a manifest or dex reader takes, without a
  dependency.
- **The IPA limit is written down**: an IPA cannot generally be redistributed, and dynamic iOS
  testing needs Xcode, a signing identity and a device. The fixture is an APK; the mobile tests are
  static.

### Still open, explicitly

- **Joern**: Java 21 is now installed and the 1.6 GB asset downloaded, but it has not been measured
  yet. No number is claimed.
- **Amass vs subfinder**: Amass passive did not finish inside a bounded run (it was still resolving
  at the limit), so there is no comparison to report yet.
- **Patch generation**: not shipped. The scratch copy, test command, rescan and typed confirmation
  are exactly where a rushed feature becomes a dangerous one.

---

## 1.27.1

A crash fix. No feature changed.

### The Results page could not be drawn

React error #300 means the number of hooks changed between renders. In `Sessions`, the component
returned `<SessionView>` for a selected result **before** its search `useEffect`. Opening a result
from the list therefore rendered one hook fewer, and the whole page fell back to the error card.

The early return now sits after every hook, so the count cannot change. This affected every result,
not one kind, and it is the reason 1.27.0 was hard to use.

### Still true

- 618 tests pass; typecheck and build are clean.
- The 1.27.0 interface pass and virtual-host discovery are unchanged.
- Joern, the APK fixture, Amass and patch generation remain open, in that order.

---

## 1.27.0

The interface gets the modern pass, and bounded virtual-host discovery is in. Joern and the mobile
fixtures are **not** in this release, and the reasons are concrete rather than a deferral.

### Interface

- **Window controls aligned.** The traffic lights sit at a fixed position with the rail's top area
  cleared, so close, minimise and zoom no longer crowd the brand. The rail header has its own space
  and the drag region is no longer shared with controls.
- **A cleaner surface everywhere.** Smaller, consistent corner radii (18px panels, 10px controls),
  a calmer rail, 34px controls, 36px inputs, thinner scrollbars, and one visible focus ring. The
  changes are in the shared stylesheet, so every page inherits them rather than drifting apart.
- The Start page, result cards, flow steps and the command palette keep their layout; only the
  proportions and chrome changed.

### Virtual-host discovery

- **Bounded by design.** Ten common names (`www`, `admin`, `api` and so on) are sent as `Host`
  headers to the result's own address, one at a time with a 300ms pause and an 8s timeout, and every
  answer is compared with a random name that cannot exist (`.invalid`). Nothing is reported when the
  answers match the baseline, which is what a wildcard does.
- A hit carries the name, status, title and the comparison that proves it. It is read-only: GET, no
  body, no redirects beyond what the pinned client allows, at most 250 KB an answer.
- Available in the Surface tab of a web or recon result, with its own button and an explained empty
  state. Eleven requests at most.
- Tests run against a local server that answers by `Host`: the admin name is found, the default name
  is not, odd names are refused, and a wildcard returns nothing.

### Joern: why it is not here

- The Mac has **Java 8** (`java version "1.8.0_513"`). Joern 4 needs Java 11 or newer.
- The macOS arm64 Joern release is **1.76 GB**, not 400 MB. At the speed available here that is
  over an hour of downloading before any analysis starts, and the app's install path does not
  support that layout yet.
- I extracted a JRE 21 to verify the runtime itself works, but stopped the 1.76 GB download. No
  Joern number is claimed.
- The corpus, query template, parser and decision rule are ready. Joern ships only if it beats 0.5
  holdout recall, stays under one false positive in ten clean files, and justifies that download.

### Xcode: installed, not selected

- `xcodebuild -version` says the active developer directory is **Command Line Tools**, not
  `/Applications/Xcode.app`. Selecting Xcode needs `sudo xcode-select -s /Applications/Xcode.app`.
- Even then, dynamic iOS testing needs a signing identity and a device, and an IPA cannot be
  redistributed. A static unsigned fixture is the honest limit.

### Still open

- A real APK fixture with attribution and a decode test.
- Amass against subfinder, passive only.
- Automated patch generation in a scratch copy, with tests and a rescan.
- Joern once a Java 11+ runtime and the download are in place.

---

## 1.26.1

The 1.26.0 release is verified, the other engines are measured, and one of them found a parser bug
worth fixing.

### 1.26.0 verified

- `releases/latest` on GitHub is **v1.26.0**, not a draft and not a prerelease.
- Both DMGs match `SHA256SUMS.txt`, and those digests match GitHub's own asset digests.
- The Ed25519 signature over `SHA256SUMS.txt` verifies against `build/release-signing.pub`.
- The release body carries the 1.26.0 notes. (The earlier report of v1.21.0 as latest was stale.)

### The other engines, measured

Bearer, Psalm and PHPStan were run against the same corpus. The full table and commands are in
`corpus/sql/measurements.md`.

| Engine | Coverage | Precision | Recall | Note |
| --- | --- | --- | --- | --- |
| Semgrep `p/sql-injection` | all 33 | 1.0 | 0.647 | Misses Laravel, JS concatenation, Prisma/TypeORM, Hibernate |
| Bearer 2.1.3 | all 33 | 0.8 | 0.235 | Finds Go, Ruby, JavaScript; one false positive on a safe JS query |
| Psalm 7.17 taint | PHP (8) | 1.0 | 0.5 | Catches PDO insert and raw; misses Laravel |
| PHPStan 2.3.7 | PHP (8) | 0.5 | 0.25 | Not a security scanner |
| Joern | not run | | | No Java runtime on this Mac |

The interesting result is Bearer's false positive: a JavaScript query that uses a bound parameter
(`pool.query('... = ?', [req.query.user])`) is reported as SQL injection. Precision matters more
than recall when a person has to act on the report.

### Psalm's output shape, fixed

Psalm 7 writes a bare JSON array. The parser expected the older `{issues: [...]}` wrapper, so the
project's own Psalm would have produced no findings in a review. Both shapes are accepted now, and
a test covers them.

### Joern

Still not run: `/usr/bin/java` exists as the macOS stub, but there is no runtime
(`Unable to locate a Java Runtime`). Any number for Joern here would be invented. The query
template, parser and scoring are ready; the decision rule stays as written.

### Roadmap

Reconciled: the install harness and its weekly live check, the cross-engine runner, the 33-case
corpus and the Semgrep, Bearer, Psalm and PHPStan measurements are marked done. Mobile fixtures,
Joern, Amass, vhost discovery and patch generation remain open, in that order.

---

## 1.26.0

The corpus is now big enough to judge an engine with. This release is the labelled set, the measured
numbers, and the decision rule for Joern written down before it is installed.

### The corpus

- **33 labelled cases across eight languages**: PHP, Python, JavaScript, TypeScript, Java, Go, Ruby
  and C#. Seventeen put request data into a query; sixteen are the prepared or bound version of the
  same code. The line that matters is marked in the source, so a label cannot drift from the code.
- **A real holdout split.** PHP and Python are the training half (9 cases); everything else is
  holdout (15 cases), and rules must not be written against it. Fifteen of the seventeen vulnerable
  cases are holdout.
- The clean halves are deliberately the same operation with a parameter, so an engine cannot pass by
  flagging the file, the framework or the word "SQL".

### The numbers, measured

Semgrep with `p/sql-injection`, on this Mac, via `npm run corpus:sql`:

| Split | Precision | Recall |
| --- | --- | --- |
| Training (PHP, Python) | 1.0 | 0.778 |
| Holdout (the other six) | 1.0 | 0.5 |
| All | 1.0 | 0.647 |

No false positives, and six misses:

- **PHP, Laravel:** `DB::select` with a concatenated string, and `DB::raw` with request data. The
  generic rules do not know Laravel's query builders.
- **JavaScript:** a query built by `+` concatenation. The template-literal case was already missed.
- **TypeScript:** Prisma's `$queryRawUnsafe` and TypeORM's `query` with a template literal.
- **Java:** Hibernate's `createQuery` with a concatenated HQL string.

That is exactly the shape of gap the corpus exists to expose: framework-specific raw APIs and ORM
escape hatches, not plain `mysql_query`.

### The Joern rule

Joern still is not installed, so no number is claimed for it. The rule for the next release is:

- it must find the holdout cases the existing engines miss, starting with the four framework and ORM
  cases above, and
- it must stay under a false-positive rate of one in ten clean files on this corpus, and
- its runtime and disk must be worth what it adds, measured on the same machine.

If it cannot beat 0.5 holdout recall, it does not ship. That decision is now measurable instead of
arguable.

### Limits

- 33 cases is a corpus, not a benchmark. The next growth is real applications with no known SQL
  injection, to measure false positives on code that was not written for the test.
- The holdout is a split by language, not by pattern: a rule tuned to PHP could still generalise.
  The next corpus grows patterns within languages, not just languages.

---

## 1.25.1

The SQL corpus, and the first real numbers from it. The point of this release is not a new rule; it
is a labelled thing to measure rules against, with a holdout split and clean code that must stay
clean.

### What is new

- **Eight labelled samples** across PHP, Python, JavaScript and Java: four that put request data into
  a query, four that use a prepared statement. Every expected line is recorded, the clean files are
  asserted to have no concatenation, and the JavaScript and Java cases are a **holdout** split that
  rules are not written against.
- **The measurement.** Findings are matched to a labelled line within two lines, two rules pointing
  at the same query count once, a clean file that is flagged is a false positive, and a labelled
  line with nothing is a miss. Precision and recall are reported for the whole corpus, the training
  split and the holdout split separately.
- **The first Semgrep numbers.** With `p/sql-injection` on the corpus:

  | Split | Precision | Recall |
  | --- | --- | --- |
  | Training (PHP, Python) | 1.0 | 1.0 |
  | Holdout (JavaScript, Java) | 1.0 | 0.5 |
  | All | 1.0 | 0.75 |

  The miss is the JavaScript template literal (`${req.query.name}` inside the query). Java is found
  by two rules at the query; they count as one problem. That is a real gap in the existing engine,
  and exactly the kind of thing the corpus exists to show.
- **Joern is ready to be measured, not measured.** There is a query template in
  `scripts/joern-sql.sc`, a parser for its JSON, and the same scoring. Joern is not installed here,
  so no number is claimed for it. The decision rule is written down: Joern ships only if it finds
  the holdout cases the existing engines miss (starting with that JavaScript one) without a
  false-positive rate that a small corpus can hide, and within a runtime and disk budget worth it.
- **`npm run corpus:sql`** runs the measurement against the Semgrep MacSec installed, writes
  `corpus/sql/report.json`, and prints the three rows.

### Limits

- Eight samples is a direction, not a statistic. The next step is thirty or more across frameworks,
  plus clean code from a real application, before any engine decision is treated as settled.
- The corpus is code in the repository, not bundled into the app. It is a development instrument.

---

## 1.25.0

The measuring stick, before any new engine. Two harnesses that run without a scanner installed, and
one of them also checks the real world every week.

### What is new

- **The install harness.** Every tool in the catalogue is checked against the rules that keep an
  install honest: a real `owner/name` repository for a downloaded tool, a plain Python package for a
  uv tool, absolute paths and a plain formula for a Homebrew tool, an https homepage, a purpose, a
  unique slug. A live half asks GitHub for the latest release of every downloaded tool, so a renamed
  repository, a deleted release or an empty asset list fails the harness instead of a user's first
  review. It runs in 10.6 seconds here.
- **A weekly workflow.** `harness.yml` runs the static rules and the live check every Monday and on
  demand. Normal CI still runs the static half on every change.
- **The cross-engine runner.** The same labelled case is put through Semgrep, Psalm and PHPStan
  output formats, through the real parsers, and scored for precision and recall. Duplicate reports
  at one place count once. It uses recorded tool output, so CI needs no scanners and no network, and
  a parser change or an engine upgrade cannot silently change what is reported.
- **Two commands.** `npm run harness:offline` for the static half, `npm run harness` for the live
  half too.

### Limits

- The live half only checks GitHub releases; the uv and Homebrew tools are covered by the static
  rules, because asking PyPI and Homebrew for a version on every run would be a different harness.
- It does not actually install each tool. That is a slower, disposable-machine test, and it is the
  next step after the SQL corpus, not something to fake in CI.

---

## 1.24.1

A consistency patch. No check changed.

- **Every release page now has its notes.** The release pages from 1.0 to 1.24 had an empty body:
  the tag workflow attached the DMGs and the signature but never set the text, so the Updates page
  in the app showed a version with no notes. All of them now carry the same notes as
  RELEASE_NOTES.md.
- **The workflow sets the body on every tag**, with a step that reads the top section of
  RELEASE_NOTES.md and edits the release. This cannot drift again.
- **The roadmap is reconciled.** It lists what shipped in 1.24.0, then the 1.25 order: QA harness
  first, the SQL corpus and Joern measured on it, real redistributable fixtures, Amass against
  subfinder, bounded vhost discovery, and patch generation last and isolated.
- Nothing in the app changed.

---

## 1.24.0

The 1.24 set, in one release. Everything that can be built and tested here is in; the few items that
need a 400 MB engine, an Android SDK or an Apple developer account are listed below with what they
actually need, rather than pretended into the release.

### Code scanning

- **Psalm and PHPStan, on the project's own terms.** When a PHP project already has
  `vendor/bin/psalm` with `psalm.xml` (or `.dist`), the review runs Psalm's **taint analysis**: it
  follows untrusted input to a dangerous sink and reports only those. When `vendor/bin/phpstan`
  and a config exist, it runs the project's PHPStan and keeps **only the security messages**, so a
  type warning is not a vulnerability. MacSec uses exactly the analysers and configuration the
  project chose: nothing is installed into it, nothing is configured behind its owner's back. Both
  have their own checkbox in the scanner panel, so they can be skipped per review.
- **The SQL rules are still Semgrep's, and they already run.** `p/sql-injection` is part of every
  Standard and deep review, together with the language packs. I did not add a second, unlabelled
  SQL rule set: without a corpus to measure it against, it would add noise, not findings. That
  evaluation is on the next list, not claimed here.
- **The PHP data flow is now cross-function where the project's analysers support it.** Psalm's
  taint analysis is the cross-function engine in this release; Joern remains the candidate for a
  proper call graph, below.

### AI

- **An independent verification agent.** On any finding with code still on the Mac, the result now
  offers "Ask a second AI to try to disprove this". It starts a separate Claude Code session that
  sees the finding and a masked 80-line excerpt, never the first reviewer's reasoning, and answers
  in exactly two lines: `VERDICT` (seconded, refuted or uncertain) and `REASON`. The answer is
  stored beside the finding and never changes its confidence. Secrets in the excerpt are masked
  before it leaves the Mac, and the agent runs in plan mode with a settings file that denies the
  Keychain, SSH, cloud credentials and the rest.
- **The automated accuracy gate is unchanged and still runs in CI.** Expanding its corpus is listed
  below as not done, because a corpus written in a hurry measures nothing.

### Recon

- **The attack-surface graph.** The Surface tab now opens with a picture: the target in the middle,
  the pages or files around it, and the findings as dots coloured by severity. It is built only
  from what the session already holds, drawn locally with SVG, and clicking a dot opens its finding.
  No telemetry and no cloud rendering.
- **The existing change tracking stays** (`Since last time`): new, fixed and still there, compared
  with the previous test of the same target.

### Burp

- **Burp XML import.** An API test can now load a Burp Proxy export (`.xml`) the same way it loads a
  HAR: requests are read from the raw request lines and the Host header, one endpoint per method and
  path, duplicates removed. The cookie or token that made a request signed in is kept only as the
  fact that it was signed in; no value is stored, and a test asserts it.
- There is no Burp API integration. Burp has no free headless API to drive, so import and a
  Burp-friendly export is the honest boundary.

### What is not in this release, and what each one needs

- **Joern.** A JVM engine of about 400 MB with its own server. It is an evaluation, not an install:
  it has to find things Semgrep, Bearer and Psalm miss on the same labelled samples to earn its
  place. Next release, with a download and a benchmark.
- **Dedicated SQL rule set.** Needs a labelled corpus first. `p/sql-injection` covers the common
  cases today.
- **Automated patch generation and validation.** Needs a scratch copy, the project's test command
  and a time limit before it can be allowed to propose anything. Not rushed into a release.
- **Deeper repository-wide tracing.** Needs the call graph Joern would provide.
- **More IDOR and business-logic verification.** Existing controlled confirmations already do the
  two-account work; more coverage is a catalogue and runner change, listed next.
- **Amass.** A Go tool; passive mode only, and it needs an evaluation against the current subfinder
  pass rather than a blind add.
- **Virtual-host discovery.** Designed, not built: a bounded Host-header list against one address,
  compared with a name that cannot exist, for hosts the person owns.
- **JADX, Apktool, Ghidra, LIEF.** All are downloads with checksums and their own caches; Ghidra is
  about 400 MB plus a JDK. They belong in the tool install path, not in a UI release.
- **iOS dynamic testing.** Blocked by hardware and an account: it needs Xcode, a developer-signed
  app and a physical device. MacSec can drive Frida over USB but cannot sign an IPA for you.
- **Android emulator orchestration.** Needs the Android SDK and an AVD; a large install.
- **Objection.** A Python wrapper around Frida; the Frida path exists, Objection is an add-on.
- **AI decompiled-code analysis.** The AI reviewer already reads code; pointing it at decompiled
  sources needs the decompilers above.
- **Real APK and IPA fixtures, cross-engine regression, scanner install validation in CI.** The
  parsers and the Burp import are covered by tests (605 passing). Real binaries raise
  redistribution and signing questions that a fixture in the repository cannot answer.

### The ledger

| Item | Status |
| --- | --- |
| PHPStan and Psalm | Shipped (project-local, config-gated) |
| Dedicated SQL rules | Existing Semgrep pack; new corpus-led set next |
| Cross-function data flow | Shipped for PHP through Psalm taint; Joern next |
| Framework coverage | Existing packs; deeper checks next |
| Independent AI verifier | Shipped (on demand) |
| AI accuracy benchmarks | Existing gate; expanded corpus next |
| Patch generation and validation | Not shipped; needs a scratch copy and tests |
| Repository-wide tracing | Not shipped; needs a call graph |
| IDOR and business logic | Existing controlled checks; more next |
| Amass | Not shipped; passive evaluation next |
| Virtual-host discovery | Not shipped; designed |
| Visual attack-surface graph | Shipped |
| Asset-change monitoring | Existing since-last-time diff |
| API auth and route mapping | Improved by Burp import; deeper mapping next |
| JADX and Apktool | Not shipped; checksummed downloads next |
| Ghidra and LIEF | Not shipped; large downloads |
| iOS dynamic testing | Blocked: Xcode, signing, a device |
| Emulator orchestration | Not shipped; Android SDK |
| Frida and Objection | Frida exists; Objection next |
| AI decompiled analysis | Not shipped; needs the decompilers |
| Burp integration | Shipped as import; no free headless API |
| Integration tests and fixtures | Parsers and import tested; real binaries and CI matrix next |

Tests: 605 passed, 4 skipped.

---

## 1.23.0

The workflow release. 1.22 rearranged the flows; this one closes the loop between finding something
and doing something about it, and keeps the setup of a repeated test.

### What is new

- **Saved profiles.** A web scan or a code review can be saved as a named profile (for example
  "Staging, gentle, signed in, no active tests"), and applied on the next run with one click. A
  profile holds choices only: never a target, never a cookie, never a token, and the code refuses a
  profile that names one. Up to 50 are kept, sorted by name, replaced when the name matches, and
  removed with the small cross beside them.
- **Bulk triage with an owner and a due date.** Select several findings at once and mark them
  fixed, accepted or not a problem, with an optional owner and due date. One result, one write, and
  the open count is recalculated the same way single triage does. Clearing the selection clears the
  owner and the date with it.
- **CSV export.** Every finding as a spreadsheet: severity, tool, category, title, place, CWE,
  advisory, check id, confidence, exploit label, triage, owner, due date and the proof reference.
  Commas and quotes are handled, and a cell that would start a formula is neutralised, because
  opening a scan export in Excel should never run anything.
- **The cost is on the result.** A code review records its estimate when it starts (tokens,
  minutes, and whether it is included in a plan, free on this Mac, or roughly what an API would
  cost), and the result shows it beside the reviewer. It is an estimate and it says so.

### Under the hood

- `profiles.ts` is the store, with validation and the secret-key refusal; `ProfileBar` is the same
  control on both pages, so the two cannot drift.
- `findings:triage-bulk` is one IPC call with an id list, validated and capped, and it writes once.
- `sessionCsv` lives with the other exports, and the CSV is a normal Export menu entry.
- `SessionInfo.estimate` is filled by `startReview` from `shared/estimate.ts`.

### Limits

- CSV only, as agreed: no Jira, no Linear, no external service. Everything stays on the Mac.
- No pull-request creation yet. The fix plan and the CSV are the path out; a PR bot is not.
- A profile is local to this Mac. There is no shared or team library.

---

## 1.22.0

The flow release. The web scan and the code review were both arranged around what the tool needed
rather than what a person is deciding. This release rearranges both, adds the summary and the pace
control that were missing, and gives the whole app one place to start.

### Web scan

- **The steps now follow the decision.** Which site, signed in or not, how much to cover, from
  outside or with the code, which confirmations, then the AI. The old third step mixed black and
  white box with Autopilot and the checklist, and put the reviewer's dependency in a different step.
  Autopilot and the checklist now sit with the reviewer that runs them, and are disabled with a
  reason until one is chosen.
- **The consent belongs to one host.** The ownership tick and the active-tests tick reset when the
  target changes, and so does the pasted session. A tick for one site can no longer carry to another.
- **Presets say what they are.** The quick choices show which one is active, and none of them turns
  on ffuf content discovery any more: discovery is its own switch, because it is hundreds of
  requests, not a detail of "Public site".
- **A summary bar that stays in view.** Above the Start button: the host, the mode, the pace, whether
  you are signed in, how many confirmations, the AI choice, and an estimate of the requests and
  time, with the biggest contributor named. If Start is disabled, the bar says why.
- **A gentle pace.** The new pace control sends about a quarter of the requests a minute and pauses
  longer between them, for a live site that must stay responsive. The estimate changes with it.
- **Sign-in expiry is noticed.** If several member pages answer as if signed out during the
  signed-in walk, the scan adds one clear note and says the results below may be missing pages,
  instead of reporting them as hidden or clear.
- **The code (white box) step is its own step** with a clear reason when it cannot start. The Burp
  button is now a secondary button in the summary bar.

### Code review

- **One product, one name.** "Just my changes" and "Test it fully" moved off the Code review page.
  They are special audits, and the page now points there once instead of carrying a second flow with
  its own state. The full test launcher on the Overview goes to the audit page too.
- **One obvious AI choice.** The published deep audits (Cloudflare, Anthropic) are behind an
  "Advanced" disclosure with a plain description that they replace the standard reviewer. The
  normal reviewer and skill choices are the default path again.
- **Scanner controls.** A new advanced panel lists every scanner with a checkbox, and a deep review
  can skip the Git history. That is the difference between five minutes and an hour on a large
  repository.
- **An estimate before you start.** Tokens, rough time, and whether the reviewer is included in a
  plan, free on this Mac, or an API bill. It says estimate, because it is one.

### Navigation and interface

- **Start a test.** A new page with four cards (code review, web scan, API security, special
  audits), a list of the other checks, and the last four results to pick up again. The New test
  button and a new rail entry both open it, so the rail is no longer the only map.
- **Cmd+K.** A command palette over every page, every result and every finding in the index. Arrow
  keys and Enter, Escape to close, and a Search entry in the rail shows the shortcut.
- **Tabs only where they have content.** OWASP no longer appears on a code review; only web, API and
  mobile results show it.
- **Rounded edges clip their children.** The rail, toasts, dialogs and jobs no longer let a close
  button, a count or a badge poke past the rounded corner. The rail's active marker sits inside the
  edge now.
- **Switches are labels.** A switch and its title are one clickable row, with the explanation under
  it. The web scan uses this for every confirmation and for the two AI extras.
- **Smaller polish.** The action bar is sticky with a blurred background, the page header wraps on
  narrow windows, the result tabs scroll, the Engine bar truncates long titles, and the start cards
  and palette follow the rest of the design.

### Under the hood

- `shared/estimate.ts` holds both estimators, so the UI and the tests agree. `tests/v42` checks the
  scaling and the wording.
- The web scan accepts `pacing: 'gentle'`, which lowers the rate for Katana, Nuclei and ffuf and
  lengthens the pause in MacSec's own client. The request carries it through `validWeb`.

### Limits

- This release is the flows, not the workflow. Saved profiles, bulk finding triage with an owner
  and a due date, and CSV export are the next release, as planned.

---

## 1.21.0

The documentation release, and the last of the open items.

### What is new

- **Every release has proper notes again.** Versions 1.14 to 1.21 were shipped with short summaries; this release writes them out in full, in the same style as the notes before them: what changed, how it works, and what is deliberately missing. They are in this file and summarised in the README.
- **A release history in the README.** A short table with the headline of every version since 1.14, so a new reader can see where the product came from without opening this file.
- **The session index.** Search used to read every `findings.json` on the Mac. It now reads a small SQLite file in `~/MacSec/config/index.db`, written with the SQLite that ships inside the app's runtime. It is updated whenever a session or its findings are saved, cleaned when a session is deleted or pruned, and rebuilt by itself on the first search of an older install. If the runtime ever lacks SQLite, the app falls back to reading the sessions and says so once in the log, so search cannot break a Mac.

### Cleaner interface

- Result tabs scroll instead of running off the window, and the page header wraps on a narrow window instead of crushing the title.
- The Engine bar truncates a long test title and hides its step line on a narrow window, instead of pushing the New test button away.
- Assets had two refresh controls doing the same job; it has one.
- The delete button on a result now has a native tooltip as well as the custom one, so it is readable however you reach it.

### Still open, honestly

- **Notarisation.** This needs an Apple Developer account, which the project does not have, so the app stays ad-hoc signed and first launch asks for "Open Anyway". Update integrity does not depend on it: releases are signed with an Ed25519 key and the app refuses an unsigned release. If the project ever gets an account, notarising is a workflow change and nothing else.
- **Windows and Linux.** MacSec is a macOS workbench, and the tooling, Keychain use and process handling all assume it.

---

## 1.20.0

The release that let MacSec gate a build, and let a person find things.

### What is new

- **MacSec from the command line, with baselines.** `MacSec --headless scan --path <folder>` runs a full review with no window, no tray and no IPC. It exits 0 when the result is clean or only contains findings in the baseline, 1 when a new finding reaches `--fail-on` (default high), 2 on an error and 3 when the scanners are not installed. `--json` prints one object for a pipeline, `--install-missing` installs the three scanners a review always needs, and `--depth` chooses quick, standard or deep.
- **A baseline a team can commit.** `MacSec --headless baseline --path <folder>` writes `<folder>/.macsec-baseline.json`. The identity of a finding is the check that made it plus where it is, so a finding that moves is still new, and a fixed finding cannot hide a different new one. Info findings, triaged findings and false positives never fail a build. `--no-baseline` always works, because a baseline must never be the only way to see a finding.
- **Find a finding anywhere.** The search box on Results now reaches inside every finished session, not only the session titles: titles, tools, file names and addresses, newest first, each row opening the session it came from.
- **Storage you can see and let go of.** Settings shows how much the MacSec folder holds and how many sessions and findings it keeps. It removes finished sessions older than the age you choose, with a clear second click and the number it removed. Nothing is swept in the background.
- **An accuracy gate in CI.** `npm run benchmark` scores the checks that carry the most weight (exposed files, key placeholders, WAF deception and attack paths) against samples that are known bad and samples that are known fine. It fails below 0.8 precision or recall, and it runs as its own CI step, so accuracy is measured on every change instead of being believed.
- **Accessibility that was overdue.** Small faint text went from about 3.5:1 to about 4.6:1 contrast, tooltips now appear on keyboard focus as well as hover, the findings list answers to arrow keys and Home/End, and the result tabs answer to the left and right arrows.

### Under the hood

- `cli.ts` and `baseline.ts` hold the rules, so the argument grammar and the comparison are unit tested without Electron. The headless branch runs before any window is created and flushes stdout before exiting.
- The release workflow now runs `MacSec --headless help` and `--headless bench` against the built app, so the command line is exercised on real hardware on every release.

### Limits

- The search at this version read the newest 300 sessions on every query. That is fast enough for a few hundred sessions and not for thousands; 1.21 adds the index.

---

## 1.19.0

A trust release. Everything in it was a finding from the second review that was still open.

### What is new

- **Session credentials no longer reach scanner tools.** httpx, Katana, Nuclei and WPScan now run signed out. The signed-in walk is MacSec's own client, capped at 120 requests on the target's own host, and the header check follows a redirect only when it stays on the same host. A pasted cookie can no longer ride a redirect to a third party.
- **DNS is really pinned.** A guarded request resolves the name once, refuses metadata and mixed answers, and then connects to the address that was approved, keeping the name in the Host header and in TLS SNI. The rebinding window that the guard described but did not close is closed.
- **Evidence is masked everywhere.** The lines around a finding are redacted whatever the finding is about, so a key that happens to sit next to a SQL injection no longer reaches a report, a SARIF file or an issue.
- **Releases are signed.** `SHA256SUMS.txt` carries an Ed25519 signature from a key that only the release workflow holds. The app verifies the signature before it verifies the hash and refuses an unsigned or wrongly signed release. The public half is in the repository; the private half is a GitHub Actions secret, and the workflow fails rather than publish an unsigned release.
- **The reviewer cannot read your credentials.** Each review writes its own Claude Code settings file that denies `.ssh`, `.aws`, `.gnupg`, Keychains, `.netrc`, `.npmrc`, `.docker`, `.kube` and the like, and the prompt says plainly that code is data, not instructions.
- **A proof reaches its finding.** When a controlled run proves a step that was planned from a finding, that finding becomes confirmed, wears the proof, and names the engagement and the run. It is shown on the finding and in the PDF, and the run reports how many findings it proved. This was the keystone the second review said was missing.
- **Attack paths carry a confidence.** A path is `likely` when every part is confirmed or proven, and `possible` otherwise. Overlapping rules no longer show the same pair of findings twice.
- **Smaller fixes.** The Metasploit callback listener binds only the address the target will call back to. The API "answers without signing in" check ignores login pages. Quick web scans skip the deception sampling again. Assets loads when opened instead of on every session update. An uncaught error in the main process is logged and shown instead of disappearing. `SECURITY.md` and `THREAT_MODEL.md` were added.

### Limitations that remain

- The headless command line, the session index and the benchmark did not exist yet.

---

## 1.18.0

Attack paths, more skills, and a rebuilt Assets page.

### What is new

- **Attack paths with a place to break them.** Findings that add up are shown as a path: how the attack would go, what it needs, what it reaches, and the one cheapest fix that removes it. Six new paths cover an upload served as a page, a key that opens a cloud service, a debug page with secrets behind it, CORS over real user data, a GraphQL API that trusts the account it is asked about, and no limit on guessing with an account to guess. The paths appear in a tab of their own on a result, in the executive PDF, in the fix plan and on Assets. A path is built only from findings that were really found, never from a guess.
- **Four more skills, wired to the functions that use them.** `attack-chains`, `api-authorization`, `js-deep-analysis` and `privilege-escalation` are loaded by the web, API, server and code-review AI, not merely listed. The total reached 48.
- **jsluice, through Katana.** The web scan runs Katana with `-jsluice` in Standard and Thorough, and reads the endpoints it pulls out of the JavaScript, resolved against the script they came from and filtered to the target's host. No new download and no Go toolchain.
- **Assets rebuilt.** It opens with what the score means and its four bands, filters by kind, sorts worst first, and shows per asset: the spark, the counts, what is proven, how long fixes took, the fix list with the score each action returns, and the attack paths with the place to break them.

### Limits

- A path is a story built from findings, not a test that the chain works, and the interface says so.

---

## 1.17.0

WAF deception, a real Metasploit proof, and the update check fixed.

### What is new

- **WAF honeypots and deception.** Public research on port mimics, dynamic path spoofing, decoy files and tarpits is now in the app. A port mimic that answers every connection is labelled as deception rather than as services. Random paths that answer 200 with the same structure are caught by comparing structure instead of size, because the lengths are nudged to defeat size filters. Decoy `.env` and `.sql` files, slow tarpits and the usual vendor fingerprints (Cloudflare, Imperva, Akamai, F5, AWS, Sucuri, Wordfence, ModSecurity) are recognised too. The scan adds one explained note and turns matching results down to info. Nothing is hidden and nothing is reported as a vulnerability.
- **A `waf-deception` skill**, and the scan's AI is told to judge noise as noise and to point at the few results that do not fit the pattern.
- **Metasploit runs, with a callback as the proof.** One approved module from a short run-only list, always with `cmd/unix/generic` and a single curl or wget back to a listener on this Mac. The callback carries the target's address and a one-off marker, so a run with no callback is `not-proven`. No session, no handler, no meterpreter, no persistence. It refuses unless the engagement marks a staging target this Mac can reach. EternalBlue, BlueKeep, Spring4Shell, ProxyLogon and Drupalgeddon 2 are deliberately absent: they crash a host or write a file MacSec cannot remove.
- **API security: a described sign-in that is not enforced.** When a spec says an endpoint needs a token and the same request with no token answers with data, MacSec reports it.
- **JavaScript: what is new since last time.** After the JS pass, endpoints and routes are compared with the previous scan of the same host, and the new ones are listed first, because new code is where new bugs are.
- **The update check cannot fail silently.** It tries the GitHub API, then the release feed, then github.com itself, and the Updates page shows the reason with a Try again button if all three fail.

### Limits

- The Metasploit run list is reasoned about, not tested against every target.

---

## 1.16.0

More of the bug-bounty toolkit, with the same rules.

### What is new

- **gau in recon.** URLs the internet already knows about a domain, from the Wayback Machine, Common Crawl and others. Passive, never touching the target. They join the same in-scope list, add parameter names, and interesting ones become leads with a step of their own.
- **wafw00f in the web scan.** It names the firewall during the confirmation step. Identification only, never an attack.
- **sqlmap as a controlled proof.** One parameter, GET only, `--risk=1 --level=1 --technique=BE`, one thread and no retries. No dump, no shell, no file read or write, no tamper, no forms. It reserves its requests against the engagement before it starts, deletes its own session folder, and only a naming of the parameter and the technique becomes a finding.
- **Recon hands over to the scan.** "Scan this site" on a recon session starts a web scan of its first live host with up to 300 same-host pages from the recon already in the list, so discovery is not thrown away between the two halves.
- **Web scan and API.** Inline JavaScript is crawled in Standard as well as Thorough, recon pages seed the crawl before Nuclei and the JS pass, and API security can load a specification straight from an address, which is what an `openapi.json` a scan finds needs.
- **Homebrew installs.** Nmap, WPScan, radare2, Ghidra and the Google Cloud CLI install from their own row, only when the button is pressed, with the command written to the log first. Nmap, WPScan and radare2 now show their installed version.
- **Policy update.** ffuf and sqlmap left the "listed only, never run" list; they are managed, bounded tools now, and the policy test asserts it.

### Limits

- Metasploit driven by the engagement, and the headless command line, were still ahead.

---

## 1.15.0

ffuf, and the read to write ladder.

### What is new

- **ffuf as a bounded discovery engine.** The web scan can ask for 200 to 435 common paths at 20 requests a second, signed out, with ffuf's own calibration. Every path that answers is asked again by MacSec, compared with a path that cannot exist, and only then reported with a proof. Each hit joins the pages Nuclei and the JavaScript crawler test next.
- **Your own word lists.** Lists in `~/MacSec/extensions/wordlists/*.txt` are validated (plain paths only) and used before MacSec's own 435 paths.
- **Two new controlled-proof rungs.** Content discovery under the engagement, which reserves its whole request count in one audited line, and an anonymous read that proves a private page opens with no cookie and no token.
- **The ladder.** The planner chains a write step so it runs only after a read on the same site is proven, and the run still stops at the first proof of each goal.
- **Steps can be filled in before they run.** The expected string, the read-back address, the method, headers, body and undo sentence are edited in the plan and re-validated on the server, so the run uses the plan that was approved.

### Limits

- Discovery is hundreds of ordinary GETs; a firewall will log it and a fragile host may feel it. The interface says so.

---

## 1.14.0

The controlled-exploitation release. The one that changed what the product can do.

### What is new

- **Controlled proofs.** A new page proves what someone could actually do on a site the person is engaged to test, and stops at the first result. It needs a written engagement first: client, authority reference, who gave it, the hosts it covers, the window, and caps for requests and writes. Every step says in advance what it sends, what it aims to prove and what it will not do. The person ticks the steps, types `EXPLOIT <host>`, and the run sends requests one at a time, logs each one with the values hidden, and stops when the goal is proven.
- **CIA, said out loud.** Every proof aims at confidentiality, integrity or availability, and the run reports which was proven and which was not.
- **Four built-in proofs and an escape hatch.** Read a system file through a parameter, template arithmetic, write one file and read it back, time one request against three, and replay one pasted request.
- **Chaining and escalation, planned cheaply.** Planning uses the findings already on the Mac with no AI call. The optional AI planner sees only a short digest of findings, is called once, and can only pick from the catalogue; MacSec validates every field. A step can chain from another, a read before a write on the same page, and the run stops as soon as each goal is proven.
- **The engagement is the gate.** No engagement, no run. Revoking one stops everything. Caps are counted from the runs stored on disk, so restarting the app does not reset the budget. Write steps need the leftover acknowledgement, and every write is removed again or listed with exactly where it is.
- **Metasploit's check list is scanners only.** The exploit modules were removed from it, because several of them run code during their check (Shellshock and Struts2 do), so "check only" was not true. A test now refuses exploit names in both lists.
- **Smaller fixes.** A window that fails to draw shows an error panel with a copy button instead of going blank. Deleting a session takes two clicks. The input validators moved to `src/main/validate.ts`, so they can be tested without Electron.

### Limits

- Deliberately absent: shells, data dumps, password guessing, persistence, evasion and concurrency. The availability proof is a measured slowdown, never a flood.

---

## 1.13.0

- **Watch an app's network traffic.** On the Mobile apps page, install mitmproxy with one button (free, stays inside MacSec), start listening, point your own test phone or emulator at it, use the app, and press Stop. MacSec then lists plain http, passwords and tokens sent in the clear, secrets in web addresses, cookies without the Secure flag and every server the app talked to, each with proof. You can also check a .har file you already have (from Burp, Charles or a browser).
- **Safe by design.** MacSec only listens on this Mac or its own local network address, never changes your phone, deletes the capture file as soon as it has been read, and keeps only names, never values.
- Limits: an empty capture does not prove certificate pinning, and Android apps from Android 7 on may ignore the capture certificate unless the test build allows it.

## 1.12.0

- **DKIM checks.** For a domain that sends mail, MacSec looks up the common DKIM selectors and reports keys that are too short (under 1024 bits), keys of 1024 bits, withdrawn keys and keys left in test mode. Each comes with the DNS record as proof. A selector that is not found says nothing, because DKIM has no public list of selectors.
- **DNSSEC check.** MacSec asks Cloudflare's public DNS service (the domain name only) whether the domain is signed. An unsigned domain is shown as an information note, never as a confirmed problem.

Still not built: KICS and Amass (their download files could not be checked here, so they are not added blind; Checkov and Hadolint already cover infrastructure files), LinkFinder and SecretFinder (the script scan already reads a site's own scripts), SQLFluff (a style linter, not a security tool), virtual host discovery, and the bigger AI items.

## 1.11.0

- **Safer scans.** A network guard now sits in front of every confirmation test. It stops a scan if a site name points at a cloud metadata address, answers with a mix of public and private addresses, or switches from public to private halfway through (DNS rebinding).
- **One finding, not three.** When two tools report the same problem in the same place, MacSec shows it once and says "Also found by" the others. Proofs are never merged away.
- **How sure are we?** Every finding now says Confirmed, Likely, Suspected, Unverified or Ruled out, and shows its OWASP ASVS chapter when the weakness type is clear.
- **Accuracy score.** A small scorer counts hits, misses and false alarms (precision and recall) for a check against a known bad and a known good sample. It is used in tests.

Not in this release: CodeQL (its licence does not allow free use on private or commercial code), Joern, KICS, Amass, LinkFinder, SecretFinder, SQLFluff, DNSSEC and DKIM checks, virtual host discovery, source-to-sink data flow, AI agents for IDOR and business logic, an AI verification agent, patch generation, and one database with attack paths across all engines. The guard covers confirmation tests; the web posture and script checks do not use it yet.

## MacSec 1.10.0

DeepSeek is now a choice in every reviewer list, and mobile checks can produce a full report.

### What is new
- **DeepSeek in the reviewer lists.** Once the DeepSeek servers and your key are saved (Tools, Model servers), "Claude Code on DeepSeek" and "DeepSeek (API)" appear in the reviewer choice of code review, web scan, API scan, mobile and recon. One click sets the server and the model, so nothing else has to be chosen first. Both say that the code or findings are sent to DeepSeek.
- **MASVS report.** On a mobile check, Export now has "MASVS report". It is one page you open and save as a PDF (Print, then Save as PDF): the summary, what was checked, all 24 MASVS controls with their status and the OWASP Mobile Top 10 category, every finding with its confidence, evidence, steps to see it again and how to fix it, and a list of what a person must still test by hand. Values of keys and passwords are never in it.

### Not in this release
- JADX, Apktool, Ghidra and LIEF, iOS and Android runtime testing (emulator, Simulator, Frida, Objection, traffic capture), the Burp connection and the AI that investigates decompiled code. These need tools and devices that MacSec cannot try here, and several would need new safety rules first. They come one at a time, each tested before it ships.

## MacSec 1.9.0

Mobile checks now cover more file types and more of the app, and the app shows which OWASP MASVS controls are met.

### What is new
- **OWASP MASVS 2.0 checklist.** On every mobile check, the OWASP tab now starts with all 24 MASVS controls (storage, crypto, authentication, network, platform, code, resilience, privacy). Each one says **Needs work** (with the findings), **Clear** (the checks that can see it ran and found nothing), **Partly clear** (nothing found, but a person must still test part of it) or **Needs a person** (no automatic check can see it, such as biometrics, PIN and OTP flows, session handling and business logic). Controls a person must test say what to do by hand. "Clear" is not a pass mark for the app.
- **More app files.** Besides .apk and .ipa: Android App Bundles (.aab), .apks sets (the base .apk is read) and Xcode archives (.xcarchive). An Xcode project folder works as source.
- **Deep links.** Custom link schemes that other apps can claim, and web links that open the app without verification.
- **Entitlements and privacy.** A Keychain group shared with every app of your team, universal links and shared sign-in domains, and the iOS privacy manifest (missing, or declaring tracking).
- **Third-party SDKs.** The SDKs found in the app (analytics, advertising, crash, payments, support, session replay), with a warning for tracking ones in a banking app.
- **Addresses in the app.** The full web addresses written into the code, with the API-looking ones first, as the starting map for API testing.
- **Vulnerable libraries in source.** Source projects now also run osv-scanner on their library lists.

### Limits
- The .aab manifest reader was tested on a manifest built by hand to the aapt2 format, not on a real store bundle. If a bundle's manifest cannot be read, the check says so.
- For an .aab or .apks, signing is not checked (the store signs a bundle itself) and the network rules file is not decoded.
- SDK names are found from names in the code: an obfuscated app can hide some of them.
- Not in this release: running the app on an Android emulator or the iOS Simulator, Burp traffic interception, Objection and a PDF report. The live test is still Android only, on a phone you confirm.

## MacSec 1.8.1

DeepSeek works with Claude Code, and online models are shown as online.

### What is new
- **DeepSeek for Claude Code.** A new ready-made server, "DeepSeek for Claude Code" (Tools, Model servers), uses the same DeepSeek key in the format Claude Code speaks. Add it, pick its model, then choose the reviewer "Claude Code on your model". The key stays in the Keychain and is handed to Claude Code only for that run. The existing "DeepSeek" server still works for the reviewer "Your model" (the API).
- **Online models are labelled.** When the chosen model is not on this Mac, the reviewer list moves it to the online group and says that the code is sent to the provider, instead of "Nothing leaves this Mac".

### Limits
- Not tried against a live DeepSeek account here. The model names (deepseek-v4-pro, deepseek-v4-flash) come from DeepSeek's documentation; if DeepSeek renames them, pick another name in the list.

## MacSec 1.8.0

MacSec now knows what firewalls do to confuse a scanner, remembers what you tell it is not a problem, and checks library versions more carefully.

### What is new
- **Firewall and decoy knowledge.** Shields such as Imperva, Cloudflare, Akamai, F5, AWS, Sucuri and Wordfence are recognised by their headers, cookies and block pages. When one address shows a crowd of open ports (or many database, mail and remote-access ports at once), MacSec reports one info finding instead of dozens, keeps only the web ports and does not run service checks on the rest. When four or more sensitive file names answer at once (trace.axd, db.sql, .env and so on), they are turned down to info as "probably a decoy" and one summary says why. Nothing is hidden: you can still read each one.
- **See it, then say "this is not it".** Keys found in a site's scripts now show the line they were found on, with every value cut to its first four characters and its length. Example values (YOUR_API_KEY, xxxx, AKIA...EXAMPLE and the like) are turned down to info on their own. Source maps and keys that belong to public libraries (jQuery, Bootstrap, files from a public CDN, node_modules) are turned down to info too.
- **Not a problem, remember.** On any finding, choose "Not a problem, remember" (this site) or "on every site". Later scans mark it "Not a problem" and stop counting it. The list is in Settings, with a button to report it again. Only the finding's id or title and place are kept, never a secret value.
- **Library versions and series.** A version is only checked against known flaws if it fits a series that exists (Bootstrap 1 to 5, jQuery 1 to 4 and so on). When a file name and the code's own banner disagree, MacSec says so and uses the code. Each library says which series it belongs to and whether that series still gets fixes.
- **Find My Mac.** MacSec now reads your iCloud account settings as well as the system flag, and says "could not tell" instead of "off" when the two do not agree. The account format is written from documentation, not tested on every Mac.
- **This Mac.** The "Fix these first" panel is now a tidy numbered list, in the same style as the rest of the page.
- **AI helpers no longer load your own tools.** The AI helpers MacSec starts now run with `--strict-mcp-config`, so Claude Code does not start the MCP servers from your own setup. This is the most likely reason a tool such as Serena opened its dashboard in your browser while MacSec ran an AI review. It is not proven: another program can start it too.

### Limits
- Decoy detection is by pattern. A real server with many open ports, or a real site with several backup files, can look like a decoy: those are listed as info with the reason, not hidden.
- MacSec still never installs Metasploit or other attack tools. If it is installed, the checks run as before.

## MacSec 1.7.0

Sign-in protocols, tokens, GraphQL and cross-site checks, an AI autopilot, and Metasploit with approval for every module.

### What is new
- **OAuth and OpenID Connect checks** (a new switch in the web scan's control confirmations). MacSec reads the sign-in links a site sends and the provider's own settings page, and reports: no state value, a state that never changes, the implicit flow, no PKCE, an http callback, tokens in addresses, "none" signatures, "plain" PKCE and open client registration. On a provider that is on the site itself, it also sends made-up callback addresses (ending in .invalid, which cannot exist) and reports a server that redirects to them. Nothing is signed in and no outside provider is contacted.
- **Token (JWT) checks.** Tokens from your own sign-in are read for a missing signature, a weak signing secret (the secret is never written down), no expiry or a very long one, secrets in the claims, a token cookie without HttpOnly, tokens in addresses and in public pages. MacSec also sends your own token back with its signature removed and with "alg: none" (claims unchanged, GET only) to a page that treats you differently from a visitor, to see whether the server checks signatures.
- **GraphQL checks.** Finds endpoints, an open schema (introspection), an open IDE (GraphiQL, Playground), field suggestions when introspection is off, stack traces in errors, mutations accepted over GET, form content types that skip the CORS check, and batching. It only asks questions: mutations are refused in code, and nothing deep, wide or long is sent.
- **CORS, CSRF and session ids.** CORS that repeats a made-up origin with credentials allowed (higher when signed in), forms with no anti-forgery token (a lead, never submitted), session ids in links, and a server that keeps a session id the visitor made up.
- **Autopilot.** After the normal steps, the AI reads what was found and picks up to 14 more checks from a fixed menu, in up to three rounds, following leads as they appear. MacSec validates and runs each one with its own rules and proof. The AI never sends a request or writes a finding.
- **Metasploit with approval.** The server scan now lists every module with what it sends and what could go wrong, and nothing runs unless you tick it. There are two kinds: Metasploit's own checks for known flaws, and look-only scanners that read a version, banner, title, methods or certificate. No exploit, login, brute force or flood module exists in the lists.
- Your checklist now marks OAuth, JWT, GraphQL and CORS items from these checks. Items these checks can only find (CSRF, session ids) are never marked "clear" for you.
- New check ids: MS-OAUTH, MS-JWT, MS-GQL, MS-CORS, MS-CSRF, MS-SESS and MS-AI.

### Honest limits
- Only providers that are part of the site itself get callback tests: a site that signs in with Google, Microsoft or Okta is tested for what it sends, not for what the provider does.
- CSRF and session fixation after a login need a form to be submitted or a login to be made, so they are leads for you to test by hand.
- GraphQL depth, size and batching limits are left for you to test on a copy: they can bring a server down.
- The Metasploit module names and output lines were written from its documentation and not tried against a real install here. A module that is missing or prints something unexpected gives no finding.
- None of this was run against a real third-party site. It was tested against local servers with a weak and a hardened version of each case.

## MacSec 1.6.0

Deeper testing everywhere: web scan with black box and white box, a checklist walk, injection tests, a deeper This Mac, deeper recon, deeper server scans and a safe Metasploit check.

### What is new
- **Web scan: black box or white box.** Black box tests the site from outside. White box also reads the code folder you pick, finds every route and parameter, and tries the private routes signed out to prove which ones are open.
- **Injection tests on every page and form.** After a login, MacSec reads the pages it can reach and tries each input with harmless markers: unescaped output, a database error from a lone quote, a server that calculates a sent expression, and a line break reaching a header. Every hit is repeated and keeps its proof. POST forms are listed, never submitted.
- **Walk my checklist.** Your own checklist (52 sections, 638 items) is walked item by item. MacSec marks what it tested itself, the AI reviewer you chose (including your Claude login) judges the rest using only the evidence found, and anything unproven stays manual. A new Checklist tab shows it all.
- **This Mac, much deeper.** Root and admin accounts, screen lock, login window, secrets in files and shell history (never shown), .env files, XProtect age, third-party extensions, rejected apps, outdated Homebrew packages, SSH server settings, cron jobs, Wi-Fi security, saved open Wi-Fi, internet sharing, DNS servers, and a "Fix these first" panel.
- **Deeper recon.** Each host gets its own headers, TLS, protection and banner checks, DevOps probes, DNS takeover signs and live CVE lookups.
- **Server scans with depth.** Each open service is asked for its version and checked against live CVE data, data stores that answer without a password are proven, and web services behind other ports are tested as web apps.
- **Metasploit, check only.** Optional switch on the server scan. A fixed list of modules, only the module's own `check`, never run or exploit. Proven results keep the command as proof.
- **Removed the self-test** from the app (it was confusing). It now lives only in the test suite.

### Honest limits
- POST forms and bugs that need a data change are listed as leads, not proven.
- The Metasploit module names were not tried against a real install here: a module that is missing is reported as unsupported, never as a finding.
- The This Mac checks were tested with sample output, not on a real Mac.
- Real WAF and real phone behaviour are still unverified.

## MacSec 1.5.0

Business logic checks, a risk score for everything you test, and ways to hand findings on.

### What is new
- **Business logic checks** (a new switch in the web scan's control confirmations). It proves what can be proven without changing anything: an open redirect (a made-up address in "next" or "return" is followed), a site that writes a forwarded host name into links (password reset poisoning), and a code or PIN form that accepts ten wrong codes in a row. It also lists leads for you to test by hand: prices, roles and ids sent as hidden form fields, late steps of a checkout that open on their own, and numbered records. A lead says "possible" and has no proof, and nothing that would change data is ever tried.
- **Quick choices** for the control confirmations: public site, login and accounts, shop or booking flow.
- **Assets.** A new page with one line per site, API, domain, app or project: a risk score from 0 to 100, how it moved scan by scan, how many days fixes took, and what to fix first.
- **Fix these first.** On every result: the few actions that take off the most risk, with the score before and after.
- **How these connect.** Small problems that become serious together (an open Git folder and a key in it, a way to find accounts and no limit on guesses) are shown as a chain, only when every part was found.
- **Check ids.** Every kind of finding has a stable id (for example MS-WEB-001) shown on the finding, so reports and re-tests can name it.
- **Re-test one finding** without running the whole scan: it repeats the proof request and tells you if it is still there, changed or gone. It never marks anything fixed by itself.
- **Copy as a ticket** (Markdown or Jira text) and **create a GitHub issue** with the token already in your Keychain.
- **Pause and resume** a running test.
- **Quiet hours** for automatic checks.
- **A one-page summary PDF** for people who decide.
- **A self-test** on the Tools page: MacSec starts a deliberately weak local app and a correct look-alike, and every planted weakness must be found with nothing reported on the correct one.

### Honest limits
- Real business logic bugs that need a data change (a price changed in transit, a coupon used twice, a race) are never proven by MacSec. You get leads and a test plan.
- Jira is copy-as-text only. Recorded login replay is not built.
- Pause stops the tools and MacSec's own requests, but a tool's own timeout keeps counting.

## MacSec 1.4.0

A JavaScript analyzer, the setup behind a site, live vulnerability counts, and an honest label on every finding.

### What is new
- **Every finding says how far it is proven.** Proven (a harmless request showed it, and the proof can be repeated), Known exploited (the version is on CISA's list), Likely (a high chance of use) or Not proven (a lead). Each has a risk score from 0 to 100 and a one-line reason, and the report header counts them. Nothing runs an exploit: "proven" means the problem itself was seen and you can repeat it with the command in the proof.
- **A guard against over-claiming.** A finding that says "confirmed" without proof is turned into "possible" before it is saved.
- **The JavaScript analyzer.** For web scans and recon: it reads every script the site serves, follows lists of hidden chunks (lazy admin screens), and names the routes, API endpoints, GraphQL operations and build variables. It finds public source maps, rebuilds the original source into the session folder (with an "Open the rebuilt source" button) and looks for keys in it. It also flags message listeners that never check the sender, internal addresses, developer comments about security, and cloud storage names. A new "JavaScript map" tab shows it all.
- **The setup behind a site.** Which firewall or CDN answers, what hosts it, SPF, DMARC and CAA, and a CNAME that points at a service nobody owns any more. DevOps and infrastructure left open: Jenkins, Grafana, Prometheus, Kibana, Elasticsearch, Consul, etcd, Kubernetes, Docker, container registries, Traefik, Argo CD, Portainer, RabbitMQ, SonarQube, Terraform state, cloud credentials and CI files. The public .git folder is read for the GitHub repository it names and for a password in its address. API scans get the same checks around the API.
- **Live vulnerability counts.** Versions found in server banners, scripts and the DevOps tools are looked up in the public NVD database, marked when they are on CISA's known-exploited list, and given FIRST's EPSS chance of use. The count is always a version match, so it says "possible".
- **A test plan for APIs**, like the one web scans already get, and the same expert notes in the AI report.
- **A cleaner AI choice.** Grouped as "On this Mac", "Cloud AI" and "No AI", one line each, with the detail of the chosen one shown below.

### How it stays safe
- All of it is GET requests, to the site itself, with a request cap, a pause between requests and a stop when the server struggles.
- A hit is recognised by what the answer contains, never by the status code, and a data probe refuses an HTML page. Every hit is repeated once, and one that does not repeat is dropped.
- Tests build sites designed to fool the checks (random content on every page, everything forbidden, everything sent to login, everything echoed back) and make sure nothing false is reported.

## MacSec 1.3.0

Deeper app checks from the file alone, a test plan from your own checklist, and Invariant's knowledge in the AI report.

### What is new
- **Apps are checked from the file, with no phone needed.** For an `.apk` or `.ipa`, MacSec now reads the app's compiled code and signing: certificate pinning present or missing, root and jailbreak checks, certificate checks that accept everything, weak encryption (ECB, DES, RC4, MD5, SHA-1), WebView risks, old TLS, plain `http` addresses, every server the app names, the old v1-only signature, and the Android debug certificate. Facts such as signing are confirmed with proof. What the code merely names is marked "possible", because it may be unused. The live phone test is still there for what only a running app shows.
- **Online checks for cloud addresses (optional).** Tick the box on the Mobile apps page and MacSec asks once, read only, about each Firebase database, S3 bucket and Google Storage bucket found inside the app. An open database or a listing bucket is confirmed with a command you can repeat. File and key names are never saved.
- **A test plan for every web scan.** Your web assessment checklist is built in (52 sections, 638 items). After the crawl, MacSec works out what kind of site it is (login, sign-up, one-time codes, password reset, profile, upload, checkout, GraphQL, API, admin and more) and writes a plan of what to try by hand, in order, with the items it already tested marked. It is saved with the session and shown under the report.
- **Invariant's knowledge and skills in the AI report.** 151 expert notes (authorization, authentication, business logic, APIs, mobile and more) are matched to what was found and given to the AI, together with four method skills: verify with proof, find hypotheses from invariants, check novelty and impact, and write the report. The report now ends with "What to try next".

### How it stays safe
- The static checks only read the file. The online checks are off by default and make at most six read-only requests per kind, never following a redirect.
- Nothing from the checklist or notes is sent anywhere by MacSec: they are only text given to the AI you chose.

## MacSec 1.2.0

The live phone test: run an Android app on a test phone and watch what it really does.

### What is new
- **Run it on a test phone (optional, Android .apk).** On the Mobile apps page, tick "Also run this app on a test phone", choose an emulator or a phone you own, and confirm you may test the app. MacSec installs the app, starts it, watches it for about half a minute, and removes it again if it installed it.
- **What it proves.** Servers the app talks to, and any request sent over plain HTTP. Whether certificate pinning is in use. Whether the app checks for a rooted phone. Passwords and tokens written to the phone's log, and passwords and tokens kept in plain text in the app's own files. Each finding has proof you can repeat with an `adb` command, and secret values are never saved, only the kind, the file and the name.
- **Frida only watches.** Every hook calls the original and returns what it returned, so the app behaves as normal. Frida is installed into MacSec the first time it is needed, and its server file for the phone is only used after its checksum matches the one GitHub lists.
- **Test phones.** MacSec lists your emulators and starts one with a click. If Android's tools are installed, "Build a test phone" makes one from a Google APIs image (which allows root, needed for Frida), downloading the image if it is missing.

### How it stays safe
- Off by default. You confirm per app and per phone.
- No taps, typing or buttons are sent to the app, so nothing is bought, posted or deleted. Only the app under test is touched.
- A real phone must be confirmed as yours. Without root, only the log is read and Frida is not used.

### Good to know
- Only the first seconds of the app are watched, because nothing is tapped. Pinning that happens later is not seen, so "no pinning seen" is marked as possible, not confirmed.
- Not in this release: iOS live testing, and testing whether pinning can be bypassed (which needs a proxy). One-time codes, session fixation and sign-out replay are also still to come.

## MacSec 1.1.0

Control confirmations: optional checks that prove a problem is real, so a finding is never a guess.

### What is new
- **Hidden pages and parameters.** Tries a list of common names to find pages and settings that are not linked from the site. A site that answers "found" to everything is detected and ignored. Every hit is asked for twice, and secret values in files such as `.env` are never copied into a finding, only the names.
- **Web firewall tests.** Names the firewall that answers, shows what it blocks, and sends harmless look-alike strings to see if one gets past it. A bypass is only reported when the string comes back in the page unchanged, so the owner can tighten the rule. Input that comes back unescaped is reported as confirmed cross-site scripting risk.
- **Login checks.** Eight wrong guesses for a user that does not exist (so no real account is touched) to see if anything slows them, and whether the login or the "forgot password" form reveals which accounts exist. Your own account is tried with two wrong passwords at most.
- **Two-account access check.** With a second account's cookie, compares what each account can open. A finding is "confirmed" when the first account's own details show up in the page the second account received, and signed out the page is refused.
- Every finding keeps its proof: the request, a command to repeat it, and what in the answer proves it. Cookies and tokens are never put in a proof or saved.

### How it stays safe
- Off by default. You switch each check on for one scan and confirm you may test the site.
- Same site only, no redirects followed to other sites, a request limit, a pause between requests, and an automatic stop if the server starts to struggle.
- Only harmless markers are sent. Nothing is changed, nothing is guessed at scale, and links that could sign you out or delete something are never opened.
- A finding that cannot be repeated is dropped, not reported.

### Not in this release
- Checks for one-time codes, session fixation and sign-out replay, and the live phone-app tests (SSL pinning and similar). These need a test device or more care, so they come next.

## MacSec 1.0.0

Version 1.0: a full review of every screen, with the app made clearer and more honest about what it knows.

### An honest score
- Under the score, MacSec now says what it is based on and what was never tested, with a link to each missing test. A good score only covers what was tested.
- **Fix these first**: the three most serious open findings sit next to the score.
- **Getting safer?**: a small line for each project you tested more than once, showing whether its score went up or down.
- The number of open findings now matches the list. Findings the AI ruled out are left out of that number, and hidden info notes are named with a link to show them.

### Clearer findings
- **Explain simply** (Settings): leads with what could happen and what to do, in everyday words, with the technical detail folded away.
- **Fix this one with Claude Code** on each finding, and **Copy as an issue** for GitHub, Jira or wherever you track work. Secrets are never copied.

### First run, and nothing downloaded without asking
- A welcome step explains what will be installed. Skill sets from other security teams are a tick box: they are no longer downloaded on their own.
- The badge at the top no longer says "Engine ready" when no scanner is installed.

### Shorter pages
- Tools is now four tabs (Scanners, AI, Skills, Extras) and the 43 skills are one line with "Show all".
- Sessions is now called Results. Logs moved into Settings as "Logs for support".
- Deep audit is a choice card next to Standard review.
- This Mac runs its check the first time you open it.
- Test a project fully: its code and its live site in one go, from the Overview.

### Look
- A light look, five accent colours and a larger text size, in Settings.
- MacSec in the menu bar: the score, and any test that is running.
- The progress pop-up no longer covers the Start button.

