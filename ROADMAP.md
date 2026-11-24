# Roadmap

Status after 1.24.0: PHPStan and Psalm, the independent verifier, the surface graph and Burp import shipped. The ledger in RELEASE_NOTES.md says which of the rest need a download, an SDK or an Apple account.

This is the agreed 1.24 work, in the order it was set. Each item says how it fits MacSec's rules: free
tools only, everything on this Mac, read-only unless a person turns on a controlled proof, and no
external account unless the person connects one themselves.

## Code scanning

- **Joern evaluation.** Free and open source, but a JVM tool of about 400 MB with its own server. The
  evaluation is: does its cross-function data flow find things Semgrep and Bearer miss on the same
  labelled samples, and what does it cost in time and disk? If it earns its place, it becomes an
  optional tool with a checksummed download and its own cache under `~/MacSec/tools`.
- **PHPStan and Psalm.** The two PHP static analysers. Both ship as a single phar, which suits
  MacSec: download with a checksum, run with the project's own `php` (or a managed one), and add the
  security rule sets. They are PHP only, so the Tools page should hide them when no PHP project is
  around.
- **Dedicated SQL security rules.** Semgrep rules for SQL built by string joining, unsafe ORM raw
  calls, and a second rule set per framework (Laravel, Django, Rails, Spring). This is rules, not a
  new engine, and it fits the existing pipeline.
- **More advanced cross-function data flow.** Semgrep's free data flow plus Bearer's; the next step
  is taint tracking across files and a small call graph. Joern is the likely engine; otherwise the
  AI reviewer is asked to trace a specific flow with the code around it, which is slower but free.
- **Broader framework-specific security coverage.** Rule packs and checks for the frameworks the
  scanner already recognises, plus framework-aware live checks (Laravel debug pages, Django debug,
  Spring actuator, Rails routes).

## AI

- **Independent AI verification agent.** A second, separate read of every high finding whose only
  job is to try to disprove it. It sees the finding, the proof and the code around it, never the
  first reviewer's reasoning, so it cannot simply agree. Disagreements are shown, never hidden.
- **Comprehensive AI accuracy benchmarks.** Grow `benchmarks.ts` from four checks to a labelled set
  across findings, paths and AI triage, with the same 0.8 precision and recall gate in CI.
- **Automated patch generation and validation.** Generate a small patch, apply it to a throwaway
  copy, run the tests that exist, and only then offer it. Never write into the person's project
  without a click. This needs a sandbox and a time limit.
- **Deeper repository-wide vulnerability tracing.** Follow a source from where it enters (a route,
  a form, a message queue) to a sink across files, and show the path. Calls for the call graph the
  Joern evaluation would provide.
- **More advanced IDOR and business-logic verification.** More two-account comparisons and
  read-only logic probes under the controlled-proof rules: no writes, no state changes, repeat
  every hit once, and stop at the first proof.

## Recon

- **Amass evaluation.** OWASP Amass, passive mode only at first (`-passive`), so it never touches
  the target. Assessed on speed and false positives against the current subfinder pass.
- **Virtual-host discovery.** A bounded Host-header probe list against one address, compared with a
  name that cannot exist. Only on hosts the person owns, and only in the confirmation rules.
- **Visual attack-surface graph.** A local, offline graph of hosts, pages, parameters and findings,
  built from what a session already holds. No telemetry, no cloud rendering.
- **Continuous asset-change monitoring.** The watch already re-runs; this adds a real diff: new
  subdomains, new ports, new pages, new certificates, and one note that says what changed.
- **Better API authentication and route mapping.** Read the specification and the traffic, map
  which routes need which scheme, and say where a route is missing from the spec or answers
  differently signed in and out. Read-only.

## Mobile

- **JADX and Apktool.** Free, Java, and they fit the existing static analysis: decompile to a
  session folder, parse manifests and sources, keep secrets as kind, file and line. Checksummed
  downloads under `~/MacSec/tools`.
- **Ghidra and LIEF.** Ghidra is large (about 400 MB) and needs a JDK, so its evaluation is disk and
  time first. LIEF is a Python library and suits the existing uv-managed Python tools. Both are
  read-only analyses.
- **iOS dynamic testing.** Needs a Mac with Xcode, a developer-signed app and a physical device.
  MacSec can drive Frida over USB the way it does for Android, but it cannot sign an IPA for you, and
  it will say so. No jailbreak automation.
- **Android emulator orchestration.** Start an AVD, wait for boot, install a chosen APK, run it and
  observe. Heavy, and it needs the Android SDK. Only for an APK the person chose, and it removes
  what it installed.
- **Frida and Objection.** Frida is already used; Objection is a Python wrapper. Both observe only:
  every hook calls the original. Never a bypass script.
- **AI-assisted decompiled-code analysis.** Send selected decompiled files to the chosen AI, not the
  whole archive, with secrets masked. Same rules as the code reviewer.
- **Burp integration.** Burp has no free headless API for MacSec to drive; the honest integration is
  importing a Burp export (HAR or XML) the way the HAR import already works, and exporting findings
  as a Burp-friendly XML. No paid API and no extension to install.

## Quality assurance

- **Full automated integration tests.** A small decoy app (already in the test helpers) run through
  the real flows on CI, with the network parts stubbed at the client boundary.
- **Real APK and IPA test fixtures.** Small, open-source, redistributable binaries. An IPA needs a
  signing identity for the dynamic parts, so the static tests use one and the dynamic test skips
  when no identity is present.
- **Cross-engine regression testing.** The same labelled fixture through every engine and reviewer,
  comparing counts and precision, so an engine upgrade cannot quietly change what is reported.
- **Validate all scanner installation and update workflows.** A CI matrix that installs each tool
  the way MacSec does, checks its version, and fails when a pinned URL or checksum rots.

The order above is the order of work. The first release in this set will be the parts that need no
new account or large download: SQL rules, framework coverage, the independent verification agent,
accuracy benchmarks, vhost discovery, route mapping, JADX and Apktool, and the QA scaffolding.
