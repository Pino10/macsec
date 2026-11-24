# Roadmap

## Done in 1.24.0

- PHPStan and Psalm, from the project's own `vendor/bin` and config, with Psalm's taint analysis
  and PHPStan's security messages only.
- The independent AI verifier, on demand, with a masked excerpt and a fixed two-line answer.
- The attack-surface graph in the Surface tab.
- Burp XML import, with no stored credentials.
- The full ledger in RELEASE_NOTES.md, so what is not done is named with its blocker.

## 1.24.1: consistency

- Every release page from 1.0 to 1.24 now carries its notes (they were empty: the tag path attached
  the files but never set the body).
- The release workflow now sets the body from RELEASE_NOTES.md on every tag, so this cannot drift
  again.
- This roadmap is the agreed next order, not a wish list.

## 1.25 priorities

1. **QA harness before any new dependency.**
   - [ ] Scanner install and update tests: every tool's pinned address, checksum and version,
         checked in CI on a schedule, so a rotted URL fails the harness and not a user's review.
   - [ ] Cross-engine fixture runner: the same labelled file through Semgrep, Bearer, Psalm,
         PHPStan and Joern, comparing finding keys, duplicates and precision. This is the
         measuring stick the next three items use.
2. **SQL corpus and Joern evaluation.**
   - [ ] A labelled corpus of SQL injection across PHP, Python, JavaScript and Java: positive
         samples (string-built queries, unsafe ORM raw calls) and clean samples that must not be
         flagged.
   - [ ] Hold out at least a third of the samples from anyone writing rules, or the measurement
         only proves the rules match their own examples.
   - [ ] Measure precision, recall, runtime and disk for `p/sql-injection`, Bearer, Psalm taint,
         PHPStan and Joern, on the same machine and the same corpus.
   - [ ] Decide Joern on the numbers: it replaces something, or it adds coverage worth 400 MB, or
         it does not ship.
3. **Real, redistributable mobile fixtures and install tests.**
   - [ ] A small open-source APK with a pinned checksum (an F-Droid build is the obvious source),
         used for the manifest and decompiler tests.
   - [ ] An IPA is different: an unsigned build from an open-source project can test static
         parsing, but dynamic testing needs a signing identity and a device. The fixture says so.
   - [ ] The install tests from 1 are extended to the mobile tools once they exist.
4. **Amass against subfinder, passive only.**
   - [ ] Run both on a fixed domain list, compare unique subdomains, false positives, runtime and
         the dependency footprint (Amass is a Go tool with its own config and database).
   - [ ] Add Amass only if it finds something subfinder does not, often enough to justify it.
5. **Bounded virtual-host discovery.**
   - [ ] A fixed candidate list of Host headers against one address, each compared with a name
         that cannot exist, at a slow rate, for hosts the person owns.
   - [ ] Report a discovered vhost with the answer that proves it, and nothing on a wildcard.
6. **Patch generation, last and isolated.**
   - [ ] Generate a patch into a scratch copy, never into the project.
   - [ ] Run the project's own test command, capped in time, then the scanners again on the patched
         copy, so a "fix" that adds a vulnerability fails.
   - [ ] Show the diff, require a typed confirmation, and keep a one-click rollback.
   - [ ] Refuse when there is no test command, and say why.

## Later

- Notarisation: needs an Apple Developer account. The app stays ad-hoc signed and the Ed25519
  release signature is what protects updates; notarising is a workflow change once an account exists.
- Windows and Linux: MacSec is a macOS workbench.

## How each item stays inside the rules

Free tools only, everything on this Mac, read-only unless a person turns on a controlled proof, and
no external account unless they connect it themselves. A new engine is added only after it is
measured against the existing ones on the same labelled data, and a new fixture only when it can be
redistributed legally.
