# Roadmap

Status after 1.26.1, verified against the release itself.

## Done

- 1.24.0: PHPStan and Psalm (project-local), the independent AI verifier, the surface graph, Burp
  XML import, and the full ledger of what was not done.
- 1.24.1: every release page carries its notes; the tag workflow sets the body.
- 1.25.0: the install harness (static rules plus a weekly live GitHub check) and the cross-engine
  runner over recorded engine output.
- 1.26.0: the corpus grew to 33 cases across eight languages, 17 vulnerable and 16 clean, with a
  language-level holdout split.
- 1.26.1: Semgrep, Bearer, Psalm and PHPStan measured on the corpus; Psalm 7's bare-array output
  fixed. Semgrep 1.0/0.647, Bearer 0.8/0.235, Psalm (PHP) 1.0/0.5, PHPStan (PHP) 0.5/0.25.

## Open, in order

1. **Real mobile fixtures and install tests.**
   - [ ] A small open-source APK with a pinned checksum (F-Droid is the source), used for the
         manifest and decompiler tests.
   - [ ] An unsigned iOS build for static parsing, with the dynamic limit stated: an IPA needs
         Xcode, a signing identity and a device, and cannot be redistributed.
   - [ ] Extend the install harness to the mobile tools once they exist.
2. **Joern, measured or not at all.**
   - [ ] Install a Java runtime and Joern, after approval for the download and the disk.
   - [ ] Measure it on the same 33 cases, starting with the six misses: Laravel `DB::select` and
         `DB::raw`, JavaScript concatenation, Prisma `$queryRawUnsafe`, TypeORM `query`, Hibernate
         `createQuery`.
   - [ ] Ship only if it beats 0.5 holdout recall, stays under one false positive in ten clean
         files, and justifies its runtime and disk. Otherwise the number is the deliverable.
3. **Amass against subfinder, passive only.**
   - [ ] Run both on a fixed domain list; compare unique subdomains, false positives, runtime and
         the dependency footprint.
   - [ ] Add Amass only if it finds something subfinder does not, often enough.
4. **Bounded virtual-host discovery.**
   - [x] A fixed Host-header list against one address, compared with a name that cannot exist, at
         a slow rate, for hosts the person owns.
   - [x] Report only an answer that proves a vhost, and nothing on a wildcard.
5. **Patch generation, last and isolated.**
   - [ ] Generate into a scratch copy, never the project.
   - [ ] Run the project's own tests with a time cap, then the scanners again on the patched copy.
   - [ ] Show the diff, require a typed confirmation, keep a one-click rollback, and refuse when
         there is no test command.

## Later

- Notarisation: needs an Apple Developer account. The app stays ad-hoc signed; the Ed25519 release
  signature and the verified DMG digests are what protect updates.
- Windows and Linux: MacSec is a macOS workbench.

## How each item stays inside the rules

Free tools only, everything on this Mac, read-only unless a person turns on a controlled proof, and
no external account unless they connect it themselves. A new engine ships only after it is measured
against the existing ones on the same labelled data, and a fixture only when it can be redistributed
legally.
