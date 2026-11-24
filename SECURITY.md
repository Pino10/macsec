# Security policy

MacSec tests your own code and systems. It holds tokens, reads source code, and can prove impact on
a staging target, so it is worth treating as a sensitive tool.

## Reporting a problem in MacSec

Open a private security advisory on GitHub: Security, Advisories, Report a vulnerability. Do not open
a public issue for anything that could let someone else read a user's sessions, tokens or code.

Please include: the version, what you did, what happened, and the smallest reproduction you can.
Expect an answer within a week. This is a small project, so there is no paid bounty.

## What we treat as a vulnerability

- reading another person's sessions, findings or tokens from a shared Mac;
- an IPC channel that accepts input from outside the app's own window;
- a scanner or tool whose arguments can be changed into something else by a target;
- a leaked token in a log, a proof, a report, an export or a crash message;
- an update that can be installed without MacSec's release signature;
- an exploit step that can run without a live engagement and the typed phrase.

## What is not a vulnerability

- Gitleaks, Semgrep or another scanner reporting a pattern in a test fixture;
- the app downloading a scanner from its official release, with its published checksum;
- a finding that a scanner got wrong: that is an accuracy bug, and a normal issue is fine.

## Supported versions

The newest release. Releases are signed; the app refuses an update whose checksum list is not signed
by MacSec's release key.
