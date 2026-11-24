# Threat model

What can hurt MacSec, and what stands in the way. This document is for contributors: a change that
weakens one of these lines needs a reason written down here.

## The window is untrusted

Every message from the window goes through one door in `src/main/index.ts`, which checks the sender
frame, the frame address, and every argument. The window has a strict content security policy, no
Node, and no navigation away from the app.

Residual risk: development tools can be opened in a packaged build, so anyone at the keyboard can
call a channel by hand. That is the same power the app itself has.

## Credentials

Tokens live in the Keychain (`secrets.ts`) and are sent only to their own service. Logs and proofs
redact them. Scanner tools are now given **no** session credentials: the signed-in walk is MacSec's
own client, with its own cap, and the tools crawl signed out. This closed the redirect leak where a
cookie followed a tool to another host.

Residual risk: the person can paste a cookie, and that cookie is used by MacSec's own requests. It
never leaves the target's origin.

## DNS

A guarded request resolves the name once, refuses metadata and mixed answers, and then connects to
the approved address (`netclient.ts`), so a name that changes its answer cannot move the request to
a private address. Plain `fetch` is still used where no guard applies (tool installs, GitHub calls).

## AI reviewers

They run read-only, with a settings file that denies the usual credential paths, a prompt that calls
the code data rather than instructions, and no MCP servers of the person's own.

Residual risk: prompt injection into a report's text. The review is read-only, so the worst case is
disclosure, not execution. Treat a report from an untrusted repository as untrusted.

## Controlled exploitation

An engagement, a typed phrase, per-step approval, caps counted from disk, a kill switch, a masked
audit log, stop at first proof, and cleanup or an explicit leftover. Every request goes through one
client whose origin, address and method rules are enforced before the socket.

Residual risk: Metasploit modules are reasoned about, not tested against every target. The run list
excludes anything known to crash a host or leave a file MacSec cannot remove.

## Updates

A release is installed only when `SHA256SUMS.txt` carries a valid Ed25519 signature from the key
whose public half is in `build/release-signing.pub`, and the DMG matches the signed list. The
private half is a GitHub Actions secret, so a release cannot be published without it.

## Supply chain

Scanners come from their official releases with their published checksums, or from PyPI through uv.
MacSec itself is built from a lockfile, and the app is ad-hoc signed today (not notarised), which is
a known gap for user trust rather than for update integrity.
