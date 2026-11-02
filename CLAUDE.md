# Notes for AI coding assistants

MacSec is a macOS security workbench (Electron 45, electron-vite, React 18, TypeScript). It reviews code
with free scanners plus an AI reviewer, and keeps every run as a session. Read MAINTAINING.md first.

## Rules

- Security first. The window is untrusted: every IPC handler in `src/main/index.ts` validates input. Project paths must be inside the www folder or picked in a dialog (`allowedProject`). Never pass user text to a shell; use `spawn`/`execFile` with argument arrays.
- Tokens live in the Keychain (`secrets.ts`), are sent only to their own service, and are redacted from logs (`logs.ts`). Clone with a one-off auth header, never a token in the URL.
- Everything MacSec writes goes under `~/MacSec` (`paths.ts`). Scanners run with `toolEnv()` so their caches stay there. Do not write anywhere else on the Mac.
- Downloads are checked against the publisher's checksum when one exists.
- AI agents run read-only. Secrets found by scanners are never stored in findings (only the kind, file and line).
- Only test what the person owns or is allowed to test. Intrusive web checks must ask for confirmation.
- UI and docs: plain, friendly English for non-experts. Never use em dashes; use a colon and a space instead.

## Checks before committing

```sh
npm run typecheck
npm test
npm run build
```

Add tests with real tool output for every new parser.
