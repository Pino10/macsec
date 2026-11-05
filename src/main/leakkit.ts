/**
 * "Stop leaking keys": a Git pre-commit hook and a GitHub Action that run Gitleaks, so a key or
 * password is caught before it is committed, and again before it is merged. MacSec only shows
 * and copies these (or saves them under ~/MacSec/kits); you put them in your own projects.
 */

/** Gitleaks for the Action, with the SHA-256 from its release's checksums file. */
export const GITLEAKS = {
  version: '8.30.1',
  linuxX64Sha256: '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb'
}
/** actions/checkout v7.0.1, pinned to its commit so the tag cannot be moved under you. */
export const CHECKOUT = { sha: '3d3c42e5aac5ba805825da76410c181273ba90b1', tag: 'v7.0.1' }

export interface LeakKit {
  /** .git/hooks/pre-commit */
  hook: string
  /** .pre-commit-config.yaml, for people who use the pre-commit tool. */
  preCommit: string
  /** .github/workflows/gitleaks.yml */
  action: string
  /** Where to put each one, in plain words. */
  steps: { hook: string[]; preCommit: string[]; action: string[] }
  version: string
}

const q = (s: string): string => `'${s.replace(/'/g, `'\\''`)}'`

export function leakKit(macsecBin: string): LeakKit {
  const hook = `#!/bin/sh
# Stop leaking keys: Gitleaks checks what you are about to commit.
# Made by MacSec. Skip once (not recommended) with: git commit --no-verify
GITLEAKS="$(command -v gitleaks || true)"
[ -z "$GITLEAKS" ] && [ -x ${q(`${macsecBin}/gitleaks`)} ] && GITLEAKS=${q(`${macsecBin}/gitleaks`)}
if [ -z "$GITLEAKS" ]; then
  echo "Gitleaks is not installed, so this commit was not checked for keys."
  echo "Install it in MacSec (Tools) or with: brew install gitleaks"
  exit 0
fi
"$GITLEAKS" git --pre-commit --staged --redact --no-banner --verbose
status=$?
if [ $status -eq 1 ]; then
  echo ""
  echo "A key or password is in this commit. Take it out, put it in .env (which is not committed),"
  echo "and change the key at its service if it was ever pushed. Nothing was committed."
elif [ $status -ne 0 ]; then
  echo "Gitleaks could not run (code $status), so nothing was committed. Try again, or check Gitleaks in MacSec."
fi
exit $status
`

  const preCommit = `# Stop leaking keys: Gitleaks runs before every commit (https://pre-commit.com).
# Then run once: pre-commit install
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v${GITLEAKS.version}
    hooks:
      - id: gitleaks
`

  const action = `# Stop leaking keys: Gitleaks checks every push and pull request, including old commits.
# Made by MacSec. Free, with no licence key: it downloads Gitleaks and checks its SHA-256 first.
name: Gitleaks

on:
  push:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  gitleaks:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@${CHECKOUT.sha} # ${CHECKOUT.tag}
        with:
          fetch-depth: 0
          persist-credentials: false

      - name: Get Gitleaks ${GITLEAKS.version}
        run: |
          curl -sSfL -o gitleaks.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS.version}/gitleaks_${GITLEAKS.version}_linux_x64.tar.gz"
          echo "${GITLEAKS.linuxX64Sha256}  gitleaks.tar.gz" | sha256sum --check --strict
          tar -xzf gitleaks.tar.gz gitleaks
          rm gitleaks.tar.gz

      - name: Look for keys and passwords
        run: ./gitleaks git --redact --no-banner --verbose --exit-code 1 .
`

  return {
    hook,
    preCommit,
    action,
    version: GITLEAKS.version,
    steps: {
      hook: ['In your project, save this as .git/hooks/pre-commit', 'Make it runnable: chmod +x .git/hooks/pre-commit', 'Every commit is now checked. It uses MacSec’s Gitleaks when it is not installed elsewhere.'],
      preCommit: ['Save this as .pre-commit-config.yaml in your project', 'Run once: pre-commit install', 'Everyone on the team who runs pre-commit install gets the same check.'],
      action: ['Save this as .github/workflows/gitleaks.yml in your project', 'Commit and push it', 'GitHub checks every push and pull request. A red check means a key was found: open the run to see the file and line (the key itself is hidden).']
    }
  }
}
