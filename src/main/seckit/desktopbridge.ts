/**
 * The command the Claude desktop app starts for a local MCP server, shared by Laramac and MacSec
 * (keep both copies of src/main/seckit the same).
 *
 * The Claude app starts MCP servers as commands, with a short PATH that has no Node. So the command
 * is a tiny shell script that only needs curl, which every Mac has: it reads each message from the
 * app, sends it to the app's local server at 127.0.0.1 and prints the answer. It reads the token from
 * the app's own token file each time, so the token is never copied into the Claude app's config.
 */
export function desktopBridge(url: string, tokenFile: string, app: string): string {
  const q = (v: string): string => `'${v.replace(/'/g, `'\\''`)}'`
  return `#!/bin/sh
# Written by ${app}: lets the Claude app talk to ${app}. It needs no Node.js.
URL=${q(url)}
TOKEN_FILE=${q(tokenFile)}
umask 077
H="$(mktemp)" || exit 1
trap 'rm -f "$H"' EXIT INT TERM HUP
printf 'Authorization: Bearer %s\\n' "$(tr -d '[:space:]' < "$TOKEN_FILE")" > "$H"
while IFS= read -r line || [ -n "$line" ]; do
  [ -z "$line" ] && continue
  out="$(printf '%s' "$line" | /usr/bin/curl -sS --max-time 600 -X POST -H @"$H" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' --data-binary @- "$URL" 2>/dev/null)"
  if [ $? -ne 0 ]; then
    id="$(printf '%s' "$line" | sed -n 's/^{"jsonrpc":"2.0","id":\\([0-9][0-9]*\\),.*/\\1/p')"
    [ -n "$id" ] && printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32000,"message":"${app} is not running. Open ${app} and try again."}}\\n' "$id"
    continue
  fi
  [ -n "$out" ] && printf '%s\\n' "$out"
done
`
}
