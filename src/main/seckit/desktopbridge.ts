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
# Every message that has an id always gets an answer, so the Claude app never sits waiting until it times out.
URL=${q(url)}
TOKEN_FILE=${q(tokenFile)}
umask 077
H="$(mktemp)" || exit 1
B="$(mktemp)" || exit 1
trap 'rm -f "$H" "$B"' EXIT INT TERM HUP
fail() {
  # $1 = the message line, $2 = the words to show. Silent for a message without an id (a notification).
  id="$(printf '%s' "$1" | awk -F'"id":' 'NF>1 { split($2, a, /[,}]/); print a[1]; exit }' | tr -d '[:space:]')"
  case "$id" in
    ''|null) return ;;
    *[!0-9A-Za-z_\\"-]*) return ;;
  esac
  printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32000,"message":"%s"}}\\n' "$id" "$2"
}
printf 'Authorization: Bearer %s\\n' "$(tr -d '[:space:]' < "$TOKEN_FILE" 2>/dev/null)" > "$H"
while IFS= read -r line || [ -n "$line" ]; do
  [ -z "$line" ] && continue
  : > "$B"
  code="$(printf '%s' "$line" | /usr/bin/curl -sS --max-time 600 -o "$B" -w '%{http_code}' -X POST -H @"$H" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' --data-binary @- "$URL" 2>/dev/null)"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    fail "$line" "${app} is not running. Open ${app} and try again."
    continue
  fi
  case "$code" in
    401|421) fail "$line" "${app} refused the connection (wrong token). Open ${app}, turn on Claude desktop again in Settings, then restart the Claude app." ; continue ;;
    2??) ;;
    *) fail "$line" "${app} answered with an error ($code)." ; continue ;;
  esac
  if [ -s "$B" ]; then tr -d '\\r' < "$B" | tr '\\n' ' '; printf '\\n'; fi
done
`
}
