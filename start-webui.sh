#!/usr/bin/env bash
# Start the local fingerprint console (if needed) and open it in Chromium.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$ROOT/webui/server.py" ]]; then
  SERVER="$ROOT/webui/server.py"
  LOG="$ROOT/webui/server.log"
else
  SERVER="$ROOT/server.py"
  LOG="$ROOT/server.log"
fi

URL='http://127.0.0.1:8899'

if ! curl -fsS "$URL/state" >/dev/null 2>&1; then
  setsid nohup python3 "$SERVER" > "$LOG" 2>&1 < /dev/null &
  sleep 2
fi

exec chromium --no-sandbox --app="$URL" \
  --window-size=1440,900 --window-position=120,60 "$@"
