#!/usr/bin/env bash
set -euo pipefail

# Liveness probe for the relay-shell HTTP transport. Exit 0 = healthy.
# For the stdio transport, liveness is the supervising client's concern.

HOST="${RELAY_SHELL_HTTP_HOST:-127.0.0.1}"
PORT="${RELAY_SHELL_HTTP_PORT:-8080}"
URL="http://${HOST}:${PORT}/"

# Any HTTP response (including 401/403/404 from the auth/edge layer) proves
# the listener is up. Check curl's exit status separately: on connection failure
# --write-out already emits 000, so appending a fallback would produce 000000
# and could accidentally report the failed connection as healthy.
if ! code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$URL")" ||
    [[ ! "$code" =~ ^[1-5][0-9]{2}$ ]]; then
    echo "relay-shell: UNHEALTHY (no response from $URL)"
    exit 1
fi
echo "relay-shell: ok (HTTP $code from $URL)"
exit 0
