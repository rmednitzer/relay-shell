#!/usr/bin/env bash
set -euo pipefail

# Liveness probe for the mcpx HTTP transport. Exit 0 = healthy.
# For the stdio transport, liveness is the supervising client's concern.

HOST="${MCPX_HTTP_HOST:-127.0.0.1}"
PORT="${MCPX_HTTP_PORT:-8080}"
URL="http://${HOST}:${PORT}/"

code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$URL" || echo 000)"

# Any HTTP response (including 401/403/404 from the auth/edge layer) proves
# the listener is up; only a connection failure (000) is unhealthy.
if [ "$code" = "000" ]; then
    echo "mcpx: UNHEALTHY (no response from $URL)"
    exit 1
fi
echo "mcpx: ok (HTTP $code from $URL)"
exit 0
