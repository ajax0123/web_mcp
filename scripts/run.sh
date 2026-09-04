#!/usr/bin/env bash
# Start the API the way it should run in a real environment:
#   - workers (not --reload)
#   - --proxy-headers, trusting XFF only from FORWARDED_ALLOW_IPS (H-6)
# Config comes from .env / the environment (see .env.example).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${PORT:-8000}"
HOST="${HOST:-0.0.0.0}"
WORKERS="${WEB_CONCURRENCY:-2}"
FORWARDED_ALLOW_IPS="${FORWARDED_ALLOW_IPS:-127.0.0.1}"

BIN="uvicorn"
[ -x ".venv/bin/uvicorn" ] && BIN=".venv/bin/uvicorn"

exec "$BIN" cyberguard_api.main:app \
  --host "$HOST" --port "$PORT" \
  --workers "$WORKERS" \
  --proxy-headers --forwarded-allow-ips "$FORWARDED_ALLOW_IPS" \
  --no-server-header \
  --no-access-log   # the app emits one structured 'request' line per request (A-L2)
