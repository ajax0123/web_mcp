#!/usr/bin/env bash
#
# Terminal smoke-test suite — graceful error handling of the CyberGuard backend.
#
#   1. Target Not Found       -> 200 + TARGET_NOT_FOUND (not 500)   [smoke_agent.py]
#   2. Direct Target Injection -> triage skipped, straight to deep-dive [smoke_agent.py]
#   3. Client-Side Fallback    -> agent endpoint down => clean fallback  [smoke_fallback.mjs]
#
# Starts the backend on :8000 if it is not already up, then tears it down.
# Usage:  tests/smoke.sh   [API_BASE]

set -uo pipefail

API="${1:-${API_BASE:-http://localhost:8000}}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] || PY="python3"

echo "════════════════════════════════════════════════════════════════"
echo " CyberGuard smoke suite   API=$API"
echo "════════════════════════════════════════════════════════════════"

STARTED_PID=""
cleanup() {
  if [ -n "$STARTED_PID" ]; then
    kill "$STARTED_PID" 2>/dev/null
    pkill -P "$STARTED_PID" 2>/dev/null
    echo "· stopped backend (pid $STARTED_PID)"
  fi
}
trap cleanup EXIT INT TERM

if ! curl -sf -o /dev/null "$API/health" 2>/dev/null; then
  echo "· backend not up — starting uvicorn (cyberguard_api.main:app :8000) ..."
  # `exec` so $! is the uvicorn process itself, not the subshell wrapper.
  ( cd "$ROOT" && exec "$ROOT/.venv/bin/uvicorn" cyberguard_api.main:app \
      --port 8000 --log-level warning ) &
  STARTED_PID=$!
  for _ in $(seq 1 60); do curl -sf -o /dev/null "$API/health" 2>/dev/null && break; sleep 0.5; done
fi

if ! curl -sf -o /dev/null "$API/health" 2>/dev/null; then
  echo "FATAL: backend unreachable at $API"
  exit 2
fi
echo "· backend healthy: $(curl -s "$API/health")"

RC=0

"$PY" "$ROOT/tests/smoke_agent.py" "$API" || RC=1

if command -v node >/dev/null 2>&1; then
  node "$ROOT/tests/smoke_fallback.mjs" "$API" || RC=1
else
  echo; echo "  ⚠ node not found — skipping case 3 (smoke_fallback.mjs)"
fi

echo
echo "════════════════════════════════════════════════════════════════"
if [ "$RC" -eq 0 ]; then
  echo " RESULT: ALL SMOKE TESTS PASSED ✓"
else
  echo " RESULT: FAILURES ✗"
fi
echo "════════════════════════════════════════════════════════════════"
exit $RC
