#!/usr/bin/env bash
# A-H3 — resolve cyberguard_api/requirements.txt into a fully hash-locked set.
# Run in a clean CPython 3.12 env. Commit the result as requirements.committed.lock
# so CI can diff against it and fail if requirements.txt drifts without a re-lock.
#
#   scripts/lock.sh          # writes requirements.lock
#   scripts/lock.sh --commit # also copies it to requirements.committed.lock
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python -m pip install --quiet "pip-tools==7.4.1"
pip-compile --quiet --generate-hashes --allow-unsafe \
  --output-file requirements.lock cyberguard_api/requirements.txt
echo "wrote requirements.lock ($(grep -c '^\S' requirements.lock 2>/dev/null || echo '?') lines)"

if [ "${1:-}" = "--commit" ]; then
  cp requirements.lock requirements.committed.lock
  echo "wrote requirements.committed.lock — git add + commit it"
fi
