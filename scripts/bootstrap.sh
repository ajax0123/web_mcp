#!/usr/bin/env bash
# Create a clean, single-version virtualenv and verify the app imports (C-1, L-2).
#   PYTHON=python3.11 scripts/bootstrap.sh   # override interpreter
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-python3.12}"
command -v "$PYTHON" >/dev/null 2>&1 || { echo "FATAL: $PYTHON not found"; exit 2; }

"$PYTHON" - <<'PY'
import sys
lo, hi = (3, 11), (3, 13)
if not (lo <= sys.version_info[:2] < hi):
    sys.exit(f"FATAL: need CPython >=3.11,<3.13 — got {sys.version.split()[0]}")
print(f"interpreter OK: {sys.version.split()[0]}")
PY

echo "· removing any previous .venv"
rm -rf .venv

echo "· creating .venv"
"$PYTHON" -m venv .venv
.venv/bin/python -m pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -r cyberguard_api/requirements.txt

echo "· verifying import + model manifest"
.venv/bin/python -c "import cyberguard_api.main; print('import OK')"
.venv/bin/python -m cyberguard_api.services.model_loader --check

echo
echo "PASS — activate with:  source .venv/bin/activate"
