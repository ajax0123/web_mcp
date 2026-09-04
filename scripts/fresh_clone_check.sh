#!/usr/bin/env bash
# C-1 verification: a clean git checkout must install and import with zero errors.
# Clones the repo (committed files only) into a temp dir, builds an isolated venv,
# and imports the app + checks the model manifest.
#
#   scripts/fresh_clone_check.sh            # uses python3.12
#   PYTHON=python3.11 scripts/fresh_clone_check.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3.12}"
command -v "$PYTHON" >/dev/null 2>&1 || { echo "FATAL: $PYTHON not found"; exit 2; }
git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "· cloning committed tree -> $TMP/clone"
git clone --quiet "$ROOT" "$TMP/clone"
cd "$TMP/clone"

echo "· creating isolated venv"
"$PYTHON" -m venv .venv
.venv/bin/python -m pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -r cyberguard_api/requirements.txt

echo "· importing app"
.venv/bin/python -c "import cyberguard_api.main; print('  fresh-clone import OK')"
.venv/bin/python -m cyberguard_api.services.model_loader --check

echo
echo "PASS — a fresh clone installs and imports cleanly."
