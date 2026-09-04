#!/usr/bin/env bash
# ============================================================================
# PP-L1 — move the large model .pkl / .joblib artifacts out of plain git history
# and into Git LFS.
#
# `.gitattributes` already declares  *.pkl / *.joblib  filter=lfs, so NEW commits
# store pointers. The ~113 MB already committed as plain blobs across the
# "Update data science models" revisions still bloats every clone until history
# is rewritten.
#
# THIS SCRIPT REWRITES HISTORY. It must be run once, coordinated with everyone
# who has a clone, followed by a single force-push. Do not run it unattended.
# ============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

command -v git-lfs >/dev/null 2>&1 || { echo "FATAL: git-lfs not installed"; exit 2; }

echo "current on-disk size of tracked model blobs:"
git ls-files -- 'cyberguard_api/models/*.pkl' | xargs -I{} du -h {} 2>/dev/null || true

read -r -p "Rewrite ALL history to move *.pkl,*.joblib into LFS? [type MIGRATE] " ans
[ "$ans" = "MIGRATE" ] || { echo "aborted."; exit 1; }

git lfs install
git lfs migrate import --include="*.pkl,*.joblib" --everything

echo
echo "verifying pointers…"
git show HEAD:cyberguard_api/models/cyberguard_rf_final.pkl | head -c 60; echo

git reflog expire --expire=now --all
git gc --prune=now --aggressive

cat <<'NEXT'

DONE locally. Next, ONCE, with the team paused:
    git push --force-with-lease origin <branch>
Everyone else then re-clones (or: git fetch && git reset --hard origin/<branch>).
NEXT
