#!/usr/bin/env bash
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "[clawstrike] checking for updates..."

# capture commit before pull
BEFORE=$(git rev-parse HEAD)

git pull origin main

AFTER=$(git rev-parse HEAD)

if [ "$BEFORE" = "$AFTER" ]; then
  echo "[clawstrike] already up to date."
else
  echo ""
  echo "[clawstrike] changes pulled:"
  git log --oneline "$BEFORE..$AFTER"
  echo ""
  "$ROOT/venv/bin/python3" -c "
import re, pathlib
f = pathlib.Path('version.py')
content = f.read_text()
content = re.sub(
    r'VERSION = \"(\d+)\.(\d+)\.(\d+)\"',
    lambda m: f'VERSION = \"{m.group(1)}.{m.group(2)}.{int(m.group(3))+1}\"',
    content
)
f.write_text(content)
print('[clawstrike] version bumped to ' + re.search(r'VERSION = \"(.+?)\"', content).group(1))
"
fi

echo ""
echo "[clawstrike] syncing dependencies..."
"$ROOT/venv/bin/pip" install -r "$ROOT/requirements.txt" --upgrade --quiet

echo "[clawstrike] done."
