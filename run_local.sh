#!/usr/bin/env bash
# Daily local jobwatch run. Polls, publishes the page, notifies only on new reqs.
# A .publish_hold file in this directory skips deploy_site.sh.
# Polling and scoring still run.
set -euo pipefail

HOME_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$HOME_DIR"

PY="$(command -v python3)"
STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "=== jobwatch run $STAMP ==="

set +e
"$PY" jobwatch.py --diff > jobwatch_report.md 2> jobwatch_run.log
POLL_RC=$?
set -e
cat jobwatch_run.log

if [ "$POLL_RC" -ne 0 ]; then
  if grep -q "sanitizer blocked" jobwatch_run.log jobwatch_report.md 2>/dev/null; then
    echo "sanitizer blocked public output; nothing was uploaded"
  fi
  osascript -e 'display notification "Every board failed. Check jobwatch_run.log." with title "jobwatch failed"' 2>/dev/null || true
  echo "poll failed rc=$POLL_RC"
  exit "$POLL_RC"
fi

NEW="$(sed -n 's/^SUMMARY new=\([0-9]*\).*/\1/p' jobwatch_report.md | head -1)"
LIVE="$(sed -n 's/^SUMMARY .*live=\([0-9]*\).*/\1/p' jobwatch_report.md | head -1)"
CLOSED="$(sed -n 's/^SUMMARY .*closed=\([0-9]*\).*/\1/p' jobwatch_report.md | head -1)"
NEW="${NEW:-0}"; LIVE="${LIVE:-0}"; CLOSED="${CLOSED:-0}"

# Publish the page every run so the site always reflects the latest poll,
# unless a hold file is present. deploy_site.sh also honors .publish_hold.
# There is no MonoClaw call: that script is not in this repo and must not
# push unsanitized output.
if [ -f .publish_hold ]; then
  echo "held"
else
  set +e
  ./deploy_site.sh >> jobwatch_run.log 2>&1
  DEPLOY_RC=$?
  set -e
  if [ "$DEPLOY_RC" -eq 0 ]; then
    echo "site published"
  else
    if grep -q "sanitizer blocked" jobwatch_run.log; then
      echo "sanitizer blocked public output; nothing was uploaded"
    fi
    echo "site publish failed, see jobwatch_run.log"
  fi
fi

# Keep a dated copy so a diff is never lost between runs.
mkdir -p history
cp jobwatch_report.md "history/$(date -u +%Y-%m-%d).md"

if [ "$NEW" -gt 0 ]; then
  osascript -e "display notification \"$NEW new, $CLOSED closed, $LIVE live\" with title \"jobwatch: $NEW new req(s)\" sound name \"Glass\"" 2>/dev/null || true
fi

echo "SUMMARY new=$NEW closed=$CLOSED live=$LIVE"
