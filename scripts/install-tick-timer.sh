#!/usr/bin/env bash
# Installs the maintenance-expiry timer (issue #21): a user crontab line that runs `labmode.py tick` every minute.
# Idempotent; `--remove` uninstalls. The job reads credentials from secrets/env.sh (gitignored).
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)
TAG="# opaleye-labmode-tick"
LINE="* * * * * set -a; . $ROOT/secrets/env.sh; set +a; cd $ROOT && python3 scripts/labmode.py tick >> $ROOT/.state/tick.log 2>&1 $TAG"
current=$(crontab -l 2>/dev/null | grep -vF "$TAG" || true)
if [ "${1:-}" = "--remove" ]; then
  printf '%s\n' "$current" | crontab -
  echo "tick timer removed"
  exit 0
fi
[ -f secrets/env.sh ] || { echo "missing secrets/env.sh (OPNSENSE_URL, OPNSENSE_API_KEY, OPNSENSE_API_SECRET, OPNSENSE_NO_SAVEPOINT)" >&2; exit 1; }
grep -q 'OPNSENSE_NO_SAVEPOINT' secrets/env.sh || { echo "secrets/env.sh must export OPNSENSE_NO_SAVEPOINT=true (core 26.7 has no savepoint); without it every tick fails and a maintenance window never closes" >&2; exit 1; }
mkdir -p .state
printf '%s\n%s\n' "$current" "$LINE" | sed '/^$/d' | crontab -
echo "tick timer installed (every minute); needs the cron service running (WSL: sudo service cron start) and the VPN up"
