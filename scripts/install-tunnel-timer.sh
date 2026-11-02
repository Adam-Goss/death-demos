#!/usr/bin/env bash
# Installs the Elastic tunnel keep-alive: a user crontab line that runs scripts/tunnel-keepalive.sh every minute.
# Idempotent; `--remove` uninstalls. CRONTAB overrides the crontab command (tests).
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)
CRONTAB=${CRONTAB:-crontab}
TAG="# opaleye-elastic-tunnel"
LINE="* * * * * cd '$ROOT' && bash scripts/tunnel-keepalive.sh $TAG"
current=$($CRONTAB -l 2>/dev/null | grep -vF "$TAG" || true)
if [ "${1:-}" = "--remove" ]; then
  printf '%s\n' "$current" | sed '/^$/d' | $CRONTAB -
  echo "elastic tunnel keep-alive removed"
  exit 0
fi
mkdir -p .state
printf '%s\n%s\n' "$current" "$LINE" | sed '/^$/d' | $CRONTAB -
echo "elastic tunnel keep-alive installed (every minute); needs the cron service, the VPN and the lab SSH key without a passphrase"
