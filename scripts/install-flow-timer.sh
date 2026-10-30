#!/usr/bin/env bash
# Start a bounded worker each minute, polling every five seconds over VPN and SSH.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)
TAG="# opaleye-firewall-flow"
current=$(crontab -l 2>/dev/null | grep -vF "$TAG" || true)
if [ "${1:-}" = --remove ]; then
  printf '%s\n' "$current" | crontab -
  echo "firewall flow timer removed"
  exit 0
fi
[ -f secrets/env.sh ] || { echo "missing secrets/env.sh" >&2; exit 1; }
mkdir -p .state
LINE="* * * * * set -a; . '$ROOT/secrets/env.sh'; set +a; cd '$ROOT' && flock -n .state/firewall-flow.lock python3 scripts/firewall_flow.py --watch-seconds 55 >> .state/firewall-flow.log 2>&1 $TAG"
printf '%s\n%s\n' "$current" "$LINE" | sed '/^$/d' | crontab -
echo "firewall flow timer installed; keep WSL, cron, VPN and the Elastic SSH tunnel running"
