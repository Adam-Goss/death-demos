#!/usr/bin/env bash
# The workstation timers the lab depends on, as one unit:
#   tick     labmode.py tick every minute: ends maintenance mode and the analysis Internet window at expiry
#   flow     firewall_flow.py: ships the firewall's flow logs to Elastic
#   tunnel   keeps the Elastic SSH tunnel (19200/18220) up for the flow shipper and labops.py
# Usage: ops-timers.sh install | remove | status
#   install   (re)installs all three for THIS checkout; lines are replaced by tag, so moving the checkout and re-running fixes them
#   status    exit 1 if a timer is missing or its line points at a directory that no longer exists
# Needs secrets/env.sh (see install-tick-timer.sh). Env: CRONTAB overrides the crontab command (tests).
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)
CRONTAB=${CRONTAB:-crontab}
cmd=${1:-}
tags=("opaleye-labmode-tick:tick" "opaleye-firewall-flow:flow" "opaleye-elastic-tunnel:tunnel")

case $cmd in
  install|remove)
    flag=; [ "$cmd" = remove ] && flag=--remove
    rc=0
    for t in "${tags[@]}"; do
      bash "scripts/install-${t#*:}-timer.sh" $flag || rc=1
    done
    exit $rc ;;
  status)
    lines=$($CRONTAB -l 2>/dev/null || true)
    bad=0
    for t in "${tags[@]}"; do
      tag=${t%%:*}
      line=$(printf '%s\n' "$lines" | grep -F "# $tag" | head -n1)
      if [ -z "$line" ]; then echo "MISSING $tag"; bad=1; continue; fi
      dir=$(printf '%s\n' "$line" | sed -n "s/.*cd '\([^']*\)'.*/\1/p" | head -n1)
      if [ -z "$dir" ] || [ ! -d "$dir" ]; then echo "STALE $tag: ${dir:-no directory} does not exist"; bad=1; continue; fi
      if [ "$dir" != "$ROOT" ]; then echo "OTHER-CHECKOUT $tag: runs in $dir, not $ROOT"; bad=1; continue; fi
      echo "ok $tag"
    done
    exit $bad ;;
  *) echo "usage: ops-timers.sh install|remove|status" >&2; exit 2 ;;
esac
