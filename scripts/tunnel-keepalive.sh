#!/usr/bin/env bash
# Starts the Elastic SSH tunnel (scripts/elastic-tunnel.sh) when local port 19200 is not answering. Run from cron every
# minute (install-tunnel-timer.sh): silent when the tunnel is up. flock keeps a single tunnel; the tunnel's own keep-alives
# make a dead connection exit, so the next run replaces it.
set -u
cd "$(dirname "$0")/.."
mkdir -p .state
if (exec 3<>/dev/tcp/127.0.0.1/19200) 2>/dev/null; then exit 0; fi
flock -n .state/tunnel.lock setsid nohup bash scripts/elastic-tunnel.sh >> .state/tunnel.log 2>&1 < /dev/null &
exit 0
