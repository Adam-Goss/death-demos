#!/bin/sh
# Install into a mounted, offline OPNsense root, never over firewall SSH (#42).
# Called by bake-deadman.sh before upload. configd loads the action at boot;
# config.xml owns the cron schedule, so no service restart is needed here.
set -eu
cd "$(dirname "$0")/.."
target=${1:?usage: install-deadman.sh <mounted-opnsense-root>}
target=$(realpath "$target")
[ "$target" != / ] && [ -d "$target/usr/local/opnsense" ] || {
  echo "expected an offline OPNsense root (not /)" >&2; exit 1;
}
install -d "$target/usr/local/sbin" "$target/usr/local/opnsense/service/conf/actions.d"
install -m 755 scripts/firewall/opaleye_deadman.py "$target/usr/local/sbin/opaleye_deadman.py"
install -m 644 scripts/firewall/actions_opaleye.conf "$target/usr/local/opnsense/service/conf/actions.d/actions_opaleye.conf"
