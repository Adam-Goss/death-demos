#!/usr/bin/env bash
# One-time (re-runnable) lab bridge setup for M2 (issue #21). Run as root in the Proxmox node's
# own shell, from a checkout of this repo. Needs python3 (stock on Proxmox).
# Creates one isolated Linux bridge per lab zone from network/plan.json: no host IP, no physical
# port, so the only path between zones is the firewall VM. Written to /etc/network/interfaces.d/,
# outside the Ludus-managed blocks in /etc/network/interfaces. Only new bridges are brought up
# (ifup), so Ludus bridges and the management bridge are never reloaded.
set -eu
export PATH="$PATH:/usr/sbin:/sbin"
cd "$(dirname "$0")/.."
CONF=/etc/network/interfaces.d/opaleye-lab.conf

[ "$(id -u)" = 0 ] || { echo "run as root on the node" >&2; exit 1; }
python3 scripts/netpolicy.py check
grep -Eq '^\s*source\s+/etc/network/interfaces\.d/\*' /etc/network/interfaces ||
  { echo "/etc/network/interfaces does not source interfaces.d; add that line by hand once" >&2; exit 1; }

new=$(mktemp); trap 'rm -f "$new"' EXIT
python3 scripts/netpolicy.py bridges >"$new"
if ! cmp -s "$new" "$CONF" 2>/dev/null; then
  install -m 0644 "$new" "$CONF"
  echo "wrote $CONF"
else
  echo "$CONF already current"
fi

bridges=$(python3 - <<'PY'
import json
p = json.load(open("network/plan.json"))
print(" ".join(z["bridge"] for n, z in p["zones"].items() if n != "home" and z["bridge"]))
PY
)
for b in $bridges; do
  ip link show "$b" >/dev/null 2>&1 || { ifup "$b"; echo "brought up $b"; }
done
echo "Bridges: $bridges"
echo "Next: HOME_BRIDGE=vmbr0 BRIDGES=\"$bridges\" scripts/bootstrap-proxmox.sh   (SDN.Use on the lab bridges; home bridge to the firewall token only)"
