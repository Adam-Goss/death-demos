#!/usr/bin/env bash
# A2: lose the operator's WSL/Linux VPN path while the firewall stays running.
# Run as root with the normal OPNsense/Proxmox environment. Windows VPN settings
# are untouched. Captures and restores all IPv4 routes on the tunnel interface.
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo 'run as root in WSL/Linux' >&2; exit 1; }
IFS=$'\t' read -r elastic operator workstation proxmox wan vpn_gateway < <(python3 - <<'PY'
import ipaddress, json
with open('network/plan.json') as f:
    p=json.load(f)
print('\t'.join([p['hosts'][h]['ip'] for h in ['elastic','operator','workstation','proxmox']] +
                [p['firewall']['wan_ip'], str(ipaddress.ip_network(p['zones']['vpn']['cidr']).network_address+1)]))
PY
)
python3 - <<'PY'
import sys
sys.path.insert(0,'scripts')
import labmode
if labmode.Lab().st['mode'] != 'exercise':
    raise SystemExit('requires exercise mode before interrupting the VPN path')
PY
vpn_if=$(ip route get "$elastic" | sed -n 's/.* dev \([^ ]*\).*/\1/p')
home_if=$(ip route get "$wan" | sed -n 's/.* dev \([^ ]*\).*/\1/p')
[ "$vpn_if" != "$home_if" ]
ip -4 addr show dev "$vpn_if" | grep -Fq "inet $operator/"
[ -z "$(ip route show exact "$elastic/32")" ] || { echo 'existing Elastic host route: refusing overwrite' >&2; exit 1; }
saved=$(mktemp)
before=$(mktemp)
baseline=$(mktemp)
lowered=0
routed=0
cleanup() {
  local rc=0
  if [ "$routed" = 1 ]; then
    ip route del "$elastic/32" via "$wan" dev "$home_if" || rc=1
    routed=0
  fi
  if [ "$lowered" = 1 ]; then
    ip link set dev "$vpn_if" up || rc=1
    # Local routes can survive link-down, so restore may exit non-zero on those duplicates. That is not a failure:
    # the caller compares the full route snapshot after restoration, and cleanup must run to completion.
    ip -4 route restore < "$saved" || true
    lowered=0
  fi
  return "$rc"
}
trap 'cleanup; rm -f "$saved" "$before" "$baseline"' EXIT
ip -4 route save table all dev "$vpn_if" > "$saved"
ip -j -4 route show table all dev "$vpn_if" > "$before"
python3 scripts/labmode.py logmark "$baseline"
export LABMODE_LOG_BASELINE="$baseline"
tcp() {
  python3 - "$1" "$2" <<'PY'
import socket,sys
try:
    with socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=3):
        print('allow')
except ConnectionRefusedError:
    print('allow')
except OSError:
    print('deny')
PY
}
row() {
  printf '| %s | %s | exercise | %s | %s | %s |\n' "$1" "$2" "$3" "$4" "$5"
  [ "$3" = "$4" ]
}
is_down() { [ "$(cat "/sys/class/net/$vpn_if/operstate")" = down ]; }
date -u '+%Y-%m-%d %H:%M:%S UTC'
echo "Operator tunnel-facing interface: $vpn_if; interface and routes will be restored"
printf '| source | destination/port | mode | expected | actual | enforcement point |\n| --- | --- | --- | --- | --- | --- |\n'
row operator elastic:5601 allow "$(tcp "$elastic" 5601)" 'firewall VPN interface (positive control)'
lowered=1
ip link set dev "$vpn_if" down
is_down
row 'workstation, VPN path down' fw:443 deny "$(tcp "$vpn_gateway" 443)" 'operator tunnel-facing interface down'
row 'workstation, VPN path down' elastic:5601 deny "$(tcp "$elastic" 5601)" 'operator tunnel-facing interface down'
row 'workstation, VPN path down' proxmox:8006 allow "$(tcp "$proxmox" 8006)" 'home LAN positive control'
python3 - <<'PY'
import json,sys
sys.path.insert(0,'scripts')
import pve
with open('network/plan.json') as f:
    p=json.load(f)
for stack in ['firewall','elastic']:
    assert pve.from_env(stack).status(p[stack]['vm_id'])=='running'
print('control: firewall and Elastic VMs remain running')
PY
routed=1
ip route add "$elastic/32" via "$wan" dev "$home_if"
route=$(ip route get "$elastic")
echo "$route" | grep -Fq "via $wan"
echo "$route" | grep -Fq "src $workstation"
direct=$(tcp "$elastic" 5601)
is_down
cleanup
ip -j -4 route show table all dev "$vpn_if" | python3 -c 'import json,sys; before=json.load(open(sys.argv[1])); after=json.load(sys.stdin); assert sorted(json.dumps(r,sort_keys=True) for r in before)==sorted(json.dumps(r,sort_keys=True) for r in after), "tunnel routes differ after restoration"' "$before"
logged=no
for _ in 1 2 3; do
  if python3 scripts/labmode.py denylog "$workstation" "$elastic" 5601 2>/dev/null; then logged=yes; break; fi
  sleep 1
done
[ "$logged" = yes ]
row 'workstation, direct WAN route with VPN path down' elastic:5601 deny "$direct" 'firewall WAN (fresh deny logged)'
row operator elastic:5601 allow "$(tcp "$elastic" 5601)" 'restored VPN path (positive control)'
echo 'VPN path loss PASS; firewall remained running; interface and routes restored'
