#!/usr/bin/env bash
# A2 evidence (issue #21): isolation and egress probe matrix, run against the live lab.
#   a2-verify.sh <exercise|maintenance> [selected-target|none] [lab|vpn|home]
#   a2-verify.sh failclosed
# Prints one row per probe: source | destination/port | mode | expected | actual | enforcement point.
# Phases (each needs a different vantage; run all three for a full A2):
#   lab   probe guests in attacker/elastic/t1/t2 (tofu -var probe_vms=true), reached over the VPN by SSH
#   vpn   from this workstation with the VPN UP   (source = operator)
#   home  from this workstation with the VPN DOWN (source = workstation; also proves VPN loss opens no route)
# Env: PROBE_SSH (default: ssh -o BatchMode=yes -o ConnectTimeout=5, user opaleye), WG_IFACE (VPN interface name,
#      for the handshake check), REVERIFY=1 (after a clean exercise/lab pass, clear labmode's re-verify flag),
#      and for `failclosed`: PROXMOX_VE_ENDPOINT, PROXMOX_VE_API_TOKEN_FIREWALL, PVE_NODE, PROXMOX_VE_INSECURE.
# Exit non-zero if any row differs from expected. Rows that cannot be sourced from here are listed as SKIP.
set -u
cd "$(dirname "$0")/.."
PY=${PYTHON:-python3}
PROBE_SSH=${PROBE_SSH:-ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new}

# run <src-host> <command>: execute on the vantage that owns that source address.
run() {
  case $1 in
    attacker|elastic|t1|t2) $PROBE_SSH "opaleye@$2" "$3" ;;
    *) bash -c "$3" ;;
  esac
}

probe_tcp() { # src src_ip dst_ip port
  local out
  out=$(run "$1" "$2" "timeout 3 bash -c 'echo >/dev/tcp/$3/$4' 2>&1; echo rc=\$?")
  case $out in
    *rc=0*) echo allow ;;
    *refused*) echo allow ;;  # RST came from the destination side: the packet crossed the firewall
    *) echo deny ;;
  esac
}
probe_dns() { run "$1" "$2" "dig +time=2 +tries=1 +short @$3 example.com >/dev/null 2>&1; echo rc=\$?" | grep -q 'rc=0$' && echo allow || echo deny; }
probe_ntp() {
  run "$1" "$2" "python3 -c \"import socket,sys;s=socket.socket(2,2);s.settimeout(2);s.sendto(b'\\x1b'+47*b'\\0',('$3',123));s.recvfrom(64)\" >/dev/null 2>&1; echo rc=\$?" | grep -q 'rc=0$' && echo allow || echo deny
}
probe_wg() { # allowed iff the VPN handshake is fresh
  [ -n "${WG_IFACE:-}" ] || { echo SKIP; return; }
  local hs; hs=$(wg show "$WG_IFACE" latest-handshakes 2>/dev/null | awk '{print $2}' | sort -n | tail -1)
  [ -n "$hs" ] && [ $(( $(date +%s) - hs )) -lt 180 ] && echo allow || echo deny
}
probe_noipv6() { # deny = no global IPv6 address and no IPv6 default route on the vantage
  run "$1" "$2" "ip -6 addr show scope global | grep -q inet6 || ip -6 route show default | grep -q default; echo rc=\$?" | grep -q 'rc=1$' && echo deny || echo allow
}

phase_of() { case $1 in attacker|elastic|t1|t2) echo lab ;; operator) echo vpn ;; workstation) echo home ;; *) echo none ;; esac; }

if [ "${1:-}" = failclosed ]; then
  : "${PROXMOX_VE_ENDPOINT:?}" "${PROXMOX_VE_API_TOKEN_FIREWALL:?}" "${PVE_NODE:?}"
  vmid=$($PY -c "import json;print(json.load(open('network/plan.json'))['firewall']['vm_id'])")
  api() { curl -sS -o /dev/null -w '%{http_code}' ${PROXMOX_VE_INSECURE:+-k} -X POST -H "Authorization: PVEAPIToken=$PROXMOX_VE_API_TOKEN_FIREWALL" "${PROXMOX_VE_ENDPOINT%/}/api2/json/nodes/$PVE_NODE/qemu/$vmid/status/$1"; }
  trap 'api start >/dev/null' EXIT
  echo "stopping firewall VM $vmid"; api stop >/dev/null; sleep 10
  echo "| source | destination/port | mode | expected | actual | enforcement point |"; echo "| --- | --- | --- | --- | --- | --- |"
  fail=0
  # Every flow the firewall normally allows must now be dead.
  while IFS=$'\t' read -r id src dst proto port kind family mode expected enf sip dip; do
    [ "$expected" = allow ] && [ "$kind" = tcp ] && [ "$(phase_of "$src")" = lab ] || continue
    [ "$dip" = UPDATE_SOURCE ] && continue
    actual=$(probe_tcp "$src" "$sip" "$dip" "$port")
    printf '| %s | %s:%s | firewall down | deny | %s | no forwarding path (VM stopped) |\n' "$src" "$dst" "$port" "$actual"
    [ "$actual" = deny ] || fail=1
  done < <($PY scripts/netpolicy.py matrix exercise t1)
  exit $fail
fi

mode=${1:?usage: a2-verify.sh <exercise|maintenance> [target|none] [lab|vpn|home] | failclosed}
sel=${2:-none}
want=${3:-lab}
$PY scripts/netpolicy.py lint "$mode" "$sel" || exit 1  # the rules we think we pushed must already satisfy the matrix

upd=$(getent ahostsv4 "$($PY -c "import json;print(json.load(open('network/plan.json'))['update_sources'][0])")" 2>/dev/null | awk 'NR==1{print $1}')
echo "| source | destination/port | mode | expected | actual | enforcement point |"
echo "| --- | --- | --- | --- | --- | --- |"
fail=0; skipped=0; n=0
while IFS=$'\t' read -r id src dst proto port kind family mode_ expected enf sip dip; do
  [ "$(phase_of "$src")" = "$want" ] || { [ "$(phase_of "$src")" = none ] && [ "$want" = home ] || continue; }
  [ "$dip" = UPDATE_SOURCE ] && dip=${upd:-}
  actual=SKIP
  if [ "$(phase_of "$src")" != none ] && { [ "$dip" != "" ] || [ "$kind" = no-ipv6 ]; }; then
    case $kind in
      tcp)      actual=$(probe_tcp "$src" "$sip" "$dip" "$port") ;;
      dns)      actual=$(probe_dns "$src" "$sip" "$dip") ;;
      ntp)      actual=$(probe_ntp "$src" "$sip" "$dip") ;;
      wg)       actual=$(probe_wg) ;;
      no-ipv6)  actual=$(probe_noipv6 "$src" "$sip") ;;
    esac
  fi
  where=$enf
  if [ "$actual" = deny ] && [ "$expected" = deny ] && [ "$kind" = tcp ]; then
    logged=no
    for _ in 1 2 3; do $PY scripts/labmode.py denylog "$sip" "$dip" "$port" 2>/dev/null && { logged=yes; break; }; sleep 1; done
    where="$enf (deny logged: $logged)"
    [ "$logged" = yes ] || fail=1
  fi
  if [ "$actual" = SKIP ]; then skipped=$((skipped+1)); else n=$((n+1)); [ "$actual" = "$expected" ] || fail=1; fi
  printf '| %s | %s:%s | %s | %s | %s | %s |\n' "$src" "$dst" "$port" "$mode" "$expected" "$actual" "$where"
done < <($PY scripts/netpolicy.py matrix "$mode" "$sel")

echo
echo "phase=$want mode=$mode selected=$sel rows=$n skipped=$skipped $([ $fail = 0 ] && echo PASS || echo FAIL)"
if [ $fail = 0 ] && [ "${REVERIFY:-}" = 1 ] && [ "$mode" = exercise ] && [ "$want" = lab ]; then
  $PY scripts/labmode.py reverified && echo "labmode: exercise-mode denies re-verified"
fi
exit $fail
