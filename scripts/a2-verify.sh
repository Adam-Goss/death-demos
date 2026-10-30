#!/usr/bin/env bash
# A2 evidence (issue #21): isolation and egress probe matrix, run against the live lab.
#   a2-verify.sh <exercise|maintenance> [selected-target|none] [lab|vpn|home]
#   a2-verify.sh failclosed
# Prints one row per probe: source | destination/port | mode | expected | actual | enforcement point.
# Phases (each needs a different vantage; run all three for a full A2):
#   lab   probe guests in attacker/elastic/t1/t2 (tofu -var probe_vms=true); the gateway probes from the real gateway VM (no probe guest: it owns that address), reached over the VPN by SSH
#   vpn   from this workstation with the VPN UP   (source = operator)
#   home  from this workstation entering through the firewall WAN (source = workstation). Needs host routes
#         that beat the tunnel's /16, e.g. `sudo ip route add 10.77.11.10/32 via <wan_ip>` for each lab target
#         (attacker 10.77.1.10, elastic 10.77.3.10, t1 10.77.11.10); otherwise the rows are ERROR. Keep the VPN up
#         so the log check can reach the API. With the VPN down there is simply no route to the lab.
#         `home_other` (192.168.0.50) and `public` (203.0.113.55) rows bind to those addresses, so add them to this
#         host first: `sudo ip addr add 192.168.0.50/32 dev <if>`, same for 203.0.113.55 (spoofed source, never leaves the LAN
#         segment: it is routed to the firewall WAN by the host routes above).
# Env: PROBE_SSH (default: ssh -o BatchMode=yes -o ConnectTimeout=5, user opaleye), REVERIFY=1 (after a clean exercise/lab pass, clear labmode's re-verify flag),
#      and for `failclosed` and the `home` phase (firewall WAN MAC): PROXMOX_VE_ENDPOINT, PROXMOX_VE_API_TOKEN_FIREWALL, PVE_NODE, PROXMOX_VE_INSECURE.
#      ONLY_DST=<host> keeps only the rows whose destination is that host (A3 reruns the elastic rows against the real VM).
#      SKIP_SOURCES="elastic" lists sources that have no probe guest (e.g. the real Elastic VM owns that address): their rows are
#      SKIP, not ERROR, and the verdict becomes PASS-WITH-SKIPS. A source that is not listed but does not answer is still ERROR.
# Exit non-zero if any row differs from expected. Rows that cannot be sourced from here are listed as SKIP.
set -u
cd "$(dirname "$0")/.."
PY=${PYTHON:-python3}
PROBE_SSH=${PROBE_SSH:-ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new}

# run <src-host> <command>: execute on the vantage that owns that source address.
run() {
  case $1 in
    attacker|elastic|t1|t2|gateway) $PROBE_SSH "opaleye@$2" "$3" </dev/null ;;  # never let ssh eat the loop's stdin
    *) bash -c "$3" </dev/null ;;
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
probe_dns() { # python3 only: probe guests have no dig and no Internet to install it. Any reply counts as reachable.
  run "$1" "$2" "python3 -c \"import socket;s=socket.socket(2,2);s.settimeout(2);s.sendto(bytes.fromhex('123401000001000000000000076578616d706c6503636f6d0000010001'),('$3',53));s.recvfrom(512)\" >/dev/null 2>&1; echo rc=\$?" | grep -q 'rc=0$' && echo allow || echo deny
}
probe_ntp() {
  run "$1" "$2" "python3 -c \"import socket,sys;s=socket.socket(2,2);s.settimeout(2);s.sendto(b'\\x1b'+47*b'\\0',('$3',123));s.recvfrom(64)\" >/dev/null 2>&1; echo rc=\$?" | grep -q 'rc=0$' && echo allow || echo deny
}
probe_wg() { # allowed iff the firewall itself reports a fresh handshake from the workstation (it only completes through the WAN allow)
  $PY scripts/labmode.py wgpeer workstation "$1" 2>/dev/null && echo allow || echo deny
}
probe_noipv6() {
  # deny = no global IPv6 address, no IPv6 default route, and nothing answers an all-routers ping on the vantage link
  run "$1" "$2" "ip -6 addr show scope global | grep -q inet6 || ip -6 route show default | grep -q default || ping -6 -c1 -W2 -I \$(ls /sys/class/net | grep -v '^lo\$' | head -1) ff02::2 >/dev/null 2>&1; echo rc=\$?" | grep -Eq 'rc=[12]$' && echo deny || echo allow
}

probe_noipv6_vpn() { # the tunnel carries IPv6 only if the firewall's own peer config routes it
  $PY scripts/labmode.py wgv4only workstation 2>/dev/null && echo deny || echo allow
}
probe_noipv6_home() { # the firewall must not answer an all-nodes ping on the home LAN; silence from everyone is ERROR, not a deny
  local mac iface
  mac=$($PY scripts/nicaudit.py wanmac 2>/dev/null) || { echo ERROR; return; }
  iface=$(ip route get "$wan" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p')
  [ -n "$iface" ] || { echo ERROR; return; }
  ping -6 -c2 -W2 -I "$iface" ff02::1 >/dev/null 2>&1
  ip -6 neigh show dev "$iface" | $PY scripts/v6probe.py "$mac"
}

phase_of() { case $1 in attacker|elastic|t1|t2|gateway) echo lab ;; operator) echo vpn ;; workstation|home_other|public) echo home ;; *) echo none ;; esac; }

# Extra home-side source addresses are aliases on this host (sudo ip addr add <ip>/32 dev <if>); the probe binds to them.
probe_bound_tcp() { # src_ip dst_ip port
  python3 -c "
import socket
s = socket.socket(); s.bind(('$1', 0)); s.settimeout(3)
try:
    s.connect(('$2', $3)); print('rc=0')
except ConnectionRefusedError:
    print('rc=refused')
except Exception:
    print('rc=timeout')" 2>/dev/null | grep -Eq 'rc=(0|refused)' && echo allow || echo deny
}
probe_bound_udp() { # src_ip dst_ip port: a blocked UDP packet gets no answer, so "deny" means the firewall logged the block
  python3 -c "import socket;s=socket.socket(2,2);s.bind(('$1',0));s.sendto(b'x',('$2',$3))" 2>/dev/null || { echo ERROR; return; }
  for _ in 1 2 3; do $PY scripts/labmode.py denylog "$1" "$2" "$3" 2>/dev/null && { echo deny; return; }; sleep 1; done
  echo allow
}

if [ "${1:-}" = failclosed ]; then
  # The VPN ends on the firewall VM, so nothing can be run on the guests while it is down.
  # Arm each probe on its guest first (delayed), stop the firewall, restart it, then read the results.
  : "${PROXMOX_VE_ENDPOINT:?}" "${PROXMOX_VE_API_TOKEN_FIREWALL:?}" "${PVE_NODE:?}"
  vmid=$($PY -c "import json;print(json.load(open('network/plan.json'))['firewall']['vm_id'])")
  api() { curl -sS -o /dev/null -w '%{http_code}' ${PROXMOX_VE_INSECURE:+-k} -X POST -H "Authorization: PVEAPIToken=$PROXMOX_VE_API_TOKEN_FIREWALL" "${PROXMOX_VE_ENDPOINT%/}/api2/json/nodes/$PVE_NODE/qemu/$vmid/status/$1"; }
  rows=$($PY scripts/netpolicy.py matrix exercise t1 | awk -F'	' -v skip="${SKIP_SOURCES:-}" '$9=="allow" && $6=="tcp" && $12!="UPDATE_SOURCE" && ($2=="attacker"||$2=="elastic"||$2=="t1"||$2=="t2"||$2=="gateway") && index(" " skip " ", " " $2 " ")==0')
  while IFS=$'	' read -r id src dst proto port kind family mode expected enf sip dip; do
    [ -n "$id" ] || continue
    run "$src" "$sip" "rm -f /tmp/fc-$id; nohup sh -c 'sleep 40; out=\$(timeout 3 bash -c \"echo >/dev/tcp/$dip/$port\" 2>&1); echo \"\$? \$out\" >/tmp/fc-$id' >/dev/null 2>&1 &" || { echo "cannot arm $id on $src" >&2; exit 1; }
  done <<<"$rows"
  trap 'api start >/dev/null' EXIT
  echo "stopping firewall VM $vmid"; api stop >/dev/null; sleep 60; api start >/dev/null; trap - EXIT
  echo "firewall restarted; waiting for the VPN and guests"; sleep 90
  echo "| source | destination/port | mode | expected | actual | enforcement point |"; echo "| --- | --- | --- | --- | --- | --- |"
  fail=0
  while IFS=$'	' read -r id src dst proto port kind family mode expected enf sip dip; do
    [ -n "$id" ] || continue
    rc=$(run "$src" "$sip" "cat /tmp/fc-$id 2>/dev/null" 2>/dev/null)
    read -r code text <<<"$rc"  # "<exit code> <bash error text>"
    case $code in  # only a refusal (RST from the far end) or a connect proves a path; timeout and "no route" do not
      0) actual=allow ;;
      124) actual=deny ;;
      1) case $text in *refused*) actual=allow ;; *) actual=deny ;; esac ;;
      *) actual=ERROR ;;
    esac
    printf '| %s | %s:%s | firewall down | deny | %s | no forwarding path (VM stopped) |
' "$src" "$dst" "$port" "$actual"
    [ "$actual" = deny ] || fail=1
  done <<<"$rows"
  echo; echo "phase=failclosed rows=$(echo "$rows" | grep -c .) $([ $fail = 0 ] && echo PASS || echo FAIL)"
  exit $fail
fi

mode=${1:?usage: a2-verify.sh <exercise|maintenance> [target|none] [lab|vpn|home] | failclosed}
sel=${2:-none}
want=${3:-lab}
case $mode in exercise|maintenance) ;; *) echo "invalid mode: $mode" >&2; exit 1 ;; esac
case $want in lab|vpn|home) ;; *) echo "invalid phase: $want" >&2; exit 1 ;; esac
# Capture once and check the producer's status: process substitution hides failures.
matrix=$($PY scripts/netpolicy.py matrix "$mode" "$sel") || exit 1
# Only blocks logged after this point count as evidence for this run (digests of the rows already in the log).
LABMODE_LOG_BASELINE=$(mktemp) || exit 1
export LABMODE_LOG_BASELINE
trap 'rm -f "$LABMODE_LOG_BASELINE"' EXIT
$PY scripts/labmode.py logmark "$LABMODE_LOG_BASELINE" || { echo "cannot read the firewall log" >&2; exit 1; }
$PY scripts/netpolicy.py lint "$mode" "$sel" || exit 1  # the rules we think we pushed must already satisfy the matrix

wan=$($PY -c "import json;print(json.load(open('network/plan.json'))['firewall']['wan_ip'])"); wan=${wan%$'\r'}  # Windows python prints CRLF
ufqdn=$($PY -c "import json;print(json.load(open('network/plan.json'))['update_sources'][0])"); ufqdn=${ufqdn%$'\r'}  # resolved on each vantage, through the firewall DNS
echo "| source | destination/port | mode | expected | actual | enforcement point |"
echo "| --- | --- | --- | --- | --- | --- |"
fail=0; skipped=0; n=0
while IFS=$'\t' read -r id src dst proto port kind family mode_ expected enf sip dip; do
  dip=${dip%$'\r'}  # last column: Windows python prints CRLF
  [ "$(phase_of "$src")" = "$want" ] || continue
  [ -z "${ONLY_DST:-}" ] || [ "$dst" = "$ONLY_DST" ] || continue
  dips=
  case " ${SKIP_SOURCES:-} " in *" $src "*) dip=; kind=skip ;; esac  # no probe guest for this source
  if [ "$dip" = UPDATE_SOURCE ]; then  # the firewall alias resolves via its own DNS; resolve the same way a real update would
    # Every address the name resolves to: CDN answers rotate, and the alias holds whichever the firewall saw.
    dips=$(run "$src" "$sip" "getent ahostsv4 $ufqdn | awk '{print \$1}' | sort -u" 2>/dev/null | tr -d '\r')
    dip=$(echo "$dips" | head -n1)
  fi
  actual=SKIP
  [ -z "${dip:-}" ] && [ "$kind" != no-ipv6 ] && [ "$kind" != skip ] && actual=ERROR  # the update-source name did not resolve on the vantage: that is a broken path, not a skipped row
  # A dead vantage would turn every deny row green: it must answer before its rows count.
  if [ "$kind" = skip ]; then
    :  # SKIP_SOURCES: no probe guest for this source; reported as SKIP
  elif [ "$(phase_of "$src")" != none ] && ! run "$src" "$sip" true >/dev/null 2>&1; then
    actual=ERROR
  elif [ "$src" = operator ] && [ "$kind" != no-ipv6 ] && ! ip route get "$dip" 2>/dev/null | grep -q "src $sip"; then
    actual=ERROR  # the route to this destination bypasses the tunnel: it never reaches the firewall's VPN interface
  elif { [ "$src" = home_other ] || [ "$src" = public ]; } && ! ip -4 addr show 2>/dev/null | grep -q "inet $sip/"; then
    actual=ERROR  # this host does not own the source address: add it as an alias first
  elif [ "$(phase_of "$src")" = home ] && [ "$dst" != fw ] && ! ip route get "$dip" from "$sip" 2>/dev/null | grep -q "via $wan"; then
    actual=ERROR  # no route into the firewall WAN: the probe would die at the home router and prove nothing
  elif [ "$(phase_of "$src")" != none ] && { [ "$dip" != "" ] || [ "$kind" = no-ipv6 ]; }; then
    case $kind in
      tcp)      if [ "$src" = home_other ] || [ "$src" = public ]; then actual=$(probe_bound_tcp "$sip" "$dip" "$port")
                elif [ -n "$dips" ]; then  # update source: allowed if any address it resolves to is reachable
                  actual=deny
                  # CDN answers rotate and the alias only holds what the firewall resolved: when an allow is expected,
                  # Wait through the default 300-second alias refresh interval:
                  # DNS cache expiry can fall just after the firewall's last poll.
                  for attempt in {1..65}; do
                    for d in $dips; do [ "$(probe_tcp "$src" "$sip" "$d" "$port")" = allow ] && { actual=allow; break 2; }; done
                    [ "$expected" = allow ] || break
                    sleep 5
                    dips=$(run "$src" "$sip" "getent ahostsv4 $ufqdn | awk '{print \$1}' | sort -u" 2>/dev/null | tr -d '\r')
                  done
                else actual=$(probe_tcp "$src" "$sip" "$dip" "$port"); fi ;;
      dns)      actual=$(probe_dns "$src" "$sip" "$dip") ;;
      ntp)      actual=$(probe_ntp "$src" "$sip" "$dip") ;;
      wg)       if [ "$src" = home_other ]; then actual=$(probe_bound_udp "$sip" "$dip" "$port"); else actual=$(probe_wg "$sip"); fi ;;
      no-ipv6)  case $(phase_of "$src") in
                  vpn)  actual=$(probe_noipv6_vpn) ;;
                  home) actual=$(probe_noipv6_home) ;;
                  *)    actual=$(probe_noipv6 "$src" "$sip") ;;
                esac ;;
    esac
  fi
  where=$enf
  if [ "$actual" = deny ] && [ "$expected" = deny ] && [ "$kind" = tcp ]; then
    logged=no
    for _ in 1 2 3; do $PY scripts/labmode.py denylog "$sip" "$dip" "$port" 2>/dev/null && { logged=yes; break; }; sleep 1; done
    where="$enf (deny logged: $logged)"
    [ "$logged" = yes ] || fail=1
  fi
  if [ "$kind" = wg ] && [ "$src" = home_other ] && [ "$actual" = deny ]; then where="$enf (deny logged: yes)"; fi
  if [ "$actual" = SKIP ]; then skipped=$((skipped+1)); else n=$((n+1)); [ "$actual" = "$expected" ] || fail=1; fi
  printf '| %s | %s:%s | %s | %s | %s | %s |\n' "$src" "$dst" "$port" "$mode" "$expected" "$actual" "$where"
done <<<"$matrix"

total=$(printf '%s\n' "$matrix" | awk -F'	' -v p="$want" -v only="${ONLY_DST:-}" '
  only != "" && $3 != only {next}
  p=="lab"  && ($2=="attacker"||$2=="elastic"||$2=="t1"||$2=="t2"||$2=="gateway") {c++}
  p=="vpn"  && $2=="operator" {c++}
  p=="home" && ($2=="workstation"||$2=="home_other"||$2=="public") {c++}
  END {print c+0}')
if [ "$total" = 0 ]; then echo "NO PROBES: no rows matched this run"; fail=1; fi
if [ $((n + skipped)) != "$total" ]; then echo "ROWS MISSING: ran $((n + skipped)) of $total"; fail=1; fi
if [ "${REVERIFY:-}" = 1 ]; then
  if [ "$mode" != exercise ] || [ "$want" != lab ] || [ "$skipped" != 0 ] || [ -n "${ONLY_DST:-}" ]; then
    echo "cannot re-verify: requires an unfiltered exercise/lab run with no skipped rows" >&2
    fail=1
  elif [ $fail = 0 ]; then
    if $PY scripts/labmode.py reverified; then
      echo "labmode: exercise-mode denies re-verified"
    else
      echo "cannot record exercise-mode re-verification" >&2
      fail=1
    fi
  fi
fi
echo
verdict=FAIL; [ $fail = 0 ] && { verdict=PASS; [ $skipped = 0 ] || verdict="PASS-WITH-SKIPS"; }
echo "phase=$want mode=$mode selected=$sel rows=$n skipped=$skipped $verdict"
exit $fail
