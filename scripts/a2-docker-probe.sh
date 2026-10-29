#!/usr/bin/env bash
# Safe Docker-published-port control for A2. Use only the disposable t1 probe.
# setup: maintenance mode, no exercise selected; check: exercise mode, t1 selected.
# Uses the same PROBE_SSH and LABMODE_STATE_DIR as a2-verify.sh. No vulnerable image.
set -euo pipefail
cd "$(dirname "$0")/.."
PROBE_SSH=${PROBE_SSH:-ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new}
action=${1:?usage: a2-docker-probe.sh setup|check}
case $action in setup|check) ;; *) exit 2 ;; esac
python3 - "$action" <<'PY'
import json, subprocess, sys
s = json.loads(subprocess.check_output(['python3', 'scripts/labmode.py', 'status']))
want = ('maintenance', None) if sys.argv[1] == 'setup' else ('exercise', 't1')
if (s['mode'], s['selected']) != want:
    raise SystemExit('requires mode/selected: %s/%s' % want)
PY
t1=$(python3 -c 'import json;print(json.load(open("network/plan.json"))["hosts"]["t1"]["ip"])')
remote() { $PROBE_SSH "opaleye@$1" "$2" </dev/null; }
[ "$(remote "$t1" hostname)" = opaleye-probe-t1 ] || { echo "refused: t1 is not the disposable probe" >&2; exit 1; }
if [ "$action" = setup ]; then
  # Build from the distro's static BusyBox binary, without pulling any container image.
  $PROBE_SSH "opaleye@$t1" 'sudo -n bash -se' <<'SH'
test "$(hostname)" = opaleye-probe-t1
export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=2 -o Acquire::http::Timeout=10 -o Acquire::https::Timeout=10 update -qq
apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=2 -o Acquire::http::Timeout=10 -o Acquire::https::Timeout=10 install -y -qq --no-install-recommends docker.io docker-cli busybox-static
/bin/busybox --list | grep -qx httpd
systemctl start docker
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp /bin/busybox "$work/busybox"
printf 'A2-safe-static-control\n' > "$work/index.html"
printf 'FROM scratch\nCOPY busybox /busybox\nCOPY index.html /www/index.html\nENTRYPOINT ["/busybox","httpd","-f","-p","8080","-h","/www"]\n' > "$work/Dockerfile"
docker build --network none --pull=false -t opaleye-a2-safe "$work"
docker rm -f opaleye-a2-safe >/dev/null 2>&1 || true
docker run -d --name opaleye-a2-safe --read-only --cap-drop ALL --security-opt no-new-privileges -p 80:8080 -p 8080:8080 opaleye-a2-safe
dpkg-query -W docker.io docker-cli busybox-static
docker image inspect opaleye-a2-safe --format '{{.Id}}'
docker port opaleye-a2-safe
SH
  exit
fi

# A real HTTP response on each published port is the positive control, from inside t1.
remote "$t1" "python3 -c \"import urllib.request; assert all(urllib.request.urlopen('http://127.0.0.1:'+p,timeout=3).read()==b'A2-safe-static-control\\n' for p in ['80','8080'])\""
baseline=$(mktemp)
trap 'rm -f "$baseline"' EXIT
python3 scripts/labmode.py logmark "$baseline"
export LABMODE_LOG_BASELINE=$baseline
printf '| source | destination/port | mode | expected | actual | enforcement point |\n| --- | --- | --- | --- | --- | --- |\n'
printf '| t1 loopback | t1:80,8080 | exercise | HTTP control | HTTP control | Docker published ports |\n'
fail=0
for source in attacker t2 elastic operator; do
  sip=$(python3 -c 'import json,sys;print(json.load(open("network/plan.json"))["hosts"][sys.argv[1]]["ip"])' "$source")
  for port in 80 8080; do
    expected=deny
    [ "$source:$port" != attacker:80 ] || expected=allow
    command="timeout 3 bash -c 'echo >/dev/tcp/$t1/$port' 2>&1; echo rc=\$?"
    if [ "$source" = operator ]; then
      ip route get "$t1" | grep -q "src $sip" || exit 1
      output=$(bash -c "$command")
    else
      remote "$sip" true
      output=$(remote "$sip" "$command")
    fi
    actual=deny
    case $output in *rc=0*|*refused*) actual=allow ;; esac
    where=firewall
    if [ "$actual:$expected" = deny:deny ]; then
      logged=no
      for _ in 1 2 3; do
        if python3 scripts/labmode.py denylog "$sip" "$t1" "$port" 2>/dev/null; then logged=yes; break; fi
        sleep 1
      done
      where="firewall (deny logged: $logged)"
      [ "$logged" = yes ] || fail=1
    fi
    printf '| %s | t1:%s | exercise | %s | %s | %s |\n' "$source" "$port" "$expected" "$actual" "$where"
    [ "$actual" = "$expected" ] || fail=1
  done
done
exit "$fail"
