#!/usr/bin/env bash
# A5 evidence (issue #23): the target reached its known state from code, and no enrolment token is in the image.
# Run from the workstation over the VPN (operator -> target:22 is allowed; operator -> target:80 is denied by design,
# so the app is checked from inside the VM). Usage: a5-verify.sh <target>. Rows: source | destination/port | mode |
# expected | actual | enforcement point. Exit non-zero on any FAIL.
set -u
cd "$(dirname "$0")/.."
t=${1:?usage: a5-verify.sh <target>}
PLAN=network/plan.json
ip=$(python3 -c "import json;print(json.load(open('$PLAN'))['hosts']['$t']['ip'])") || exit 2
app=$(python3 -c "import json;i=json.load(open('$PLAN'))['target_stack']['dvwa']['images']['app'];print(i['ref']+'@'+i['digest'])")
db=$(python3 -c "import json;i=json.load(open('$PLAN'))['target_stack']['dvwa']['images']['db'];print(i['ref']+'@'+i['digest'])")
dir=$(python3 -c "import json;print(json.load(open('$PLAN'))['target_stack']['dvwa_dir'])")
level=$(python3 -c "import json;print(json.load(open('$PLAN'))['target_stack']['dvwa']['security_level'])")
SSH="ssh -o BatchMode=yes -o ConnectTimeout=10 opaleye@$ip"
fail=0
echo "| source | destination/port | mode | expected | actual | enforcement point |"
echo "| --- | --- | --- | --- | --- | --- |"
row() { # name expected actual
  local v=OK; [ "$2" = "$3" ] || { v=FAIL; fail=1; }
  echo "| operator | $t:22 $1 | exercise | $2 | $3 | in-guest ($v) |"
}
run() { $SSH "$@" 2>/dev/null | tr -d '\r' | head -1; }

row "app image digest" "$app" "$(run "sudo docker inspect --format '{{.Config.Image}}' \$(sudo docker-compose -f $dir/compose.yml ps -q dvwa)")"
row "db image digest" "$db" "$(run "sudo docker inspect --format '{{.Config.Image}}' \$(sudo docker-compose -f $dir/compose.yml ps -q db)")"
row "login page" "200" "$(run "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1/login.php")"
row "security level" "$level" "$(run "sudo docker-compose -f $dir/compose.yml exec -T dvwa printenv DEFAULT_SECURITY_LEVEL" | tr -d '[:space:]')"
row "database created" "yes" "$(run "test -f /var/lib/opaleye/dvwa-db.done && echo yes || echo no")"
row "agent state (2=HEALTHY)" "2" "$(run "sudo elastic-agent status --output json | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"state\"])'")"
# The token is never written by our code. These locations would hold it if a command line or file leaked it.
row "no enrolment token on disk outside the agent's own store" "0" "$(run "sudo grep -rIl -e '--enrollment-token' -e 'enrollment_token' $dir /etc/lab-ca /var/tmp /home /root /etc/systemd 2>/dev/null | wc -l" | tr -d '[:space:]')"
echo
[ $fail = 0 ] && echo "phase=A5 target=$t PASS" || echo "phase=A5 target=$t FAIL"
exit $fail
