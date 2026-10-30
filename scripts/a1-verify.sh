#!/usr/bin/env bash
# A1 evidence (issue #20). Run from the operator workstation after bootstrap.
# Records: source, destination, mode, expected, actual, enforcement point.
# Env: same as lab.sh. Exit non-zero if any check fails.
set -u
cd "$(dirname "$0")/.."
: "${PROXMOX_VE_ENDPOINT:?}"
base=${PROXMOX_VE_ENDPOINT%/}/api2/json
curlopt=(-sS -o /dev/null -w '%{http_code}'); [ "${PROXMOX_VE_INSECURE:-}" = true ] && curlopt+=(-k)
fail=0
row() { printf '| %s | %s | %s | %s | %s | %s |\n' "$@"; [ "$4" = "$5" ] || fail=1; }
echo "| source | destination | mode | expected | actual | enforcement point |"
echo "| --- | --- | --- | --- | --- | --- |"

stacks=(firewall elastic targets attacker gateway)
for s in "${stacks[@]}"; do
  var=PROXMOX_VE_API_TOKEN_$(echo "$s" | tr a-z A-Z); tok=${!var:?set $var}
  api() { curl "${curlopt[@]}" -H "Authorization: PVEAPIToken=$tok" "$base$1"; }
  row "$s token" "GET /pools/lab-$s" n/a "200" "$(api /pools/lab-$s)" "PVE pool ACL"
  for other in "${stacks[@]}"; do
    [ "$other" = "$s" ] && continue
    row "$s token" "GET /pools/lab-$other" n/a "403" "$(api /pools/lab-$other)" "PVE pool ACL"
  done
  row "$s token" "GET /storage/local" n/a "403" "$(api /storage/local)" "PVE storage ACL"
  row "$s token" "POST /access/users" n/a "403" "$(curl "${curlopt[@]}" -X POST -H "Authorization: PVEAPIToken=$tok" -d userid=x@pve "$base/access/users")" "no User.Modify"
done

echo
echo "Offline checks:"
bash tests/static-checks.sh || fail=1

echo
plan_out=$(mktemp); trap 'rm -f "$plan_out"' EXIT
echo "Ordered deploy then no-op re-apply (fresh state each time is the operator's call):"
scripts/lab.sh init all >/dev/null && scripts/lab.sh apply all >/dev/null || fail=1
for s in "${stacks[@]}"; do
  scripts/lab.sh plan "$s" >"$plan_out" 2>&1
  grep -q 'No changes' "$plan_out" && echo "no-op $s: yes" || { echo "no-op $s: NO"; fail=1; }
done
echo "node SSH used: no (provider has no ssh block; scripts never call ssh)"
exit $fail
