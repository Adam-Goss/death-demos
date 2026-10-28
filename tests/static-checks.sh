#!/usr/bin/env bash
# Offline guards for A1 (issue #20): layout, encrypted state, no SSH, no secrets,
# token scoped to lab pools. Needs no Proxmox, tofu or network.
set -u
cd "$(dirname "$0")/.."
fail=0
ok()  { echo "ok   $*"; }
bad() { echo "FAIL $*"; fail=1; }
check() { local desc=$1; shift; if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi; }

stacks=(firewall elastic targets)

for s in "${stacks[@]}"; do
  d=tofu/stacks/$s
  check "$s: has versions.tf, main.tf, outputs.tf" test -f $d/versions.tf -a -f $d/main.tf -a -f $d/outputs.tf
  check "$s: state encryption enforced" grep -q 'enforced *= *true' $d/versions.tf
  check "$s: own local state path" grep -q "\.state/$s\.tfstate" $d/versions.tf
  check "$s: provider pinned" grep -Eq 'version *= *"= ?[0-9]' $d/versions.tf
  check "$s: no SSH block (API token only)" bash -c "! grep -Eq '^\s*ssh\s*\{' $d/*.tf"
  check "$s: no hardcoded token" bash -c "! grep -Eq 'api_token *= *\"' $d/*.tf"
done

check "bootstrap script exists" test -x scripts/bootstrap-proxmox.sh -o -f scripts/bootstrap-proxmox.sh
check "ordered runner exists" test -f scripts/lab.sh
check "A1 verifier exists" test -f scripts/a1-verify.sh
check "ansible.cfg exists" test -f ansible/ansible.cfg
check "gitignore covers state, tfvars, keys" bash -c "grep -q '^\.state/' .gitignore && grep -q 'tfvars' .gitignore && grep -q 'secrets' .gitignore"

# Token role must stay inside lab scope: no Sys.*, Permissions.Modify, or root ACL path.
check "role has no Sys./Permissions.Modify privileges" \
  bash -c "! grep -E 'privs=|PRIVS=' scripts/bootstrap-proxmox.sh | grep -Eq 'Sys\.|Permissions\.Modify|Realm'"
check "ACLs never granted on '/' root path" bash -c "! grep -Eq 'acl modify +/ ' scripts/bootstrap-proxmox.sh"
check "token privilege separation on" grep -q -- '--privsep 1' scripts/bootstrap-proxmox.sh
check "one token per stack" bash -c "[ \$(grep -c 'token add' scripts/bootstrap-proxmox.sh) -ge 1 ] && grep -q 'for stack in' scripts/bootstrap-proxmox.sh"

# No secrets in the repo (tracked or not-ignored files).
files=$(git ls-files -co --exclude-standard | grep -v '^tests/static-checks.sh$')
check "no PVE token secrets (uuid) in repo" bash -c "! echo \"$files\" | xargs grep -EIl '[A-Za-z0-9_-]+@[a-z]+![A-Za-z0-9_-]+=[0-9a-f]{8}-[0-9a-f]{4}-' 2>/dev/null | grep -q ."
check "no private keys in repo" bash -c "! echo \"$files\" | xargs grep -EIl 'BEGIN (OPENSSH|RSA|EC) PRIVATE KEY|AGE-SECRET-KEY' 2>/dev/null | grep -q ."
check "no tfstate/tfvars tracked" bash -c "! git ls-files | grep -Eq '\.(tfstate|tfvars)(\.|$)'"

# M2 (issue #21): lab network plan and isolation guards.
check "network plan is sane (unique bridges, no overlap with Ludus/home)" python3 scripts/netpolicy.py check
check "exercise rules match the A2 probe matrix" python3 scripts/netpolicy.py lint exercise t1
check "maintenance rules match the A2 probe matrix" python3 scripts/netpolicy.py lint maintenance
check "netpolicy and labmode unit tests pass" python3 -m unittest discover -s tests -p 'test_*.py'
check "firewall stack builds NICs from the plan (no literal bridge names)"   bash -c "grep -q 'nic_order' tofu/stacks/firewall/main.tf && ! grep -Eq 'vmbr[0-9]+' tofu/stacks/*/*.tf"
check "only the firewall stack can reach the home bridge"   bash -c "! grep -Eq 'zones\.home|zones\[\"home\"\]|\.home\b' tofu/stacks/elastic/*.tf tofu/stacks/targets/*.tf"
check "bridge bootstrap writes outside Ludus blocks (interfaces.d)" grep -q 'interfaces.d' scripts/bootstrap-bridges.sh
check "A2 verifier exists" test -f scripts/a2-verify.sh
check "firewall ISO is pinned by a 64-hex sha256 in the plan" python3 -c "import json,re,sys;i=json.load(open('network/plan.json'))['firewall']['image'];sys.exit(0 if re.fullmatch('[0-9a-f]{64}',i['sha256']) else 1)"

# M2 follow-up (issue #31): firewall config seed.
check "seed tooling exists" test -x scripts/seed-build.sh -a -f scripts/seed-sanitize.py
check "seed template (if present) holds no secrets or filter rules" bash -c "[ ! -f seed/opnsense/config.xml.tmpl ] || python3 -c 'import importlib.util as u,sys;sp=u.spec_from_file_location(\"s\",\"scripts/seed-sanitize.py\");m=u.module_from_spec(sp);sp.loader.exec_module(m);sys.exit(1 if m.leaks(open(\"seed/opnsense/config.xml.tmpl\").read()) else 0)'"
check "no raw config.xml tracked" bash -c "! git ls-files -co --exclude-standard | grep -E '(^|/)config\.xml$'"
check "seed ISO stays out of git" bash -c "git check-ignore -q .state/opnsense-seed.iso"

exit $fail
