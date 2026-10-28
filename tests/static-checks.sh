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

# M3 (issue #22): Elastic stack guards.
check "elastic VM has a destroy guard" grep -Eq 'prevent_destroy *= *true' tofu/stacks/elastic/main.tf
check "elastic packages pinned by sha512" python3 -c "import json,re,sys;e=json.load(open('network/plan.json'))['elastic'];sys.exit(0 if all(re.fullmatch('[0-9a-f]{128}',p['sha512']) for p in e['packages'].values()) else 1)"
check "no Elastic secrets in ansible/tofu (generated under secrets/)" bash -c "! grep -REn 'password: *[\"'\''][A-Za-z0-9]{8,}' ansible tofu/stacks/elastic"
check "elastic playbooks pass syntax-check (if ansible is installed)" bash -c "! command -v ansible-playbook >/dev/null || (cd ansible && ansible-playbook playbooks/elastic.yml --syntax-check)"

# M2 follow-up (issue #31): firewall config as code.
check "firewall seed is current, secret-free, rule-free and passes invariants" python3 scripts/opnsense_seed.py check
check "seed generator tests pass" python3 -m unittest tests.test_opnsense_seed
check "no real secrets in any non-ignored XML (config.xml seeds)" bash -c "echo \"$files\" | grep -E '\.xml$' | xargs python3 scripts/opnsense_seed.py scan"
check "no rendered seed or ISO outside gitignored paths" bash -c "! git ls-files | grep -Eq '(^|/)(opnsense-seed\.iso|config\.xml)$'"
check "firewall stack takes the seed by file id only (no secret variables)" bash -c "grep -q seed_iso_file_id tofu/stacks/firewall/main.tf && ! grep -Eiq 'variable \"[a-z_]*(password|secret|private_key|api_key)' tofu/stacks/firewall/*.tf"

exit $fail
