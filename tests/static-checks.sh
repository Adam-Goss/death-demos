#!/usr/bin/env bash
# Offline guards for A1 (issue #20): layout, encrypted state, no SSH, no secrets,
# token scoped to lab pools. Needs no Proxmox, tofu or network.
set -u
cd "$(dirname "$0")/.."
# Ansible ignores ansible.cfg in a world-writable directory (a checkout on /mnt/c in WSL): name it explicitly.
export ANSIBLE_CONFIG="$PWD/ansible/ansible.cfg"
fail=0
ok_count=0
fail_count=0
skip_count=0
ok()  { echo "ok   $*"; ok_count=$((ok_count + 1)); }
bad() { echo "FAIL $*"; fail=1; fail_count=$((fail_count + 1)); }
skip() { echo "SKIP $* (Git index unavailable)"; skip_count=$((skip_count + 1)); }
git_available=false
if git rev-parse --is-inside-work-tree 2>/dev/null | grep -qx true; then
  git_available=true
fi
git_check() { if "$git_available"; then check "$@"; else skip "$1"; fi; }
check() { local desc=$1; shift; if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi; }

stacks=(firewall elastic targets attacker gateway analysis)

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

# Scan the filesystem, including untracked files, even in a git-archive checkout.
check "no PVE token secrets (uuid) in repo" python3 scripts/scan_secrets.py token
check "no private keys in repo" python3 scripts/scan_secrets.py key
git_check "no tfstate/tfvars tracked" bash -c "! git ls-files | grep -Eq '\.(tfstate|tfvars)(\.|$)'"

# M2 (issue #21): lab network plan and isolation guards.
check "network plan is sane (unique bridges, no overlap with Ludus/home)" python3 scripts/netpolicy.py check
check "exercise rules match the A2 probe matrix" python3 scripts/netpolicy.py lint exercise t1
check "maintenance rules match the A2 probe matrix" python3 scripts/netpolicy.py lint maintenance
# Archive regression tests invoke this script themselves; run them separately
# rather than recursively multiplying the bundled suites during an A1 check.
check "netpolicy and labmode unit tests pass" env STATIC_CHECKS_NESTED=1 python3 -m unittest discover -s tests -p 'test_*.py'
check "firewall stack builds NICs from the plan (no literal bridge names)"   bash -c "grep -q 'nic_order' tofu/stacks/firewall/main.tf && ! grep -Eq 'vmbr[0-9]+' tofu/stacks/*/*.tf"
check "only the firewall stack can reach the home bridge"   bash -c "! grep -Eq 'zones\.home|zones\[\"home\"\]|\.home\b' tofu/stacks/elastic/*.tf tofu/stacks/targets/*.tf tofu/stacks/attacker/*.tf"
check "bridge bootstrap writes outside Ludus blocks (interfaces.d)" grep -q 'interfaces.d' scripts/bootstrap-bridges.sh
check "A2 verifier exists" test -f scripts/a2-verify.sh
check "firewall ISO is pinned by a 64-hex sha256 in the plan" python3 -c "import json,re,sys;i=json.load(open('network/plan.json'))['firewall']['image'];sys.exit(0 if re.fullmatch('[0-9a-f]{64}',i['sha256']) else 1)"

# M3 (issue #22): Elastic stack guards.
check "elastic VM has a destroy guard" grep -Eq 'prevent_destroy *= *true' tofu/stacks/elastic/main.tf
check "elastic packages pinned by sha512" python3 -c "import json,re,sys;e=json.load(open('network/plan.json'))['elastic'];sys.exit(0 if all(re.fullmatch('[0-9a-f]{128}',p['sha512']) for p in e['packages'].values()) else 1)"
check "no Elastic secrets in ansible/tofu (generated under secrets/)" bash -c "! grep -REn 'password: *[\"'\''][A-Za-z0-9]{8,}' ansible tofu/stacks/elastic"
check "elastic playbooks pass syntax-check (if ansible is installed)" bash -c "! command -v ansible-playbook >/dev/null || (cd ansible && ansible-playbook playbooks/elastic.yml --syntax-check)"

# M5 (issue #24): attacker stack and operator-command guards.
check "operator commands never reference evidence deletion" bash -c "! grep -Eq 'evidence-delete|evidence_delete|_delete_by_query' scripts/labops.py scripts/labpower.py scripts/pve.py scripts/lab.sh scripts/target.sh"
check "attacker playbook passes syntax-check (if ansible is installed)" bash -c "! command -v ansible-playbook >/dev/null || (cd ansible && ansible-playbook playbooks/attacker.yml --syntax-check)"

# M4 (issue #23): target VM guards.
check "target images pinned by digest in the plan" python3 -c "import json,re,sys;i=json.load(open('network/plan.json'))['target_stack']['dvwa']['images'];sys.exit(0 if all(re.fullmatch('sha256:[0-9a-f]{64}',v['digest']) for v in i.values()) else 1)"
check "integration zips pinned by sha256 in the plan" python3 -c "import json,re,sys;i=json.load(open('network/plan.json'))['target_stack']['integrations'];sys.exit(0 if all(re.fullmatch('[0-9a-f]{64}',v['sha256']) for v in i.values()) else 1)"
check "no enrolment token in the target role or template script" bash -c "! grep -RIniE 'enrol+ment[-_ ]?(token|key)|api_key' ansible/roles/target/templates ansible/roles/target/defaults scripts/make-target-template.sh"
check "target stack has no prevent_destroy (rebuilt, never kept)" bash -c "! grep -q prevent_destroy tofu/stacks/targets/main.tf"
check "target playbooks pass syntax-check (if ansible is installed)" bash -c "! command -v ansible-playbook >/dev/null || (cd ansible && ansible-playbook playbooks/target.yml --syntax-check -e target=t1 -e rebuild_generation=1 && ansible-playbook playbooks/elastic-evidence.yml --syntax-check)"
check "fleetctl and target tests pass" python3 -m unittest tests.test_fleetctl tests.test_target_plan

# M2 follow-up (issue #31): firewall config as code.
check "firewall seed is current, secret-free, rule-free and passes invariants" python3 scripts/opnsense_seed.py check
check "seed generator tests pass" python3 -m unittest tests.test_opnsense_seed
check "no real secrets in any non-ignored XML (config.xml seeds)" python3 scripts/scan_secrets.py xml
git_check "no rendered seed or ISO outside gitignored paths" bash -c "! git ls-files | grep -Eq '(^|/)(opnsense-seed\.iso|config\.xml)$'"
check "firewall stack takes the seed by file id only (no secret variables)" bash -c "grep -q seed_iso_file_id tofu/stacks/firewall/main.tf && ! grep -Eiq 'variable \"[a-z_]*(password|secret|private_key|api_key)' tofu/stacks/firewall/*.tf"
check "seed ISO builder exists" test -x scripts/seed-build.sh
git_check "seed ISO stays out of git" bash -c "git check-ignore -q .state/opnsense-seed.iso"
check "nano image fetcher exists and its tests pass" bash -c "test -f scripts/fetch_nano.py && python3 -m unittest tests.test_fetch_nano"
git_check "fetched nano image stays out of git" bash -c "git check-ignore -q .state/opnsense-nano.raw"

# M2 follow-up (issue #41): hands-off first boot from a cloned seeded template.
check "firewall template builder and console driver exist" test -f scripts/make-firewall-template.sh -a -f scripts/firewall_console.py
check "console driver tests pass" python3 -m unittest tests.test_firewall_console
check "template builder deletes the seed ISO (secrets leave the store)" grep -q 'pvesm free "\$SEED_ISO"' scripts/make-firewall-template.sh
check "template builder puts the template in the private lab-firewall pool" grep -q -- '--pool lab-firewall' scripts/make-firewall-template.sh
check "firewall stack clones the template and uploads no seed or nano disk (secrets stay off the API and state)" bash -c "grep -q firewall_template_vm_id tofu/stacks/firewall/main.tf && ! grep -q proxmox_virtual_environment_file tofu/stacks/firewall/main.tf"

# #51: Guacamole gateway guards.
check "gateway images pinned by digest in the plan" python3 -c "import json,re,sys;i=json.load(open('network/plan.json'))['gateway']['guacamole']['images'];sys.exit(0 if all(re.fullmatch('sha256:[0-9a-f]{64}',v['digest']) for v in i.values()) else 1)"
check "gateway tests pass" python3 -m unittest tests.test_guacctl
check "no Guacamole secrets in the gateway role or guacctl (generated on the VM / from env)" bash -c "! grep -REn 'PASSWORD *[=:] *[A-Za-z0-9]{12,}' ansible/roles/gateway scripts/guacctl.py"
git_check "gateway secrets directory is gitignored" bash -c "git check-ignore -q secrets/gateway/targets_ed25519"
check "gateway playbook passes syntax-check (if ansible is installed)" bash -c "! command -v ansible-playbook >/dev/null || (cd ansible && ansible-playbook playbooks/gateway.yml --syntax-check)"

# #52: malware analysis zone guards.
check "analysis rules match the A2 probe matrix with the Internet toggle on (exercise)" python3 scripts/netpolicy.py lint exercise none online
check "analysis rules match the A2 probe matrix with the Internet toggle on (maintenance)" python3 scripts/netpolicy.py lint maintenance none online
check "analysis plan, labmode toggle, reset, fleet policy and connection tests pass" python3 -m unittest tests.test_analysis_plan tests.test_netpolicy tests.test_labmode tests.test_labops tests.test_fleetctl tests.test_guacctl
check "no secrets in the analysis role, runbook or ops commands" bash -c "! grep -REn 'PASSWORD *[=:] *[A-Za-z0-9]{12,}' ansible/roles/analysis_remnux docs/runbooks/malware-analysis.md scripts/labops.py"
check "analysis playbook passes syntax-check (if ansible is installed)" bash -c "! command -v ansible-playbook >/dev/null || (cd ansible && ansible-playbook playbooks/analysis.yml --syntax-check)"

# #60: the lab skills in .claude/skills/ name only commands, paths and documents this repo has.
check "skills match the repo (frontmatter, cited paths, real subcommands)" python3 -m unittest tests.test_skills

# #65: a reset must not die halfway because a script has no exec bit (a checkout synced from /mnt/c has none).
check "scripts run in a checkout with no exec bits (bash callers, shebang means exec bit)" python3 -m unittest tests.test_script_exec

# Workstation timers (ops-timers.sh): one install/status/remove for tick, flow shipper and tunnel.
check "ops timer scripts are valid shell" bash -n scripts/ops-timers.sh scripts/install-tunnel-timer.sh scripts/tunnel-keepalive.sh scripts/install-tick-timer.sh scripts/install-flow-timer.sh scripts/elastic-tunnel.sh
check "ops timers install, status and stale detection" python3 -m unittest tests.test_ops_timers

echo "Summary: $ok_count ok, $fail_count FAIL, $skip_count SKIP"
exit $fail
