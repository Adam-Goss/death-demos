#!/usr/bin/env bash
# Provision or rebuild a target VM (issue #23). Usage: target.sh <provision|bump|generation> <target> [--acknowledge-no-drain-check]
#   provision   Tofu apply of the targets stack at the current generation, then the Ansible target play. Re-runnable.
#   bump        increment the rebuild generation (the next provision replaces the VM). The drain check that makes a
#               reset safe is `scripts/labops.py reset`, which runs it and then calls bump; run by hand, bump refuses
#               without --acknowledge-no-drain-check (acknowledged loss).
#   generation  print the current generation
# Needs maintenance mode for provision (image pulls, apt) and scripts/elastic-tunnel.sh running (agent registration).
# Env as for lab.sh, plus TF_VAR_node_name and TF_VAR_ssh_public_key.
set -eu
cd "$(dirname "$0")/.."
cmd=${1:?usage: target.sh <provision|bump|generation> <target>}
t=${2:?usage: target.sh <provision|bump|generation> <target>}
python3 - "$t" <<'PY' || { echo "unknown target (no VM in network/plan.json)" >&2; exit 1; }
import json, sys
t = json.load(open("network/plan.json"))["targets"].get(sys.argv[1], {})
sys.exit(0 if "vm_id" in t else 1)
PY
gen_file=.state/targets/$t.generation
mkdir -p .state/targets
[ -f "$gen_file" ] || echo 1 > "$gen_file"
gen=$(cat "$gen_file")
case $gen in ''|*[!0-9]*|0) echo "bad generation in $gen_file" >&2; exit 1;; esac

case $cmd in
  generation) echo "$gen" ;;
  bump)
    [ "${3:-}" = --acknowledge-no-drain-check ] || {
      echo "refused: bump has no drain check of its own. Use scripts/labops.py reset (drain check first); unshipped events of the old target are lost on rebuild." >&2
      echo "re-run with --acknowledge-no-drain-check to accept that loss" >&2; exit 1; }
    echo $((gen + 1)) > "$gen_file"; echo "generation $((gen + 1))" ;;
  provision)
    ip=$(python3 -c "import json;print(json.load(open('network/plan.json'))['hosts']['$t']['ip'])")
    export TF_VAR_rebuild_generation="{\"$t\": $gen}"
    scripts/lab.sh apply targets
    ssh-keygen -R "$ip" >/dev/null 2>&1 || true   # a rebuilt VM has a new host key
    ( cd ansible && ansible-galaxy collection install -r requirements.yml >/dev/null \
      && ansible-playbook playbooks/target.yml -e "target=$t" -e "rebuild_generation=$gen" ) ;;
  *) echo "bad command" >&2; exit 2 ;;
esac
