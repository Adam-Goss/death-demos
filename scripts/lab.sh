#!/usr/bin/env bash
# Ordered runner for the Tofu stacks. Usage: lab.sh <init|plan|apply|destroy> <stack|all>
# Env (from the operator secrets store, never the repo):
#   OPALEYE_STATE_PASSPHRASE   offline-recoverable state key (>= 16 chars)
#   PROXMOX_VE_ENDPOINT        https://<node>:8006/
#   PROXMOX_VE_API_TOKEN_<STACK>  user@pve!deploy=<secret>, one per stack
#   PROXMOX_VE_INSECURE        optional, true for the default self-signed cert
set -eu
cd "$(dirname "$0")/.."
ORDER="firewall elastic targets attacker gateway"
cmd=${1:?usage: lab.sh <init|plan|apply|destroy> <stack|all>}
target=${2:?usage: lab.sh <init|plan|apply|destroy> <stack|all>}

: "${OPALEYE_STATE_PASSPHRASE:?set the state passphrase}"
[ "${#OPALEYE_STATE_PASSPHRASE}" -ge 16 ] || { echo "passphrase too short" >&2; exit 1; }
# It is interpolated into HCL: refuse characters that would break or inject.
case $OPALEYE_STATE_PASSPHRASE in *[\"\\\$]*) echo "passphrase must not contain \" \ or \$" >&2; exit 1;; esac
: "${PROXMOX_VE_ENDPOINT:?set the endpoint}"
export TF_ENCRYPTION="key_provider \"pbkdf2\" \"lab\" { passphrase = \"$OPALEYE_STATE_PASSPHRASE\" }"
mkdir -p .state

case $cmd in init|plan|apply|destroy) ;; *) echo "bad command" >&2; exit 1;; esac
if [ "$target" = all ]; then
  stacks=$ORDER
  # Guard: a broad destroy never reaches Elastic evidence.
  # Single quotes: in double quotes bash expands `$!` and the sed script collapses to "delete everything".
  if [ "$cmd" = destroy ]; then stacks=$(echo $ORDER | tr ' ' '\n' | grep -v '^elastic$' | sed '1!G;h;$!d' | tr '\n' ' '); fi
else
  # analysis (#52) is run by name only: its VMs are off by default and `all` must not build or destroy them.
  case " $ORDER analysis " in *" $target "*) stacks=$target;; *) echo "unknown stack" >&2; exit 1;; esac
  if [ "$cmd" = destroy ] && [ "$target" = elastic ]; then
    echo "refused: Elastic destroy is evidence deletion; use its guarded command (M3)" >&2; exit 1
  fi
fi

# The targets stack resolves a missing rebuild_generation entry to 1, and that entry is the VM's
# replace_triggered_by: unset, the variable turns any plan into "1 to add, 1 to change, 1 to destroy" with no
# "must be replaced" line to warn you, so an apply destroys a healthy target outside maintenance mode, with no
# drain check, and enrols the replacement back at generation 1 (#71). Derive it from the counters instead;
# scripts/target.sh stays their only writer, this is only a reader. No counters yet (a first build) means the
# empty map and the stack's own default of 1, which is the right generation for a VM that does not exist.
# A value exported by the operator wins, so an empty one is treated as absent: it is not valid HCL for a
# map(number), and passing it through would fail the stack rather than read the counter that is sitting there.
case " $stacks " in *" targets "*)
  if [ -z "${TF_VAR_rebuild_generation:-}" ]; then
    gens=
    for f in .state/targets/*.generation; do
      [ -f "$f" ] || continue
      t=$(basename "$f" .generation)
      g=$(cat "$f")
      # Both halves are interpolated into HCL, and a counter read as 0 or as junk would silently become a rebuild.
      # Same rule as the counter's writer, scripts/target.sh: keep the two in step. Refusing here, before the
      # stack loop, means a junk counter stops the deployment instead of half-applying it (the lesson of #65).
      case $t in ''|*[!a-z0-9_-]*) echo "bad target id in $f" >&2; exit 1;; esac
      case $g in ''|*[!0-9]*|0) echo "bad generation in $f: $g" >&2; exit 1;; esac
      gens="$gens${gens:+, }\"$t\": $g"
    done
    export TF_VAR_rebuild_generation="{$gens}"
  fi
  ;;
esac

for s in $stacks; do
  var=PROXMOX_VE_API_TOKEN_$(echo "$s" | tr a-z A-Z)
  [ -n "${!var:-}" ] || { echo "set $var" >&2; exit 1; }
  echo "== $cmd $s"
  ( export PROXMOX_VE_API_TOKEN=${!var}
    cd "tofu/stacks/$s"
    case $cmd in
      init) tofu init -input=false ;;
      plan) tofu plan -input=false -detailed-exitcode || [ $? = 2 ] ;;
      apply) tofu apply -input=false -auto-approve ;;
      destroy) tofu destroy -input=false -auto-approve ;;
    esac )
done

# The workstation timers (labmode tick, firewall flow shipper, Elastic tunnel) belong to a deployed lab: (re)install them
# for this checkout. A failure here never fails the deployment.
if [ "$cmd" = apply ] && [ "$target" = all ]; then
  bash scripts/ops-timers.sh install || echo "warning: ops timers not installed: run scripts/ops-timers.sh install" >&2
fi
