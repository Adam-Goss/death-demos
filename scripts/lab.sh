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
