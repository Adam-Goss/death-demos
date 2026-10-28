#!/usr/bin/env bash
# One-time Proxmox bootstrap for M1 (issue #20). Run as root in the Proxmox node's own
# shell (console/UI shell), not over routine deployment. Creates lab pools, one role,
# and one privilege-separated API token per stack, each scoped to its own pool.
# Re-runnable: existing objects are left as they are. Token secrets print ONCE to the
# terminal; copy them to the operator secrets store. Nothing is written to disk.
#
# Env: STORAGE (default iso-files; never `local`, see docs/inventory/site-inventory.md)
#      BRIDGES (space-separated lab bridges to allow VM NICs on, set once M2 creates them)
#      HOME_BRIDGE (home-side bridge, e.g. vmbr0): granted to the firewall token ONLY, so no other
#                  stack can attach a NIC to it
#      ROTATE=1 re-issues each stack token (use if a secret was lost)
set -eu
export PATH="$PATH:/usr/sbin:/sbin"  # pveum lives in /usr/sbin; not on every root shell PATH
STORAGE=${STORAGE:-iso-files}
BRIDGES=${BRIDGES:-}
HOME_BRIDGE=${HOME_BRIDGE:-}
ROTATE=${ROTATE:-0}
ROLE=OpaleyeDeploy
# Deliberately no Sys.*, Permissions.*, Realm.* or User.* privileges.
PRIVS="VM.Allocate VM.Audit VM.Clone VM.Config.CDROM VM.Config.CPU VM.Config.Cloudinit VM.Config.Disk VM.Config.HWType VM.Config.Memory VM.Config.Network VM.Config.Options VM.PowerMgmt Datastore.AllocateSpace Datastore.Audit Pool.Audit"
NET_ROLE=OpaleyeNet   # SDN.Use only, for lab bridges (M2)

[ "$(id -u)" = 0 ] || { echo "run as root on the node" >&2; exit 1; }

role_exists() { pveum role list --output-format json | tr -d ' ' | grep -q "\"roleid\":\"$1\""; }
role_exists "$ROLE" || pveum role add "$ROLE" --privs "$(echo $PRIVS | tr ' ' ',')"
role_exists "$NET_ROLE" || pveum role add "$NET_ROLE" --privs SDN.Use

for stack in firewall elastic targets attacker; do
  pool=lab-$stack
  user=opaleye-$stack@pve
  pvesh get /pools/$pool >/dev/null 2>&1 || pvesh create /pools --poolid "$pool" --comment "Opaleye $stack stack"
  pveum user list --output-format json | tr -d ' ' | grep -q "\"userid\":\"$user\""     || pveum user add "$user" --comment "Opaleye $stack deploy"
  # Token first: ACLs on a token need it to exist. No user password; API token only.
  has_token() { pveum user token list "$user" --output-format json | tr -d ' ' | grep -q '"tokenid":"deploy"'; }
  if has_token && [ "$ROTATE" = 1 ]; then pveum user token remove "$user" deploy; fi
  if has_token; then
    echo "token $user!deploy exists; not re-issued (ROTATE=1 to re-issue)"
  else
    echo "=== $stack token (shown once) ==="
    pveum user token add "$user" deploy --privsep 1 --comment "Opaleye $stack stack"
  fi
  # privsep: effective rights = user ACL intersect token ACL, so grant both.
  for who in "--users $user" "--tokens $user!deploy"; do
    pveum acl modify "/pool/$pool" $who --roles "$ROLE"
    pveum acl modify "/storage/$STORAGE" $who --roles "$ROLE"
    for br in $BRIDGES; do
      pveum acl modify "/sdn/zones/localnetwork/$br" $who --roles "$NET_ROLE"
    done
    if [ "$stack" = firewall ]; then
      for br in $HOME_BRIDGE; do
        pveum acl modify "/sdn/zones/localnetwork/$br" $who --roles "$NET_ROLE"
      done
    fi
  done
done
echo "Done. Run scripts/a1-verify.sh from the workstation."
