#!/usr/bin/env bash
# One-off (re-runnable) helper for M2 (issue #41). Run as root in the Proxmox node's own shell.
# Builds the seeded OPNsense template: boots the baked nano disk once with the config seed
# attached, imports it over the serial console (scripts/firewall_console.py), powers off,
# drops the seed and converts the VM to a template in the lab-firewall pool. The firewall stack
# then clones it (no importer, no console). The disk holds the seed's secrets (WireGuard private
# key, API secret hash, root hash): keep the pool private; rotating a secret = rebuild the template.
# Env: NANO (required, baked nano disk on the node, .state/opnsense-nano.raw copied over),
#      SEED_ISO (required, volume id of the uploaded seed, e.g. iso-files:iso/opnsense-seed.iso;
#                deleted after use), VMID (default 2101), STORAGE (default iso-files, never `local`)
set -eu
export PATH="$PATH:/usr/sbin:/sbin"
NANO=${NANO:?set NANO to the baked nano disk path on this node}
SEED_ISO=${SEED_ISO:?set SEED_ISO to the uploaded seed volume id}
VMID=${VMID:-2101}
STORAGE=${STORAGE:-iso-files}
SOCK=/var/run/qemu-server/$VMID.serial0
[ "$(id -u)" = 0 ] || { echo "run as root on the node" >&2; exit 1; }
if qm status "$VMID" >/dev/null 2>&1; then echo "VM $VMID already exists; nothing to do"; exit 0; fi
[ -f "$NANO" ] || { echo "nano disk not found: $NANO" >&2; exit 1; }
pvesm path "$SEED_ISO" >/dev/null || { echo "seed ISO not found: $SEED_ISO" >&2; exit 1; }
here=$(cd "$(dirname "$0")" && pwd)
# No NICs: the importer needs none, and the clone gets its NICs from the firewall stack.
qm create "$VMID" --name opaleye-firewall-template --pool lab-firewall --memory 4096 --cores 2 --cpu host \
  --machine q35 --ostype other --scsihw virtio-scsi-pci --serial0 socket --vga serial0 \
  --virtio0 "$STORAGE:0,import-from=$NANO,format=raw" --boot order=virtio0 \
  --ide2 "$SEED_ISO,media=cdrom"
qm resize "$VMID" virtio0 20G
qm start "$VMID"
python3 "$here/firewall_console.py" "$SOCK" cd0
# poweroff was sent; wait for the guest to stop before touching its config.
for _ in $(seq 60); do
  [ "$(qm status "$VMID" | awk '{print $2}')" = stopped ] && break
  sleep 2
done
[ "$(qm status "$VMID" | awk '{print $2}')" = stopped ] || { echo "VM $VMID did not power off" >&2; exit 1; }
qm set "$VMID" --delete ide2
pvesm free "$SEED_ISO"
qm template "$VMID"
echo "template $VMID ready (pool lab-firewall); seed ISO deleted"
