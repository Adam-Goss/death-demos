#!/usr/bin/env bash
# One-time (re-runnable) helper for M4 (issue #23). Run as root in the Proxmox node's own shell.
# Builds the target VM template from a Debian cloud image already on `iso-files`, inside the lab-targets
# pool so the targets token can clone it over the API (no node SSH in Tofu). The image holds no secrets and no
# Elastic Agent: Fleet credentials are injected at provision time by Ansible, never baked in.
# Env: IMAGE (default iso-files:iso/debian-13-genericcloud-amd64.img), VMID (default: plan.json targets.t1.template_vm_id),
#      STORAGE (default iso-files)
set -eu
export PATH="$PATH:/usr/sbin:/sbin"
cd "$(dirname "$0")/.."
IMAGE=${IMAGE:-iso-files:iso/debian-13-genericcloud-amd64.img}
VMID=${VMID:-$(python3 -c "import json;print(json.load(open('network/plan.json'))['targets']['t1']['template_vm_id'])")}
STORAGE=${STORAGE:-iso-files}
BRIDGE=$(python3 -c "import json;p=json.load(open('network/plan.json'));print(p['zones']['t1']['bridge'])")
[ "$(id -u)" = 0 ] || { echo "run as root on the node" >&2; exit 1; }
pvesh get /pools/lab-targets >/dev/null 2>&1 || { echo "pool lab-targets missing: run scripts/bootstrap-proxmox.sh first" >&2; exit 1; }
if qm status "$VMID" >/dev/null 2>&1; then echo "VM $VMID already exists; nothing to do"; exit 0; fi
path=$(pvesm path "$IMAGE")
[ -f "$path" ] || { echo "image not found: $path" >&2; exit 1; }
qm create "$VMID" --name opaleye-target-template --pool lab-targets --memory 1024 --cores 1 --cpu host \
  --ostype l26 --scsihw virtio-scsi-pci --net0 "virtio,bridge=$BRIDGE" --serial0 socket --vga serial0 \
  --virtio0 "$STORAGE:0,import-from=$path,format=raw" --boot order=virtio0
qm resize "$VMID" virtio0 4G
qm set "$VMID" --ide2 "$STORAGE:cloudinit"
qm template "$VMID"
echo "template $VMID ready (pool lab-targets)"
