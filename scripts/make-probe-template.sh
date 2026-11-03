#!/usr/bin/env bash
# One-time (re-runnable) helper for M2 (issue #21). Run as root in the Proxmox node's own shell.
# Builds the A2 probe template from a Debian cloud image already on `iso-files`, inside the
# lab-firewall pool so the firewall token can clone it over the API (no node SSH in Tofu).
# Env: IMAGE (default iso-files:iso/debian-13-genericcloud-amd64.img), VMID (default 2100),
#      STORAGE (default iso-files, never `local`)
set -eu
export PATH="$PATH:/usr/sbin:/sbin"
IMAGE=${IMAGE:-iso-files:iso/debian-13-genericcloud-amd64.img}
VMID=${VMID:-2100}
STORAGE=${STORAGE:-iso-files}
[ "$(id -u)" = 0 ] || { echo "run as root on the node" >&2; exit 1; }
if qm status "$VMID" >/dev/null 2>&1; then echo "VM $VMID already exists; nothing to do"; exit 0; fi
path=$(pvesm path "$IMAGE")
[ -f "$path" ] || { echo "image not found: $path" >&2; exit 1; }
qm create "$VMID" --name opaleye-probe-template --pool lab-firewall --memory 512 --cores 1 --cpu host \
  --ostype l26 --scsihw virtio-scsi-pci --net0 virtio,bridge=vmbr2001 --serial0 socket --vga serial0 \
  --virtio0 "$STORAGE:0,import-from=$path,format=raw" --boot order=virtio0
qm resize "$VMID" virtio0 4G
qm set "$VMID" --ide2 "$STORAGE:cloudinit"
qm template "$VMID"
echo "template $VMID ready (pool lab-firewall)"
