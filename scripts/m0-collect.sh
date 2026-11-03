#!/usr/bin/env bash
# M0 site inventory: READ-ONLY. Run as root on the Proxmox node, then paste
# the output file into docs/inventory/site-inventory.md (issue #19, check A0).
set -u
out="m0-inventory-$(hostname)-$(date +%Y%m%d-%H%M%S).txt"
run() { echo; echo "### $*"; "$@" 2>&1 || echo "(exit $?)"; }
sh_() { echo; echo "### $1"; bash -c "$1" 2>&1 || echo "(exit $?)"; }
{
  run pveversion -v
  run lscpu
  run free -h
  run pvesm status
  run lsblk -o NAME,SIZE,TYPE,ROTA,MOUNTPOINT,MODEL
  sh_ 'df -h'
  sh_ 'cat /etc/network/interfaces; ls /etc/network/interfaces.d 2>/dev/null'
  run ip -br addr
  run ip -br link
  run ip route
  run ip -6 route
  sh_ 'bridge vlan show'
  sh_ 'sysctl net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.all.forwarding net.ipv4.ip_forward'
  sh_ 'cat /etc/pve/firewall/cluster.fw /etc/pve/nodes/$(hostname)/host.fw 2>/dev/null'
  sh_ 'pve-firewall status; nft list ruleset 2>/dev/null | head -50; iptables -S 2>/dev/null | head -20'
  sh_ 'cat /etc/pve/storage.cfg'
  sh_ 'pvesh get /cluster/resources --type vm --output-format json-pretty'
  sh_ 'cat /etc/resolv.conf; timedatectl'
} > "$out"
echo "wrote $out (review for secrets before committing)"
