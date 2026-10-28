# M0 site inventory and authority

Issue #19. Exit = check A0 in [acceptance checks](../decisions/acceptance-checks-and-build-plan.md). Evidence format: source, destination/port, mode, expected, actual, enforcement point. Collect with `scripts/m0-collect.sh`. Redact secrets and public IPs as needed.

## Facts (human fills)

| Item | Value | Evidence (command/source) |
| --- | --- | --- |
| PVE version | | `pveversion -v` |
| Firewall backend (pve-firewall / nftables / iptables) | | |
| `/etc/network/interfaces` summary | | |
| Bridges / VLANs in use, free VLAN IDs | | |
| Router / gateway model, VLAN support | | |
| IPv6 state (host, LAN, router RA/DHCPv6) | | |
| Management path + out-of-band recovery console | | |
| CPU (`lscpu`) | | |
| RAM (`free -h`) | | |
| Storage + disk type (`pvesm status`) | | |
| Separate backup storage (or explicit risk acceptance, #9) | | |
| Image approach (cloud image + first boot vs Packer) | | #8 |
| Image pins + checksums | | |
| Authority to change shared networking (who, scope) | | |

## A0 sizing check

Allocatable must be >= #9 placeholders: ~9-10 vCPU / 18 GB RAM, Elastic 100 GB data disk.

| Resource | Needed | Allocatable | Pass |
| --- | --- | --- | --- |
| vCPU | 9-10 | | |
| RAM | 18 GB | | |
| Disk (data) | 100 GB + backups | | |

If any fail: **reopen sizing**, do not shrink silently.

## A0 result

- [ ] All facts recorded
- [ ] Sizing >= placeholders
- [ ] Change authority confirmed
- M1 does not start until all three checked.
