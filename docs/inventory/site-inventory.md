# M0 site inventory and authority

Issue #19. Exit = check A0 in [acceptance checks](../decisions/acceptance-checks-and-build-plan.md). Collected 2026-10-28 07:50 UTC with `scripts/m0-collect.sh` on node `ludus`. Evidence format: source, destination/port, mode, expected, actual, enforcement point.

**Host is a Ludus range host** (Ludus-managed bridges, NAT and WireGuard on the node). Lab networking must not collide with Ludus.

## Facts

| Item | Value | Evidence |
| --- | --- | --- |
| PVE version | proxmox-ve 9.2.0, pve-manager 9.2.2, kernel 7.0.2-6-pve | `pveversion -v` |
| Firewall backend | `pve-firewall` 6.0.4 + `proxmox-firewall` 1.2.3 (nftables) installed; **status disabled/running**; no cluster/host `.fw`; iptables policies all ACCEPT; no nft ruleset | `pve-firewall status`, `iptables -S` |
| `/etc/network/interfaces` | `vmbr0` 192.168.0.161/24 gw 192.168.0.1 on `enp8s0` (home LAN, not VLAN-aware). Ludus blocks: `vmbr1000` NAT 192.0.2.254/24 (VLAN-aware 2-4094, MASQUERADE out `vmbr0`, ip_forward=1), `vmbr1001` Ludus user 1 (VLAN-aware 2-4094, route 10.1.0.0/16 via 192.0.2.101). Spare NICs `eno1`, `ens4` DOWN | `/etc/network/interfaces` |
| Bridges / VLANs | Only VLAN 1 present on ports; Ludus bridges allow 2-4094. Free VLAN IDs: undetermined (Ludus allocates per range). Lab should use a **new dedicated bridge**, not `vmbr1000`/`vmbr1001` | `bridge vlan show` |
| Other interfaces | `wg0` 198.51.100.1/24 (Ludus WireGuard) | `ip -br addr` |
| Router / gateway | Home router 192.168.0.1 stays the upstream gateway (model/VLAN/RA not needed for lab). Lab router/firewall will be a **virtualized OPNsense or pfSense VM** in M2; product choice is a separate research ticket. Note: stopped VM 114 `pfsense01` already exists (Ludus-side, not lab) | `ip route`, Adam 2026-10-28 |
| IPv6 state | Host: link-local only, no global address, no IPv6 default route, `disable_ipv6=0`, `ipv6.forwarding=0`. Upstream RA/DHCPv6 on home router: unconfirmed, A2 probes IPv6 regardless | `ip -6 route`, `sysctl` |
| Management path | `vmbr0` 192.168.0.161 (Proxmox UI/SSH on home LAN). Recovery console: **physical access** to the host (no IPMI), per Adam 2026-10-28 | `ip -br addr` |
| CPU | 2x Xeon E5-2683 v4, 32 cores / 64 threads, VT-x, 2 NUMA nodes | `lscpu` |
| RAM | 125 GiB total, 122 GiB available, 976 MiB swap | `free -h` |
| Storage | `local` (dir, NVMe 238 GB root): **89.5% used, 13 GB free, do not use**. `iso-files` (dir, SATA SSD CT2000MX500, 1.8 TB): 1.6 TB free, content incl. images/backup | `pvesm status`, `lsblk` |
| Backup storage | No PBS or NFS. `iso-files` allows `backup` but is a second disk **in the same host** . **Risk accepted explicitly by Adam, 2026-10-28 (#9):** no separate backup storage; snapshots at best on `iso-files`; host loss = evidence loss | `/etc/pve/storage.cfg` |
| Existing guests | 20 VMs, all stopped (templates 100-109, 111-113; VMs 110, 114-119). Largest: `win11` 20 vCPU/40 GB, `android` 20/39 GB, `jump01` 8/17.5 GB | `pvesh get /cluster/resources` |
| Time/DNS | NTP synced, Europe/London; resolvers 192.168.0.1, 8.8.8.8, 1.1.1.1 | `timedatectl`, `resolv.conf` |
| Image approach | **Cloud image + first boot, or a Proxmox template** (no Packer), per Adam 2026-10-28. Final per-VM choice at M2-M4 | #8 |
| Image pins + checksums | Record version + SHA256 when each image is selected (firewall M2, Elastic M3, target M4, attacker M5) | |
| Authority to change shared networking | **Adam has authority**; Ludus tolerates additional bridges alongside its own (Adam 2026-10-28). Keep lab bridges outside Ludus-marked blocks | Adam 2026-10-28 |

## A0 sizing check

Placeholders from #9: ~9-10 vCPU / 18 GB RAM, Elastic 100 GB data disk.

| Resource | Needed | Allocatable | Pass |
| --- | --- | --- | --- |
| vCPU | 9-10 | 64 threads (existing guests stopped) | yes |
| RAM | 18 GB | ~122 GB free | yes |
| Disk (data) | 100 GB + snapshots | 1.6 TB on `iso-files` (**not** `local`, 13 GB free) | yes, if placed on `iso-files` |

Caveat: if Ludus guests run concurrently (e.g. win11 + android = 40 vCPU / 80 GB), headroom shrinks. Recheck then.

## Findings to carry forward

- `local` root at 95%: free space or keep all lab disks on `iso-files`.
- Host firewall disabled and iptables ACCEPT: M2 isolation must be enforced by the firewall VM and dedicated bridges, not host rules. Ludus iptables NAT hooks mean host rules are Ludus-owned.
- IPv6: no global v6 on host; A2 still requires IPv6 probes.
- Ludus rewrites its marked blocks in `/etc/network/interfaces`; add lab bridges outside those markers.

## A0 result

- [x] All facts recorded (image pins deferred to the milestone that selects each image; IPv6 RA covered by A2 probes)
- [x] Sizing >= placeholders
- [x] Change authority confirmed
- M1 does not start until all three checked.
