# M2 firewall VM and lab networks runbook

Issue #21. Exit = check A2 in [acceptance checks](../decisions/acceptance-checks-and-build-plan.md). **A2 is a hard gate before any vulnerable target powers on.** Policy: [ADR 0001](../adr/0001-isolate-the-attack-lab-behind-a-firewall-vm.md) and the #6 flow contract.

**Status: A2 evidence collected 2026-10-28 (see below); pending Adam's review before #21 closes.** The OPNsense API field names and the Tofu VM arguments held up on 26.7 with the fixes recorded in git history; first-boot OPNsense setup is still manual (Known gaps).

## Decisions (defaults accepted 2026-10-28)

| Gap | Choice |
| --- | --- |
| Firewall product | OPNsense CE 26.1.11 ([research](../research/opnsense-vs-pfsense.md)); ISO sha256 to be recorded in `network/plan.json` at download |
| VPN | WireGuard on the firewall, `10.77.9.0/24`, handshake on UDP 51820 from the workstation only |
| Ranges | `10.77.0.0/16`: attacker `.1.0/24`, elastic `.3.0/24`, one `/24` and one bridge per target (`.11`, `.12`), VPN `.9`. Checked against Ludus (`10.1/16`, `192.0.2/24`, `198.51.100/24`) and home `192.168.0.0/24` |
| Bridges | `vmbr2001` attacker, `vmbr2003` elastic, `vmbr2011`/`vmbr2012` targets. No host IP, no physical port. Per-target bridges because a shared L2 would let targets talk without crossing the firewall |
| IPv6 | Disabled: block+log on every interface, and A2 checks no global address or default route on each vantage |
| Maintenance | Controller-timed (`labmode.py tick` from a timer), max 120 min, reason required, initiators attacker/t1/t2, FQDN alias of Debian/Ubuntu/Docker sources, tcp 80/443. Elastic gets no egress |
| Home placeholders | `hosts.workstation` `192.168.0.223` and `firewall.wan_ip` `192.168.0.82` are guesses: set real values in `network/plan.json` first |

## Layout

- `network/plan.json`: single source (zones, bridges, hosts, services, targets, literal A2 probe table).
- `scripts/netpolicy.py`: flows -> rendered ruleset; `lint` checks it against the probe table; `matrix`, `bridges`, `check`.
- `scripts/opnsense.py`, `scripts/labmode.py`: push the ruleset (savepoint -> apply -> confirm, so a change that cuts the controller off reverts) and switch exercise/maintenance/selected target. State and audit log in `.state/labmode.{json,log}`.
- `scripts/bootstrap-bridges.sh`: root, node shell. Writes `/etc/network/interfaces.d/opaleye-lab.conf` (outside the Ludus blocks) and `ifup`s only new bridges.
- `tofu/stacks/firewall`: firewall VM (only guest with the home bridge, WAN = first NIC) and optional throwaway probe guests.
- `scripts/a2-verify.sh`: prints the A2 evidence table.
- Tests: `tests/test_netpolicy.py`, `tests/test_labmode.py` (against `tests/fake_opnsense.py`), guards in `tests/static-checks.sh`.

## Extra checks (run after A2)

- `PVE_NODE=ludus python3 scripts/nicaudit.py`: only VM 2000 touches the home bridge; every other guest is on exactly one lab bridge (`tests/test_nicaudit.py` covers the rules).

## Run

1. Fix the two home placeholders in `network/plan.json`; `python3 scripts/netpolicy.py check`.
2. Node, as root: `scripts/bootstrap-bridges.sh`, then `HOME_BRIDGE=vmbr0 BRIDGES="vmbr2001 vmbr2003 vmbr2011 vmbr2012" scripts/bootstrap-proxmox.sh` (home bridge ACL goes to the firewall token only).
3. Upload the OPNsense ISO to `iso-files`; `export TF_VAR_node_name=ludus TF_VAR_installer_iso_file_id=iso-files:iso/<file>`; `scripts/lab.sh apply firewall`.
4. **Manual first boot (gap, see below):** install OPNsense, assign vtnet0..4 per `tofu output nic_zones` (wan, lan, opt1, opt2, opt3), set interface addresses (`.1` of each zone), create the WireGuard instance as `opt4`, enable Unbound DNS and NTP on the lab interfaces, remote syslog to Elastic (M3), disable hardware offload, create an API user, install `os-qemu-guest-agent`. Disable IPv6 on all interfaces.
5. `export OPNSENSE_URL=https://<fw> OPNSENSE_API_KEY=... OPNSENSE_API_SECRET=... OPNSENSE_INSECURE=true`; `python3 scripts/labmode.py exercise t1`.
6. Probe guests: as root on the node, `scripts/make-probe-template.sh` (needs the Debian cloud `.img` on `iso-files`; builds template 2100 in pool lab-firewall). Then `TF_VAR_probe_vms=true TF_VAR_probe_ssh_public_key="$(cat ~/.ssh/id_ed25519.pub)" scripts/lab.sh apply firewall`. Then `scripts/a2-verify.sh exercise t1 lab`, `... vpn` (VPN up), `... home` (VPN down), `a2-verify.sh failclosed`.
7. Maintenance: `labmode.py maintenance --minutes 30 --reason "..."`; run `labmode.py tick` every minute from a timer; after return, `REVERIFY=1 scripts/a2-verify.sh exercise t1 lab` clears the flag. `labmode.py select` refuses until then.
8. Record the tables below; destroy probe guests; only then does M3 start.

## Known gaps

- **Manual first boot** (#31): interfaces, WireGuard, Unbound/NTP, API user, **Interfaces > WAN > Block private networks off** (it drops the workstation before the handshake allow), anti-lockout off, no default allow-any rules, hardware offload off, IPv6 off. Ping to the firewall is denied by design (only TCP 443 from the VPN); test with `curl -k https://10.77.9.1/`.
- **No auto-revert on rule pushes** (#32): OPNsense core 26.7 has no `savepoint`/`cancelRollback` (`os-firewall` plugin only) and `apply` takes no revision. `labmode.py` refuses unless `OPNSENSE_NO_SAVEPOINT=true`; a bad push can then only be undone from the VM console (`pfctl -d`, or a config backup). Take **System > Configuration > Backups** before the first push.
- IPv6 is checked from the lab vantages only (no global address, no default route, no reply to an all-routers ping); nothing probes IPv6 from the VPN or home side.
- The `workstation -> fw:51820` allow row is SKIP (`WG_IFACE` unset); the handshake is evidenced by packet capture.
- `attacker -> fw` is probed on 443/22 (p46, p47) in the `lab` phase only; the other phases' tables predate those rows.
- `denylog` ignores rows already in the log when the verifier starts (digest baseline), so a stale block from an earlier run cannot satisfy a row; within one run, an identical earlier block for the same src/dst/port still would.
- `labmode.py tick` needs a timer: `scripts/install-tick-timer.sh` installs a per-minute user crontab line (WSL: `sudo service cron start`, VPN up); `--remove` uninstalls. Not yet exercised live.
- Docker-published ports and per-target NICs need the M4 target; probe a published non-exercise port from outside the target before it powers on.
- `a2-verify.sh` reports `PASS-WITH-SKIPS` when rows were skipped; a dead probe vantage yields `ERROR`, never a green deny.

## API user scope

`opaleye-api` is not an administrator and has only the firewall rule ("Firewall: Rules [new]", the `firewall/filter/*` API), firewall alias, and firewall log privileges (set in System > Access > Users; part of the manual first boot, #31). Verified 2026-10-28: `labmode.py` select, maintenance, exercise and `denylog` work with it, and `GET /api/core/firmware/status` and `/api/core/system/status` return 403. If a push returns 403, a privilege is missing; do not widen to Administrators.

## How to rerun A2

All from the workstation, tunnel up, `OPNSENSE_URL=https://10.77.9.1`, `OPNSENSE_NO_SAVEPOINT=true`; probe guests created with `TF_VAR_probe_vms=true` (clone of template 2100). SSH host keys change on every recreate: `ssh-keygen -R <ip>` first.

- `exercise lab`: `labmode.py select t1; a2-verify.sh exercise t1 lab`
- `vpn`: Windows tunnel `AllowedIPs = 10.77.0.0/16, 192.168.0.161/32, 1.1.1.1/32` (restore afterwards), then `a2-verify.sh exercise t1 vpn`
- `home`: `sudo ip addr add 192.168.0.50/32 dev <if>`, same for `203.0.113.55/32`, and `sudo ip route add <10.77.1.10|10.77.3.10|10.77.11.10>/32 via 192.168.0.82`, then `a2-verify.sh exercise t1 home`; remove them afterwards
- `failclosed`: `PVE_NODE=ludus a2-verify.sh failclosed`
- maintenance: `labmode.py maintenance --minutes 30 --reason ...`, `a2-verify.sh maintenance none lab`, then `labmode.py exercise`, `REVERIFY=1 a2-verify.sh exercise none lab`, `labmode.py select t1`
- NIC audit: `PVE_NODE=ludus python3 scripts/nicaudit.py`
- Update-source rows resolve the name on the probe guest through the firewall DNS, because the firewall alias resolves it its own way.

## A2 evidence

Collected 2026-10-28 on node `ludus`, OPNsense 26.7 (VM 2000), probe guests cloned from template 2100, `1.1.1.1:443` as the Internet canary. Packet filter enabled, anti-lockout disabled (confirmed by Adam). Rules pushed with `labmode.py` (`OPNSENSE_NO_SAVEPOINT=true`). Tables below are the verifier output files from the final run, unedited. Earlier runs of the same phases failed and led to fixes (filter disabled, log client bugs, ssh consuming the matrix, selected-target verdicts, update-source resolution); only the passing runs are recorded.

### Exercise mode, t1 selected, phase `lab`

phase=lab mode=exercise selected=t1 rows=36 skipped=0 PASS

| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| attacker | t1:80 | exercise | allow | allow | firewall:lan |
| attacker | t1:22 | exercise | deny | deny | firewall:lan (deny logged: yes) |
| attacker | t2:80 | exercise | deny | deny | firewall:lan (deny logged: yes) |
| t1 | t2:80 | exercise | deny | deny | firewall:opt2 (deny logged: yes) |
| t2 | t1:80 | exercise | deny | deny | firewall:opt3 (deny logged: yes) |
| t1 | proxmox:8006 | exercise | deny | deny | firewall:opt2 (deny logged: yes) |
| t1 | proxmox:22 | exercise | deny | deny | firewall:opt2 (deny logged: yes) |
| t1 | home_router:80 | exercise | deny | deny | firewall:opt2 (deny logged: yes) |
| t1 | internet:443 | exercise | deny | deny | firewall:opt2 (deny logged: yes) |
| t1 | update_source:443 | exercise | deny | deny | firewall:opt2 (deny logged: yes) |
| attacker | update_source:443 | exercise | deny | deny | firewall:lan (deny logged: yes) |
| elastic | update_source:443 | exercise | deny | deny | firewall:opt1 (deny logged: yes) |
| attacker | proxmox:8006 | exercise | deny | deny | firewall:lan (deny logged: yes) |
| attacker | home_router:80 | exercise | deny | deny | firewall:lan (deny logged: yes) |
| attacker | internet:443 | exercise | deny | deny | firewall:lan (deny logged: yes) |
| attacker | elastic:5601 | exercise | deny | deny | firewall:lan (deny logged: yes) |
| attacker | elastic:9200 | exercise | allow | allow | firewall:lan |
| t1 | elastic:9200 | exercise | allow | allow | firewall:opt2 |
| t1 | elastic:8220 | exercise | allow | allow | firewall:opt2 |
| t1 | elastic:5601 | exercise | deny | deny | firewall:opt2 (deny logged: yes) |
| t1 | elastic:22 | exercise | deny | deny | firewall:opt2 (deny logged: yes) |
| t1 | fw:53 | exercise | allow | allow | firewall:opt2 |
| t1 | fw:123 | exercise | allow | allow | firewall:opt2 |
| t1 | fw:443 | exercise | deny | deny | firewall:opt2 (deny logged: yes) |
| t1 | fw:22 | exercise | deny | deny | firewall:opt2 (deny logged: yes) |
| elastic | internet:443 | exercise | deny | deny | firewall:opt1 (deny logged: yes) |
| elastic | t1:80 | exercise | deny | deny | firewall:opt1 (deny logged: yes) |
| elastic | attacker:22 | exercise | deny | deny | firewall:opt1 (deny logged: yes) |
| elastic | proxmox:8006 | exercise | deny | deny | firewall:opt1 (deny logged: yes) |
| elastic | fw:123 | exercise | allow | allow | firewall:opt1 |
| attacker | fw:443 | exercise | deny | deny | firewall:lan (deny logged: yes) |
| attacker | fw:22 | exercise | deny | deny | firewall:lan (deny logged: yes) |
| attacker | fw:0 | exercise | deny | deny | firewall:lan |
| elastic | fw:0 | exercise | deny | deny | firewall:opt1 |
| t1 | fw:0 | exercise | deny | deny | firewall:opt2 |
| t2 | fw:0 | exercise | deny | deny | firewall:opt3 |

### Exercise mode, phase `vpn`

Windows tunnel `AllowedIPs = 10.77.0.0/16, 192.168.0.161/32, 1.1.1.1/32` so the proxmox and internet probes enter the tunnel (the verifier reports ERROR otherwise).

phase=vpn mode=exercise selected=t1 rows=8 skipped=0 PASS

| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| operator | attacker:22 | exercise | allow | allow | firewall:opt4 |
| operator | elastic:5601 | exercise | allow | allow | firewall:opt4 |
| operator | t1:22 | exercise | allow | allow | firewall:opt4 |
| operator | t1:80 | exercise | deny | deny | firewall:opt4 (deny logged: yes) |
| operator | fw:443 | exercise | allow | allow | firewall:opt4 |
| operator | proxmox:8006 | exercise | deny | deny | firewall:opt4 (deny logged: yes) |
| operator | internet:443 | exercise | deny | deny | firewall:opt4 (deny logged: yes) |
| operator | elastic:22 | exercise | allow | allow | firewall:opt4 |

VPN handshake with the filter on, by capture at the firewall: `192.168.0.223 -> 192.168.0.82:51820` initiation, response and keepalives, passed by `pass in quick on vtnet0 ... from 192.168.0.223 to (self) port 51820`.

### Exercise mode, phase `home`

Source addresses on the workstation: `192.168.0.223`, plus aliases `192.168.0.50` (`home_other`) and `203.0.113.55` (`public`). Host routes `10.77.1.10/32`, `10.77.3.10/32`, `10.77.11.10/32` via `192.168.0.82` beat the tunnel's `/16`, so the probes enter through the firewall WAN; the tunnel stays up for the log check. The `home_other` UDP row has no reply to observe, so its verdict is the logged block.

phase=home mode=exercise selected=t1 rows=6 skipped=1 PASS-WITH-SKIPS

| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| workstation | fw:51820 | exercise | allow | SKIP | firewall:wan |
| workstation | fw:443 | exercise | deny | deny | firewall:wan (deny logged: yes) |
| workstation | t1:80 | exercise | deny | deny | firewall:wan (deny logged: yes) |
| workstation | attacker:22 | exercise | deny | deny | firewall:wan (deny logged: yes) |
| workstation | elastic:5601 | exercise | deny | deny | firewall:wan (deny logged: yes) |
| home_other | fw:51820 | exercise | deny | deny | firewall:wan (deny logged: yes) |
| public | t1:80 | exercise | deny | deny | firewall:wan (deny logged: yes) |

### Firewall down (`a2-verify.sh failclosed`)

Each normally-allowed flow was armed on its source guest, then VM 2000 was stopped for 60 s and restarted; results read back from the guests. Only a connect or an RST counts as a path; a timeout or "No route to host" counts as none. Run before the canary and IPv6 probe changes, which do not touch this phase.

phase=failclosed rows=4 PASS

| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| attacker | t1:80 | firewall down | deny | deny | no forwarding path (VM stopped) |
| attacker | elastic:9200 | firewall down | deny | deny | no forwarding path (VM stopped) |
| t1 | elastic:9200 | firewall down | deny | deny | no forwarding path (VM stopped) |
| t1 | elastic:8220 | firewall down | deny | deny | no forwarding path (VM stopped) |

### Maintenance mode

`labmode.py maintenance --minutes 30 --reason "A2 rerun"`, then `a2-verify.sh maintenance none lab`. No target selected, so `attacker -> t1:80` is denied. The update-source rows resolve `deb.debian.org` on the probe guest through the firewall DNS and make real connections out.

phase=lab mode=maintenance selected=none rows=34 skipped=0 PASS

| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| attacker | t1:80 | maintenance | deny | deny | firewall:lan (deny logged: yes) |
| attacker | t1:22 | maintenance | deny | deny | firewall:lan (deny logged: yes) |
| attacker | t2:80 | maintenance | deny | deny | firewall:lan (deny logged: yes) |
| t1 | t2:80 | maintenance | deny | deny | firewall:opt2 (deny logged: yes) |
| t2 | t1:80 | maintenance | deny | deny | firewall:opt3 (deny logged: yes) |
| t1 | proxmox:8006 | maintenance | deny | deny | firewall:opt2 (deny logged: yes) |
| t1 | proxmox:22 | maintenance | deny | deny | firewall:opt2 (deny logged: yes) |
| t1 | home_router:80 | maintenance | deny | deny | firewall:opt2 (deny logged: yes) |
| t1 | internet:443 | maintenance | deny | deny | firewall:opt2 (deny logged: yes) |
| t1 | update_source:443 | maintenance | allow | allow | firewall:opt2 |
| attacker | update_source:443 | maintenance | allow | allow | firewall:lan |
| elastic | update_source:443 | maintenance | deny | deny | firewall:opt1 (deny logged: yes) |
| attacker | proxmox:8006 | maintenance | deny | deny | firewall:lan (deny logged: yes) |
| attacker | home_router:80 | maintenance | deny | deny | firewall:lan (deny logged: yes) |
| attacker | internet:443 | maintenance | deny | deny | firewall:lan (deny logged: yes) |
| attacker | elastic:5601 | maintenance | deny | deny | firewall:lan (deny logged: yes) |
| attacker | elastic:9200 | maintenance | allow | allow | firewall:lan |
| t1 | elastic:9200 | maintenance | allow | allow | firewall:opt2 |
| t1 | elastic:8220 | maintenance | allow | allow | firewall:opt2 |
| t1 | elastic:5601 | maintenance | deny | deny | firewall:opt2 (deny logged: yes) |
| t1 | elastic:22 | maintenance | deny | deny | firewall:opt2 (deny logged: yes) |
| t1 | fw:53 | maintenance | allow | allow | firewall:opt2 |
| t1 | fw:123 | maintenance | allow | allow | firewall:opt2 |
| t1 | fw:443 | maintenance | deny | deny | firewall:opt2 (deny logged: yes) |
| t1 | fw:22 | maintenance | deny | deny | firewall:opt2 (deny logged: yes) |
| elastic | internet:443 | maintenance | deny | deny | firewall:opt1 (deny logged: yes) |
| elastic | t1:80 | maintenance | deny | deny | firewall:opt1 (deny logged: yes) |
| elastic | attacker:22 | maintenance | deny | deny | firewall:opt1 (deny logged: yes) |
| elastic | proxmox:8006 | maintenance | deny | deny | firewall:opt1 (deny logged: yes) |
| elastic | fw:123 | maintenance | allow | allow | firewall:opt1 |
| attacker | fw:0 | maintenance | deny | deny | firewall:lan |
| elastic | fw:0 | maintenance | deny | deny | firewall:opt1 |
| t1 | fw:0 | maintenance | deny | deny | firewall:opt2 |
| t2 | fw:0 | maintenance | deny | deny | firewall:opt3 |

### Back to exercise mode, re-verified

`labmode.py exercise`; `labmode.py select t1` is refused until `REVERIFY=1 a2-verify.sh exercise none lab` passes, then succeeds.

phase=lab mode=exercise selected=none rows=34 skipped=0 PASS

| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| attacker | t1:80 | exercise | deny | deny | firewall:lan (deny logged: yes) |
| attacker | t1:22 | exercise | deny | deny | firewall:lan (deny logged: yes) |
| attacker | t2:80 | exercise | deny | deny | firewall:lan (deny logged: yes) |
| t1 | t2:80 | exercise | deny | deny | firewall:opt2 (deny logged: yes) |
| t2 | t1:80 | exercise | deny | deny | firewall:opt3 (deny logged: yes) |
| t1 | proxmox:8006 | exercise | deny | deny | firewall:opt2 (deny logged: yes) |
| t1 | proxmox:22 | exercise | deny | deny | firewall:opt2 (deny logged: yes) |
| t1 | home_router:80 | exercise | deny | deny | firewall:opt2 (deny logged: yes) |
| t1 | internet:443 | exercise | deny | deny | firewall:opt2 (deny logged: yes) |
| t1 | update_source:443 | exercise | deny | deny | firewall:opt2 (deny logged: yes) |
| attacker | update_source:443 | exercise | deny | deny | firewall:lan (deny logged: yes) |
| elastic | update_source:443 | exercise | deny | deny | firewall:opt1 (deny logged: yes) |
| attacker | proxmox:8006 | exercise | deny | deny | firewall:lan (deny logged: yes) |
| attacker | home_router:80 | exercise | deny | deny | firewall:lan (deny logged: yes) |
| attacker | internet:443 | exercise | deny | deny | firewall:lan (deny logged: yes) |
| attacker | elastic:5601 | exercise | deny | deny | firewall:lan (deny logged: yes) |
| attacker | elastic:9200 | exercise | allow | allow | firewall:lan |
| t1 | elastic:9200 | exercise | allow | allow | firewall:opt2 |
| t1 | elastic:8220 | exercise | allow | allow | firewall:opt2 |
| t1 | elastic:5601 | exercise | deny | deny | firewall:opt2 (deny logged: yes) |
| t1 | elastic:22 | exercise | deny | deny | firewall:opt2 (deny logged: yes) |
| t1 | fw:53 | exercise | allow | allow | firewall:opt2 |
| t1 | fw:123 | exercise | allow | allow | firewall:opt2 |
| t1 | fw:443 | exercise | deny | deny | firewall:opt2 (deny logged: yes) |
| t1 | fw:22 | exercise | deny | deny | firewall:opt2 (deny logged: yes) |
| elastic | internet:443 | exercise | deny | deny | firewall:opt1 (deny logged: yes) |
| elastic | t1:80 | exercise | deny | deny | firewall:opt1 (deny logged: yes) |
| elastic | attacker:22 | exercise | deny | deny | firewall:opt1 (deny logged: yes) |
| elastic | proxmox:8006 | exercise | deny | deny | firewall:opt1 (deny logged: yes) |
| elastic | fw:123 | exercise | allow | allow | firewall:opt1 |
| attacker | fw:0 | exercise | deny | deny | firewall:lan |
| elastic | fw:0 | exercise | deny | deny | firewall:opt1 |
| t1 | fw:0 | exercise | deny | deny | firewall:opt2 |
| t2 | fw:0 | exercise | deny | deny | firewall:opt3 |

### Other checks

- **NIC audit** (`nicaudit.py`): VM 2000 on `vmbr0, vmbr2001, vmbr2003, vmbr2011, vmbr2012`; template VM 2100 on `vmbr2001`. `ok: only the firewall VM touches the home bridge; every other guest is on one lab bridge`.
- **Rule push idempotence:** `labmode.py exercise t1` run twice reports `no changes` both times.
- **Maintenance expiry:** `maintenance --minutes 1`; `tick` before expiry does nothing; `tick` after 70 s prints `maintenance expired: back to exercise mode`, mode `exercise`, `reverify_required: true`. A probe run with the guests gone reported ERROR on every row, never a pass.

### Not covered

See Known gaps. Not evidenced: IPv6 from the VPN and home side, `workstation -> fw:51820` allow (by capture only), Docker-published ports and per-target NICs (M4).
