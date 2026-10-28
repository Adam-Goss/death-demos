# M2 firewall VM and lab networks runbook

Issue #21. Exit = check A2 in [acceptance checks](../decisions/acceptance-checks-and-build-plan.md). **A2 is a hard gate before any vulnerable target powers on.** Policy: [ADR 0001](../adr/0001-isolate-the-attack-lab-behind-a-firewall-vm.md) and the #6 flow contract.

**Status: code and offline tests done; A2 evidence not yet collected.** Nothing here has run against the real node or a real OPNsense. The OPNsense API field names and endpoints, and the Tofu VM arguments, are written from docs and unverified.

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

- **First-boot OPNsense setting:** untick **Interfaces > WAN > Block private networks**; it drops the workstation (`192.168.0.0/16`) before the handshake allow rule. Ping to the firewall is denied by design (only TCP 443 is allowed); test with `curl -k https://10.77.9.1/`.

- **No savepoint on OPNsense core 26.7.** `firewall/filter/savepoint` and `cancelRollback` belong to the `os-firewall` plugin (404 on core). Core `apply` takes no revision and nothing auto-reverts. `labmode.py` refuses unless `OPNSENSE_NO_SAVEPOINT=true`; a bad push can then only be undone from the Proxmox VM console (`pfctl -d`, or restore a config backup). Take a **System > Configuration > Backups** download before the first push.

- **Step 4 is hand configuration**, against "re-runnable code only". The OPNsense interface-assignment and WireGuard APIs were incomplete on 26.1 ([research](../research/opnsense-vs-pfsense.md)); a `config.xml` seed would replace it but cannot be written blind. Decide after seeing the real VM.
- Rule diffing compares only the fields we send; if live OPNsense returns them in another shape the controller will re-`setRule` every run (harmless, but not a no-op).
- `home_other` and `public` probe rows are SKIP: they cannot be sourced from the workstation. Covered by the rules lint and per-interface default-deny; there is no port forward or public inbound path.
- Docker-published ports: probe a target-published port from outside the target (the `attacker -> target` rows) once M4 exists; A2 here uses probe guests.
- The WireGuard handshake row needs `WG_IFACE`; otherwise SKIP.

- **Delete OPNsense default rules** (default LAN allow-any, anti-lockout) in step 4, or they bypass the default-deny set; add an attacker -> firewall probe once done (only t1 -> firewall is probed).
- `TEST-NET` addresses stand in for "Internet" in deny rows, so they prove policy, not a live egress hole; the maintenance rows use a real update-source IP. Add a routable canary (e.g. 1.1.1.1) at A2 time.
- IPv6 rows check only that lab vantages have no global address or default route; no v6 packet is sent, and nothing probes v6 from home/VPN.
- `denylog` matches any past block row for src/dst/port (no timestamp), and `tick` needs a timer you install on the workstation; neither is enforced by code.
- **VPN phase needs the tunnel to carry the probe destinations.** Temporarily set the Windows tunnel `AllowedIPs = 10.77.0.0/16, 192.168.0.161/32, 203.0.113.10/32` for the `vpn` phase (restore afterwards), or the verifier reports `ERROR` for `proxmox` and `internet` rows.
- `a2-verify.sh` reports `PASS-WITH-SKIPS` when rows were skipped; a dead probe vantage yields `ERROR`, never a green deny.

## A2 evidence

Collected 2026-10-28 on node `ludus`, OPNsense 26.7 (VM 2000), probe guests cloned from template 2100. Packet filter confirmed enabled; rules pushed with `labmode.py exercise t1` (`OPNSENSE_NO_SAVEPOINT=true`).

### Exercise mode, selected target t1, phase `lab` (`a2-verify.sh exercise t1 lab`): PASS, 34/34

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
| attacker | fw:0 (IPv6) | exercise | deny | deny | firewall:lan |
| elastic | fw:0 (IPv6) | exercise | deny | deny | firewall:opt1 |
| t1 | fw:0 (IPv6) | exercise | deny | deny | firewall:opt2 |
| t2 | fw:0 (IPv6) | exercise | deny | deny | firewall:opt3 |

Earlier runs of the same phase failed (filter was disabled; log client bugs); only this passing run is recorded.

### Exercise mode, phase `vpn` (`a2-verify.sh exercise t1 vpn`): PASS, 8/8

Run with the Windows tunnel `AllowedIPs = 10.77.0.0/16, 192.168.0.161/32, 203.0.113.10/32` so the proxmox and internet probes enter the tunnel (the verifier reports ERROR otherwise). Filter enabled.

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

VPN handshake with the filter on confirmed by capture: `192.168.0.223 -> 192.168.0.82:51820` initiation, response and keepalives, passed by `pass in quick on vtnet0 ... from 192.168.0.223 to (self) port 51820`.

### Exercise mode, phase `home` (`a2-verify.sh exercise t1 home`): PASS-WITH-SKIPS, 4 run, 3 skipped

Source is the workstation (192.168.0.223) entering through the firewall WAN: host routes `10.77.1.10/32`, `10.77.3.10/32`, `10.77.11.10/32` via `192.168.0.82` (they beat the tunnel's `/16`); tunnel up so the log check can reach the API. Skipped: `workstation -> fw:51820` (WG_IFACE unset; handshake shown by capture above), `home_other` and `public` (sources not available from this host; same interface default-deny, no port forwards).

| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| workstation | fw:443 | exercise | deny | deny | firewall:wan (deny logged: yes) |
| workstation | t1:80 | exercise | deny | deny | firewall:wan (deny logged: yes) |
| workstation | attacker:22 | exercise | deny | deny | firewall:wan (deny logged: yes) |
| workstation | elastic:5601 | exercise | deny | deny | firewall:wan (deny logged: yes) |

### Firewall down (`a2-verify.sh failclosed`): PASS, 4/4

Each flow the firewall normally allows was armed on its source guest, then VM 2000 was stopped for 60 s and restarted; results read back from the guests. Only a connect or an RST counts as a path; a timeout or "No route to host" counts as none. (An earlier run misclassified a fast "No route to host" as allow; the classifier was fixed and the run repeated.) After restart the tunnel, rules and probe SSH came back without changes.

| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| attacker | t1:80 | firewall down | deny | deny | no forwarding path (VM stopped) |
| attacker | elastic:9200 | firewall down | deny | deny | no forwarding path (VM stopped) |
| t1 | elastic:9200 | firewall down | deny | deny | no forwarding path (VM stopped) |
| t1 | elastic:8220 | firewall down | deny | deny | no forwarding path (VM stopped) |

### Still to record

maintenance mode and the post-maintenance exercise re-run, then remove the OPNsense anti-lockout rule and rerun.
