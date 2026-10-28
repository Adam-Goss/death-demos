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
6. Probe guests: `TF_VAR_probe_vms=true TF_VAR_probe_image_file_id=... TF_VAR_probe_ssh_public_key=... scripts/lab.sh apply firewall`. Then `scripts/a2-verify.sh exercise t1 lab`, `... vpn` (VPN up), `... home` (VPN down), `a2-verify.sh failclosed`.
7. Maintenance: `labmode.py maintenance --minutes 30 --reason "..."`; run `labmode.py tick` every minute from a timer; after return, `REVERIFY=1 scripts/a2-verify.sh exercise t1 lab` clears the flag. `labmode.py select` refuses until then.
8. Record the tables below; destroy probe guests; only then does M3 start.

## Known gaps

- **Step 4 is hand configuration**, against "re-runnable code only". The OPNsense interface-assignment and WireGuard APIs were incomplete on 26.1 ([research](../research/opnsense-vs-pfsense.md)); a `config.xml` seed would replace it but cannot be written blind. Decide after seeing the real VM.
- Rule diffing compares only the fields we send; if live OPNsense returns them in another shape the controller will re-`setRule` every run (harmless, but not a no-op).
- `home_other` and `public` probe rows are SKIP: they cannot be sourced from the workstation. Covered by the rules lint and per-interface default-deny; there is no port forward or public inbound path.
- Docker-published ports: probe a target-published port from outside the target (the `attacker -> target` rows) once M4 exists; A2 here uses probe guests.
- The WireGuard handshake row needs `WG_IFACE`; otherwise SKIP.

- **Delete OPNsense default rules** (default LAN allow-any, anti-lockout) in step 4, or they bypass the default-deny set; add an attacker -> firewall probe once done (only t1 -> firewall is probed).
- `TEST-NET` addresses stand in for "Internet" in deny rows, so they prove policy, not a live egress hole; the maintenance rows use a real update-source IP. Add a routable canary (e.g. 1.1.1.1) at A2 time.
- IPv6 rows check only that lab vantages have no global address or default route; no v6 packet is sent, and nothing probes v6 from home/VPN.
- `denylog` matches any past block row for src/dst/port (no timestamp), and `tick` needs a timer you install on the workstation; neither is enforced by code.
- `a2-verify.sh` reports `PASS-WITH-SKIPS` when rows were skipped; a dead probe vantage yields `ERROR`, never a green deny.

## A2 evidence

Not collected. Paste `a2-verify.sh` output for each mode/phase here (source, destination/port, mode, expected, actual, enforcement point), plus the fail-closed table and the post-maintenance exercise re-run.
