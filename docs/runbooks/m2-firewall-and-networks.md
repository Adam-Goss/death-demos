# M2 firewall VM and lab networks runbook

Issue #21. Exit = check A2 in [acceptance checks](../decisions/acceptance-checks-and-build-plan.md). **A2 is a hard gate before any vulnerable target powers on.** Policy: [ADR 0001](../adr/0001-isolate-the-attack-lab-behind-a-firewall-vm.md) and the #6 flow contract.

**Status: A2 evidence collected 2026-10-28 (see below); pending Adam's review before #21 closes.** The OPNsense API field names and the Tofu VM arguments held up on 26.7 with the fixes recorded in git history; first-boot OPNsense setup is generated as a config seed and was proven by a rebuild with all A2 phases passing (2026-10-29), except that first boot still needs one console step (Known gaps).

## Decisions (defaults accepted 2026-10-28)

| Gap | Choice |
| --- | --- |
| Firewall product | OPNsense CE 26.7 ([research](../research/opnsense-vs-pfsense.md)); ISO `OPNsense-26.7-dvd-amd64.iso`, sha256 `1efd5dc9fa12a1f93571183fe5e3823e22e332872de8417fafb5e4e4d48d5dcd` (pinned in `network/plan.json`; verify with `sha256sum` on the node before use) |
| VPN | WireGuard on the firewall, `10.77.9.0/24`, handshake on UDP 51820 from the workstation only |
| Ranges | `10.77.0.0/16`: attacker `.1.0/24`, elastic `.3.0/24`, one `/24` and one bridge per target (`.11`, `.12`), VPN `.9`. Checked against Ludus (`10.1/16`, `192.0.2/24`, `198.51.100/24`) and home `192.168.0.0/24` |
| Bridges | `vmbr2001` attacker, `vmbr2003` elastic, `vmbr2011`/`vmbr2012` targets. No host IP, no physical port. Per-target bridges because a shared L2 would let targets talk without crossing the firewall |
| IPv6 | Disabled: block+log on every interface, and A2 checks no global address or default route on each vantage |
| Maintenance | Controller-timed (`labmode.py tick` from a timer), max 120 min, reason required, initiators attacker/t1/t2, FQDN alias of Debian/Ubuntu/Docker sources, tcp 80/443. Elastic gets no egress |
| Home placeholders | `hosts.workstation` `192.168.0.223` and `firewall.wan_ip` `192.168.0.82` are guesses: set real values in `network/plan.json` first |

## Layout

- `network/plan.json`: single source (zones, bridges, hosts, services, targets, literal A2 probe table).
- `scripts/netpolicy.py`: flows -> rendered ruleset; `lint` checks it against the probe table; `matrix`, `bridges`, `check`.
- `scripts/opnsense.py`, `scripts/labmode.py`: push the ruleset (pending marker -> apply -> confirm marker; the dead-man job reverts a push the controller never confirmed) and switch exercise/maintenance/selected target. State and audit log in `.state/labmode.{json,log}`.
- `scripts/firewall/opaleye_deadman.py`, `scripts/install-deadman.sh`: dead-man switch that runs on the firewall (#32); tests in `tests/test_deadman.py`.
- `scripts/bootstrap-bridges.sh`: root, node shell. Writes `/etc/network/interfaces.d/opaleye-lab.conf` (outside the Ludus blocks) and `ifup`s only new bridges.
- `tofu/stacks/firewall`: firewall VM (only guest with the home bridge, WAN = first NIC) and optional throwaway probe guests.
- `scripts/opnsense_seed.py`, `network/opnsense-seed.xml`: first-boot `config.xml` seed (#31); tests in `tests/test_opnsense_seed.py`.
- `scripts/a2-verify.sh`: prints the A2 evidence table.
- Tests: `tests/test_netpolicy.py`, `tests/test_labmode.py` (against `tests/fake_opnsense.py`), guards in `tests/static-checks.sh`.

## Extra checks (run after A2)

- `PVE_NODE=ludus python3 scripts/nicaudit.py`: only VM 2000 touches the home bridge; every other guest is on exactly one lab bridge (`tests/test_nicaudit.py` covers the rules).

## Run

1. Fix the two home placeholders in `network/plan.json`; `python3 scripts/netpolicy.py check`.
2. Node, as root: `scripts/bootstrap-bridges.sh`, then `HOME_BRIDGE=vmbr0 BRIDGES="vmbr2001 vmbr2003 vmbr2011 vmbr2012" scripts/bootstrap-proxmox.sh` (home bridge ACL goes to the firewall token only).
3. Upload the OPNsense ISO to `iso-files`; `export TF_VAR_node_name=ludus TF_VAR_installer_iso_file_id=iso-files:iso/<file>`; `scripts/lab.sh apply firewall`.
4. **Seeded first boot (#31):** no console steps. `network/opnsense-seed.xml` is the secret-free `config.xml` generated from `network/plan.json` (`python3 scripts/opnsense_seed.py template > network/opnsense-seed.xml` after any plan change; `tests/static-checks.sh` fails if stale or if it holds secrets). It sets the bootstrap rules above (`labmode.py exercise` then completes the ruleset), interfaces vtnet0..4, addresses, the WireGuard instance and peer, Unbound and NTP on the lab interfaces, the `opaleye-api` user and key, WAN "Block private networks" off, anti-lockout off, offload off, IPv6 off. Secrets come from the operator environment (`secrets/env.sh` is gitignored): `export OPNSENSE_ROOT_PASSWORD OPNSENSE_API_KEY OPNSENSE_API_SECRET OPNSENSE_WG_PRIVATE_KEY OPNSENSE_WG_PUBLIC_KEY OPNSENSE_WG_PEER_PUBLIC_KEY; scripts/seed-build.sh` (wraps `opnsense_seed.py iso`; writes `.state/opnsense-seed.iso`, gitignored; needs openssl plus xorriso/genisoimage/mkisofs/hdiutil). Then **nano image path (hands-off):** `export OPNSENSE_NANO_URL=... OPNSENSE_NANO_SHA256=...` (from the release checksums file) before `scripts/seed-build.sh`, which also fetches, verifies and decompresses the nano image to `.state/opnsense-nano.raw`; then `TF_VAR_seeded=true scripts/lab.sh apply firewall` (both files are uploaded by Tofu; the token needs `Datastore.AllocateTemplate` on `iso-files`, no `Sys.*`); the nano image is pre-installed so neither the interactive installer nor the importer keypress is involved, and the seed ISO lands only in encrypted state. **Installer path:** upload the ISO to `iso-files` and `TF_VAR_attach_installer=false TF_VAR_seed_iso_file_id=iso-files:iso/opnsense-seed.iso scripts/lab.sh apply firewall`; the importer takes `conf/config.xml` from it. Still by hand: remote syslog to Elastic (M3) and `os-qemu-guest-agent`.
5. `export OPNSENSE_URL=https://<fw> OPNSENSE_API_KEY=... OPNSENSE_API_SECRET=... OPNSENSE_INSECURE=true`; `python3 scripts/labmode.py exercise t1`.
6. Probe guests: as root on the node, `scripts/make-probe-template.sh` (needs the Debian cloud `.img` on `iso-files`; builds template 2100 in pool lab-firewall). Then `TF_VAR_probe_vms=true TF_VAR_probe_ssh_public_key="$(cat ~/.ssh/id_ed25519.pub)" scripts/lab.sh apply firewall`. Then `scripts/a2-verify.sh exercise t1 lab`, `... vpn` (VPN up), `... home` (VPN down), `a2-verify.sh failclosed`.
7. Maintenance: `labmode.py maintenance --minutes 30 --reason "..."`; run `labmode.py tick` every minute from a timer; after return, `REVERIFY=1 scripts/a2-verify.sh exercise t1 lab` clears the flag. `labmode.py select` refuses until then.
8. Record the tables below; destroy probe guests; only then does M3 start.

## Known gaps

- **Config seed proven except the hands-off first boot** (#31): VM 2000 was destroyed and rebuilt from the nano image plus the seed on 2026-10-29 and all A2 phases passed on it (evidence at the end; fixes found along the way in "What the rebuild taught us"). The bootstrap rules match what `labmode.py` pushes, and its first sync adopted them in place (same rule UUIDs). **Still open:** the nano image does not import the seed by itself, so a rebuild needs one console step (`opnsense-importer`, pick the cdrom) plus re-adding the dead-man cron job; the rebuild with the final seed was applied by `cp` of the cdrom `config.xml`, not a clean importer run from a fresh checkout. Close #31 only after one of the hands-off options (UFS write into the nano image, a cloned pre-seeded template disk, or Proxmox `sendkey`) is built and one rebuild from a fresh checkout needs no console. Remote syslog to Elastic (M3) and `os-qemu-guest-agent` are still by hand. Still true after any rebuild: ping to the firewall is denied by design (only TCP 443 from the VPN); test with `curl -k https://10.77.9.1/`.
- **Dead-man switch** (#32, replaces the missing core savepoint; **implemented and tested offline, not yet proven on the firewall**): `scripts/install-deadman.sh <fw>` copies the job and a configd action; add a GUI cron job (System > Settings > Cron, every minute, "Opaleye dead-man switch"); then `labmode.py arm`. Each push sets alias `opaleye_pending` to a fresh token, applies, then sets `opaleye_confirmed` to the same token, which only works if the API is still reachable. The job keeps a copy of `config.xml` whenever the two match and, if they differ for 120 s, restores that copy and reloads the filter (worst case about 3 min). The restore also drops any other config change made since the last confirmed push. `labmode.py` refuses to push while unarmed or while a previous push is unconfirmed. Unverified on 26.7: the configd action file format and the `configctl filter reload` / `refresh_aliases` commands the job uses. Take **System > Configuration > Backups** before the first push anyway.
- IPv6 is probed per side: lab vantages (no global address, no default route, no reply to an all-routers ping); VPN (the firewall's own WireGuard peer config routes no IPv6: `labmode.py wgv4only`); home (the firewall's WAN MAC from the Proxmox API must not answer a `ping -6 ff02::1`, with other neighbours answering as the control, else ERROR). The home probe needs `PROXMOX_VE_*`/`PVE_NODE` in the environment and a working IPv6 multicast path on the workstation. Recorded in the `vpn` and `home` runs below.
- The `workstation -> fw:51820` allow row reads the firewall's own WireGuard status (`labmode.py wgpeer`: peer `workstation`, fresh handshake, endpoint `192.168.0.223`); needs the `VPN: WireGuard: Status` privilege on `opaleye-api`. Recorded in the `home` run below (7 rows, 0 skipped).
- `attacker -> fw` is probed on 443/22 (p46, p47) in the `lab` phase only; the other phases' tables predate those rows.
- `denylog` ignores rows already in the log when the verifier starts (digest baseline), so a stale block from an earlier run cannot satisfy a row; within one run, an identical earlier block for the same src/dst/port still would.
- `labmode.py tick` needs a timer: `scripts/install-tick-timer.sh` installs a per-minute user crontab line (WSL: `sudo service cron start`, VPN up); `--remove` uninstalls. Credentials come from `secrets/env.sh` (cron sees only that file). Proven live 2026-10-28 by cron: a 1-minute maintenance window closed itself (`maintenance expired: back to exercise mode`, `reverify_required: true`); the first attempt failed for a missing variable and left maintenance open until fixed (the tick retries each minute).
- Docker-published ports and per-target NICs need the M4 target; probe a published non-exercise port from outside the target before it powers on.
- `a2-verify.sh` reports `PASS-WITH-SKIPS` when rows were skipped; a dead probe vantage yields `ERROR`, never a green deny.

## API user scope

`opaleye-api` is not an administrator and has only the firewall rule ("Firewall: Rules [new]", the `firewall/filter/*` API), firewall alias, and firewall log privileges (created by the config seed, #31; privilege names unverified). Verified 2026-10-28: `labmode.py` select, maintenance, exercise and `denylog` work with it, and `GET /api/core/firmware/status` and `/api/core/system/status` return 403. If a push returns 403, a privilege is missing; do not widen to Administrators.

## How to rerun A2

All from the workstation, tunnel up, `OPNSENSE_URL=https://10.77.9.1`; probe guests created with `TF_VAR_probe_vms=true` (clone of template 2100). SSH host keys change on every recreate: `ssh-keygen -R <ip>` first.

- `exercise lab`: `labmode.py select t1; a2-verify.sh exercise t1 lab`
- `vpn`: Windows tunnel `AllowedIPs = 10.77.0.0/16, 192.168.0.161/32, 1.1.1.1/32` (restore afterwards), then `a2-verify.sh exercise t1 vpn`
- `home` (also `PVE_NODE=ludus` and the `PROXMOX_VE_*` variables, for the firewall WAN MAC): `sudo ip addr add 192.168.0.50/32 dev <if>`, same for `203.0.113.55/32`, and `sudo ip route add <10.77.1.10|10.77.3.10|10.77.11.10>/32 via 192.168.0.82`, then `a2-verify.sh exercise t1 home`; remove them afterwards
- `failclosed`: `PVE_NODE=ludus a2-verify.sh failclosed`
- maintenance: `labmode.py maintenance --minutes 30 --reason ...`, `a2-verify.sh maintenance none lab`, then `labmode.py exercise`, `REVERIFY=1 a2-verify.sh exercise none lab`, `labmode.py select t1`
- NIC audit: `PVE_NODE=ludus python3 scripts/nicaudit.py`
- Update-source rows resolve the name on the probe guest through the firewall DNS, because the firewall alias resolves it its own way.

## A2 evidence

Collected 2026-10-28 on node `ludus`, OPNsense 26.7 (VM 2000), probe guests cloned from template 2100, `1.1.1.1:443` as the Internet canary. Packet filter enabled, anti-lockout disabled (confirmed by Adam). Rules pushed with `labmode.py` (before #32, so without auto-revert). Tables below are the verifier output files from the final run, unedited. Earlier runs of the same phases failed and led to fixes (filter disabled, log client bugs, ssh consuming the matrix, selected-target verdicts, update-source resolution); only the passing runs are recorded.

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

phase=vpn mode=exercise selected=t1 rows=9 skipped=0 PASS

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
| operator | fw:0 | exercise | deny | deny | firewall:opt4 |

VPN handshake with the filter on, by capture at the firewall: `192.168.0.223 -> 192.168.0.82:51820` initiation, response and keepalives, passed by `pass in quick on vtnet0 ... from 192.168.0.223 to (self) port 51820`.

### Exercise mode, phase `home`

Source addresses on the workstation: `192.168.0.223`, plus aliases `192.168.0.50` (`home_other`) and `203.0.113.55` (`public`). Host routes `10.77.1.10/32`, `10.77.3.10/32`, `10.77.11.10/32` via `192.168.0.82` beat the tunnel's `/16`, so the probes enter through the firewall WAN; the tunnel stays up for the log check. The `home_other` UDP row has no reply to observe, so its verdict is the logged block. The `workstation -> fw:51820` allow is read from the firewall's WireGuard status.

phase=home mode=exercise selected=t1 rows=8 skipped=0 PASS

| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| workstation | fw:51820 | exercise | allow | allow | firewall:wan |
| workstation | fw:443 | exercise | deny | deny | firewall:wan (deny logged: yes) |
| workstation | t1:80 | exercise | deny | deny | firewall:wan (deny logged: yes) |
| workstation | attacker:22 | exercise | deny | deny | firewall:wan (deny logged: yes) |
| workstation | elastic:5601 | exercise | deny | deny | firewall:wan (deny logged: yes) |
| home_other | fw:51820 | exercise | deny | deny | firewall:wan (deny logged: yes) |
| public | t1:80 | exercise | deny | deny | firewall:wan (deny logged: yes) |
| workstation | fw:0 | exercise | deny | deny | firewall:wan |

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

See Known gaps. Not evidenced: Docker-published ports and per-target NICs (M4).

## A2 evidence on the rebuilt firewall (#31, 2026-10-29)

VM 2000 destroyed and recreated from the pre-installed OPNsense 26.7 nano image plus the config seed (`scripts/seed-build.sh`, Tofu `seeded=true`), then rules pushed with `labmode.py` (dead-man armed). Probe guests cloned from template 2100. Verifier output unedited; only the passing runs are recorded.

### Exercise mode, t1 selected, phase `lab`

phase=lab mode=exercise selected=t1 rows=39 skipped=0 PASS

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
| t2 | elastic:9200 | exercise | allow | allow | firewall:opt3 |
| attacker | elastic:8220 | exercise | allow | allow | firewall:lan |
| t2 | elastic:8220 | exercise | allow | allow | firewall:opt3 |
| attacker | fw:0 | exercise | deny | deny | firewall:lan |
| elastic | fw:0 | exercise | deny | deny | firewall:opt1 |
| t1 | fw:0 | exercise | deny | deny | firewall:opt2 |
| t2 | fw:0 | exercise | deny | deny | firewall:opt3 |

### Exercise mode, phase `vpn`

phase=vpn mode=exercise selected=t1 rows=11 skipped=0 PASS

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
| operator | elastic:9200 | exercise | deny | deny | firewall:opt4 (deny logged: yes) |
| operator | elastic:8220 | exercise | deny | deny | firewall:opt4 (deny logged: yes) |
| operator | fw:0 | exercise | deny | deny | firewall:opt4 |

### Exercise mode, phase `home`

phase=home mode=exercise selected=t1 rows=8 skipped=0 PASS

| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| workstation | fw:51820 | exercise | allow | allow | firewall:wan |
| workstation | fw:443 | exercise | deny | deny | firewall:wan (deny logged: yes) |
| workstation | t1:80 | exercise | deny | deny | firewall:wan (deny logged: yes) |
| workstation | attacker:22 | exercise | deny | deny | firewall:wan (deny logged: yes) |
| workstation | elastic:5601 | exercise | deny | deny | firewall:wan (deny logged: yes) |
| home_other | fw:51820 | exercise | deny | deny | firewall:wan (deny logged: yes) |
| public | t1:80 | exercise | deny | deny | firewall:wan (deny logged: yes) |
| workstation | fw:0 | exercise | deny | deny | firewall:wan |

### Firewall down (`failclosed`)

phase=failclosed rows=7 PASS

| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| attacker | t1:80 | firewall down | deny | deny | no forwarding path (VM stopped) |
| attacker | elastic:9200 | firewall down | deny | deny | no forwarding path (VM stopped) |
| t1 | elastic:9200 | firewall down | deny | deny | no forwarding path (VM stopped) |
| t1 | elastic:8220 | firewall down | deny | deny | no forwarding path (VM stopped) |
| t2 | elastic:9200 | firewall down | deny | deny | no forwarding path (VM stopped) |
| attacker | elastic:8220 | firewall down | deny | deny | no forwarding path (VM stopped) |
| t2 | elastic:8220 | firewall down | deny | deny | no forwarding path (VM stopped) |

### Maintenance mode

phase=lab mode=maintenance selected=none rows=39 skipped=0 PASS

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
| attacker | fw:443 | maintenance | deny | deny | firewall:lan (deny logged: yes) |
| attacker | fw:22 | maintenance | deny | deny | firewall:lan (deny logged: yes) |
| t2 | elastic:9200 | maintenance | allow | allow | firewall:opt3 |
| attacker | elastic:8220 | maintenance | allow | allow | firewall:lan |
| t2 | elastic:8220 | maintenance | allow | allow | firewall:opt3 |
| attacker | fw:0 | maintenance | deny | deny | firewall:lan |
| elastic | fw:0 | maintenance | deny | deny | firewall:opt1 |
| t1 | fw:0 | maintenance | deny | deny | firewall:opt2 |
| t2 | fw:0 | maintenance | deny | deny | firewall:opt3 |

After maintenance: `labmode.py exercise`, `REVERIFY=1 a2-verify.sh exercise none lab` (39 rows PASS), `labmode.py select t1`. NIC audit (`nicaudit.py`): only VM 2000 touches the home bridge; every other guest is on one lab bridge.

### What the rebuild taught us (seed and runbook fixes)

- **The nano image does not import the seed by itself.** It ships a default `/conf/config.xml`, so the boot-time importer (which only runs when none exists) exits silently. Hands-off first boot is **not achieved**: the seed ISO is attached but a console step (`opnsense-importer`, pick the cdrom) is still needed. Options in the issue: a UFS write of `conf/config.xml` into the nano image on a host that can write UFS (not Windows or WSL), a cloned pre-seeded template disk, or Proxmox `sendkey` automation (needs `VM.Console`).
- **Seed fixes found by diffing against a real export:** privilege names; `OPNsense/Gateways`; offload and IPv6 under `OPNsense/Interfaces/settings`; `apikeys` as `key|hash`; user passwords as **bcrypt** (`$2y$`, SHA-512 is rejected at login); an `admins` group with `page-all` (without it root cannot log in to the GUI); container `version` attributes (without them the migrations reset Unbound to disabled); the **whole** `unboundplus` subtree (configd renders `unbound.conf` from `config.xml` and fails on a missing `acls`); `system/timeservers` (it alone enables ntpd).
- **Operator traps:** replacing the seed ISO under a running VM leaves the guest with stale media (mixed old and new blocks, I/O errors past the old size): eject and re-attach the cdrom after every upload (`ide2=none` then the ISO again). Tofu does not notice a changed local ISO and `-replace` needs `Datastore.Allocate` on the store, so upload through the API instead. A Windows checkout (`core.autocrlf`) turns scripts that run on the firewall into CRLF; `.gitattributes` now pins `scripts/firewall/*` and `network/*.xml` to LF (a CRLF shebang made the dead-man job exit 127).
- **The nano image is fetched, checked and decompressed on the workstation** (`seed-build.sh`) and uploaded by Tofu: Proxmox's own download needs `Sys.Audit`, which the stack token deliberately lacks. The role gained `Datastore.AllocateTemplate` only.
- **After a re-import the cron job is gone** (it lives in `config.xml`): add "Opaleye dead-man switch" every minute in System > Settings > Cron, then `labmode.py arm`. Seeding it is a follow-up.
- **`failclosed` hard-stops the VM.** Run right after a push it can lose the last config write (the selected-target rule came back disabled while labmode said t1). Re-run `labmode.py exercise t1` after `failclosed` before verifying again.
- **Maintenance update-source rows can flap**: the firewall's alias refresh and the probe's lookup can land on different Fastly answers (35 s TTL). A fresh `labmode.py maintenance` push followed immediately by the verifier passed.
