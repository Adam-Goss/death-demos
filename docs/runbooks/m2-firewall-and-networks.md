# M2 firewall VM and lab networks runbook

Issue #21. Exit = check A2 in [acceptance checks](../decisions/acceptance-checks-and-build-plan.md). **A2 is a hard gate before any vulnerable target powers on.** Policy: [ADR 0001](../adr/0001-isolate-the-attack-lab-behind-a-firewall-vm.md) and the #6 flow contract.

**Status: fresh A2 closeout evidence recorded 2026-10-29 at the end of this runbook; pending Adam's review before #21 closes.** The OPNsense API field names and the Tofu VM arguments held up on 26.7 with the fixes recorded in git history; first-boot OPNsense setup is generated as a config seed (#31) and rebuilt hands-off from a cloned seeded template (#41): clone + start, no console or GUI step, all A2 phases pass on it, and the dead-man switch is proven live (#32).

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
- `scripts/firewall/opaleye_deadman.py`, `scripts/firewall/actions_opaleye.conf`, `scripts/bake-deadman.sh`, `scripts/install-deadman.sh`: dead-man switch that runs on the firewall (#32); tests in `tests/test_deadman.py`.
- `scripts/bootstrap-bridges.sh`: root, node shell. Writes `/etc/network/interfaces.d/opaleye-lab.conf` (outside the Ludus blocks) and `ifup`s only new bridges.
- `tofu/stacks/firewall`: firewall VM (only guest with the home bridge, WAN = first NIC) and optional throwaway probe guests.
- `scripts/opnsense_seed.py`, `network/opnsense-seed.xml`: first-boot `config.xml` seed (#31); tests in `tests/test_opnsense_seed.py`.
- `scripts/a2-verify.sh`: prints the A2 evidence table.
- `scripts/opnsense_dns.py`: brings an existing seeded firewall to the local-only resolver/cache settings without widening the API user's privileges.
- `scripts/a2-docker-probe.sh`: builds a safe static Docker HTTP control on the disposable t1 probe and checks its published ports through the normal A2 verifier.
- Tests: `tests/test_netpolicy.py`, `tests/test_labmode.py` (against `tests/fake_opnsense.py`), guards in `tests/static-checks.sh`.

## Extra checks (run after A2)

- `PVE_NODE=ludus python3 scripts/nicaudit.py`: only VM 2000 touches the home bridge; every other guest is on exactly one lab bridge (`tests/test_nicaudit.py` covers the rules).

## Run

1. Fix the two home placeholders in `network/plan.json`; `python3 scripts/netpolicy.py check`.
2. Node, as root: `scripts/bootstrap-bridges.sh`, then `HOME_BRIDGE=vmbr0 BRIDGES="vmbr2001 vmbr2003 vmbr2011 vmbr2012" scripts/bootstrap-proxmox.sh` (home bridge ACL goes to the firewall token only).
3. Upload the OPNsense ISO to `iso-files`; `export TF_VAR_node_name=ludus TF_VAR_installer_iso_file_id=iso-files:iso/<file>`; `scripts/lab.sh apply firewall`.
4. **Seeded first boot (#31, #41): clone a seeded template, no console.** The template is built once; every rebuild is clone + start. `network/opnsense-seed.xml` is the secret-free `config.xml` generated from `network/plan.json` (`python3 scripts/opnsense_seed.py template > network/opnsense-seed.xml` after any plan change; `tests/static-checks.sh` fails if stale or if it holds secrets). It sets the bootstrap rules above (`labmode.py exercise` then completes the ruleset), interfaces vtnet0..4, addresses, the WireGuard instance and peer, Unbound and NTP on the lab interfaces, the `opaleye-api` user and key, WAN "Block private networks" off, anti-lockout off, offload off, IPv6 off. Secrets come from the operator environment (`secrets/env.sh` is gitignored): `export OPNSENSE_ROOT_PASSWORD OPNSENSE_API_KEY OPNSENSE_API_SECRET OPNSENSE_WG_PRIVATE_KEY OPNSENSE_WG_PUBLIC_KEY OPNSENSE_WG_PEER_PUBLIC_KEY`; `export OPNSENSE_NANO_URL=... OPNSENSE_NANO_SHA256=...` (release checksums file); `scripts/seed-build.sh` fetches and verifies the nano image, bakes the dead-man files into `.state/opnsense-nano.raw` on a FreeBSD build host (below) and writes `.state/opnsense-seed.iso` (needs openssl, the `bcrypt` Python module, and xorriso/genisoimage/mkisofs/hdiutil or `pycdlib`). **Template build (once, or after a secret/seed/plan change):** copy `.state/opnsense-nano.raw` to the node, upload `.state/opnsense-seed.iso` to `iso-files` as `opnsense-seed.iso`, then as root on the node `NANO=/path/opnsense-nano.raw SEED_ISO=iso-files:iso/opnsense-seed.iso scripts/make-firewall-template.sh` (VM 2101, pool `lab-firewall`). It boots the disk with the seed, drives the importer over the serial socket (`scripts/firewall_console.py`; success is read from computed exit-status markers and a check that the `opaleye-api` user landed in `/conf/config.xml`), powers off, detaches and **deletes the seed ISO**, and converts the VM to a template. Then `TF_VAR_node_name=ludus TF_VAR_firewall_template_vm_id=2101 scripts/lab.sh apply firewall`: Tofu clones the template (the token already has `VM.Clone`), uploads nothing and never sees the seed. Rebuild VM 2000 = destroy it and apply again. **Secrets on the template:** the template disk holds the WireGuard private key, API secret hash and root hash. The template lives in the private `lab-firewall` pool (the firewall token clones it, nothing else is granted on it), the seed ISO exists in the store only between upload and the template build, and Tofu state holds only the template id. Rotating a secret or changing the seed/plan means destroying template 2101 and rebuilding it; existing clones keep the old secrets until rebuilt. This matches the existing trust in the node and does not change the ADR 0001 threat model. **Installer path (no template):** leave `firewall_template_vm_id` at 0, upload the installer ISO to `iso-files` and `TF_VAR_attach_installer=false TF_VAR_seed_iso_file_id=iso-files:iso/opnsense-seed.iso scripts/lab.sh apply firewall`; the importer takes `conf/config.xml` from it by hand. Still by hand: remote syslog to Elastic (M3) and `os-qemu-guest-agent`.
5. `export OPNSENSE_URL=https://<fw> OPNSENSE_API_KEY=... OPNSENSE_API_SECRET=... OPNSENSE_INSECURE=true`; `python3 scripts/labmode.py arm`; wait for the first per-minute restore point. Run `python3 scripts/labmode.py exercise none`, then `python3 scripts/opnsense_dns.py --apply` (also needs `OPNSENSE_ROOT_PASSWORD` from step 4). A second DNS apply must report no changes. Then select `t1` after any required complete re-verification. This also converges clones of template 2101 built before the DNS fix; rebuild that template from the new seed when next rotating its secrets.
6. Probe guests: as root on the node, `scripts/make-probe-template.sh` (needs the Debian cloud `.img` on `iso-files`; builds template 2100 in pool lab-firewall). Then `TF_VAR_probe_vms=true TF_VAR_probe_ssh_public_key="$(cat ~/.ssh/id_ed25519.pub)" scripts/lab.sh apply firewall`. Then `scripts/a2-verify.sh exercise t1 lab`, `... vpn` (VPN up), `... home` (VPN down), `a2-verify.sh failclosed`.
7. Maintenance: `labmode.py maintenance --minutes 30 --reason "..."`; install `scripts/install-tick-timer.sh` on the controller (cron running, VPN up) so `labmode.py tick` runs every minute; after return, an unfiltered `REVERIFY=1 scripts/a2-verify.sh exercise none lab` with no skipped rows clears the flag. `labmode.py select` refuses until then.
8. Record the tables below; destroy probe guests; only then does M3 start.

## Prepare the dead-man disk (#42)

Use a disposable FreeBSD build host with this checkout and the verified nano image.
`scripts/seed-build.sh` runs the fetch and bake together there (bash and the seed
builder's Python dependencies are required). Alternatively, fetch on the workstation:

```sh
python3 scripts/fetch_nano.py "$OPNSENSE_NANO_URL" "$OPNSENSE_NANO_SHA256" .state/opnsense-nano-base.raw
```

Copy that pristine disk and the checkout to the FreeBSD builder, then run as root:

```sh
sh scripts/bake-deadman.sh .state/opnsense-nano-base.raw .state/opnsense-nano.raw
```

Copy the resulting `.state/opnsense-nano.raw` back to the workstation before applying
the seeded firewall stack. On Windows/Linux, unset `OPNSENSE_NANO_URL` when building
only the seed ISO with `scripts/seed-build.sh`; baking UFS requires FreeBSD. Bake again
whenever either `scripts/firewall/*` file changes. The helper copies the pristine disk,
finds its single UFS partition, mounts it offline, installs the script (0755) and configd
action (0644), then unmounts and publishes the prepared disk. It does not change the
pristine download or its checksum stamp. `scripts/install-deadman.sh` now takes a
mounted offline root directory, rather than an SSH hostname.

Tofu no longer uploads either file (#41): the baked disk and seed ISO go to the node
by hand for `scripts/make-firewall-template.sh`, so the token's inability to delete
uploads no longer blocks a rebuild. Re-bake and rebuild the template when the dead-man
files change.

**Why bake:** the [26.7 importer](https://github.com/opnsense/core/blob/stable/26.7/src/sbin/opnsense-importer)
only restores a fixed list of files from `conf`; arbitrary adjacent scripts are not
installed. Baking avoids firewall SSH, console file installation, and boot-time network
downloads. The files live outside `/conf`, so importing the generated config preserves
them. The importer still has to run once, on the template builder (#41), not on every rebuild.
The Cron 1.0.4 layout and job fields match the operator's GUI export
`config-opaleye-firewall.lab.internal-20261029113405.xml`; only its random UUID and
`persisted_at` metadata are replaced/omitted. Never commit the full export: it contains secrets.

### #42 validation

Offline tests assert an enabled every-minute `opaleye deadman` entry and reject missing,
disabled or delayed jobs. The existing API tests exercise `labmode.py arm`. Live baking
and rebuilt-VM acceptance passed on 2026-10-29 (evidence below). To repeat the check:

1. Import the seed and reboot. No cron GUI or firewall file installation is needed.
2. Run `python3 scripts/labmode.py arm` over the VPN; it must return 0.
3. Observe nobody's crontab rendering `* * * * * /usr/local/sbin/configctl -d -- opaleye deadman`.
   Wait for at least two scheduled runs; record exit status 0 and advancing
   `/var/db/opaleye/confirmed.xml` timestamps. A successful `arm` alone does not prove the scheduler works.
4. Push exercise mode and verify it persists beyond the rollback window. Rerun A2 when changing network policy.

### Issue #42 live rebuild evidence (2026-10-29)

The bake ran as root in a temporary OPNsense 26.7 DVD VM on Proxmox, using the
verified pristine nano disk. Its BSD UFS partition begins at sector zero, so
`fstyp` identifies both the disk and its partition as UFS; the helper now selects
the `freebsd-ufs` provider from `gpart show -p` instead of counting overlapping aliases.
The prepared raw disk's SHA256 was
`d957e55a8ae8bdbe6e83a076c1e6f47bc1596cfa371a6c3bf53e118da98dbe07`.
Both installed files matched the repository hashes, with script mode 0755 and action
mode 0644, on the mounted prepared disk and again on the rebuilt firewall.

VM 2000 was backed up, destroyed and recreated through Tofu with that disk and the
new seed ISO. The token's first attempt to delete the old uploads was refused;
administrator storage-API deletion of those two files allowed the subsequent plan
and apply to finish. No deployment privileges were widened. The then-needed
importer step (removed by #41) was performed using `opnsense-importer cd0 && reboot` on the console.
No script/action installation, SSH access, cron GUI change, or cron file edit was
performed on the rebuilt firewall.

`labmode.py arm` returned 0 and created matching marker aliases. Nobody's generated
crontab contained `* * * * * /usr/local/sbin/configctl -d -- opaleye deadman`.
An explicit `configctl opaleye deadman` returned `OK` with exit status 0.
Kernel tracing of configd and its children then established the scheduled executions:

| UTC | Dead-man process | Result |
| --- | --- | --- |
| 15:45:00 | PID 10971 | Executed `/usr/local/sbin/opaleye_deadman.py`, exited 0 |
| 15:46:00 | PID 21351 | Executed `/usr/local/sbin/opaleye_deadman.py`, exited 0 |
| 15:47:00 | PID 34588 | Executed `/usr/local/sbin/opaleye_deadman.py`, exited 0 |

`confirmed.xml` advanced at the minute boundaries without manual action. The trace
captured system calls and path lookups, not file contents, and was disabled afterward.
The exercise/t1 push at **15:44:26 UTC** remained confirmed at **15:48:09 UTC**
(223 seconds): matching markers, t1 exercise rules enabled, t2 exercise rules disabled.
The NIC audit passed; only VM 2000 touched the home bridge. Network policy was not
changed by #42, so the full A2 matrix was not repeated for this check.

The full offline suite (210 tests, one skipped), all static guards, Python compilation,
and Tofu validation/format checks passed. Tests ran from a clean LF archive because
the Windows checkout's existing `tests/stub_ssh.py` CRLF shebang breaks unrelated
lab-operations tests. Both review axes found no code defects. Screenshots and local
test artifacts remain under ignored `.state/`. The temporary builder and transfer
servers were stopped. The pre-rebuild VM backup remains private under
`/mnt/pve/iso-files/opaleye-build-42/backup/` on the node.

## Known gaps

- **Config seed and hands-off first boot** (#31, #41): VM 2000 was destroyed and rebuilt from the nano image plus the seed on 2026-10-29 and all A2 phases passed on it (evidence at the end; fixes found along the way in "What the rebuild taught us"), but that run needed one console step. #41 replaces it with a cloned seeded template (Run step 4): the dead-man cron job is in the seed, so a clone needs no GUI step. **Proven live 2026-10-29:** the rebuild is clone + start with no console, and A2 `lab` passes on it (section "Hands-off rebuild from a cloned seeded template"). A2 `lab`, `maintenance`, `vpn`, `home` and `failclosed` all pass on the rebuilt VM (section "A2 on the rebuilt firewall, run from WSL"; elastic-sourced rows are A3's). #31 closed 2026-10-29. Remote syslog to Elastic (M3) and `os-qemu-guest-agent` are still by hand. Still true after any rebuild: ping to the firewall is denied by design (only TCP 443 from the VPN); test with `curl -k https://10.77.9.1/`.
- **Dead-man switch** (#32, replaces the missing core savepoint; **proven live on 26.7 on 2026-10-29**, see "Issue #32 live recovery evidence" below): The prepared nano disk installs the script and configd action before upload, and the generated seed includes the enabled every-minute cron job (#42). After importing the seed and rebooting, run `labmode.py arm` and wait for the first saved restore point before pushing. Each push sets `opaleye_pending`, applies, then confirms through the API. If confirmation cannot reach the firewall for 120 s after cron first observes the pending token, the job restores the saved config and reloads aliases and the filter (worst case about three minutes). Reload failures retain a retry marker. Restoring also drops other config changes made since the last saved confirmed configuration. The controller refuses unarmed or already-unconfirmed pushes. Take a separate configuration backup before testing recovery. Baking and rebuilt-VM cron execution were verified live for #42; see the evidence below.
- IPv6 is probed per side: lab vantages (no global address, no default route, no reply to an all-routers ping); VPN (the firewall's own WireGuard peer config routes no IPv6: `labmode.py wgv4only`); home (the firewall's WAN MAC from the Proxmox API must not answer a `ping -6 ff02::1`, with other neighbours answering as the control, else ERROR). The home probe needs `PROXMOX_VE_*`/`PVE_NODE` in the environment and a working IPv6 multicast path on the workstation. Recorded in the `vpn` and `home` runs below.
- The `workstation -> fw:51820` allow row reads the firewall's own WireGuard status (`labmode.py wgpeer`: peer `workstation`, fresh handshake, endpoint `192.168.0.223`); needs the `VPN: WireGuard: Status` privilege on `opaleye-api`. Recorded in the `home` run below (7 rows, 0 skipped).
- `attacker -> fw` is probed on 443/22 (p46, p47) in the `lab` phase only; the other phases' tables predate those rows.
- `denylog` ignores rows already in the log when the verifier starts (digest baseline), so a stale block from an earlier run cannot satisfy a row; within one run, an identical earlier block for the same src/dst/port still would.
- `labmode.py tick` needs a timer: `scripts/install-tick-timer.sh` installs a per-minute user crontab line (WSL: `sudo service cron start`, VPN up); `--remove` uninstalls. Credentials come from `secrets/env.sh` (cron sees only that file). Proven live 2026-10-28 by cron: a 1-minute maintenance window closed itself (`maintenance expired: back to exercise mode`, `reverify_required: true`); the first attempt failed for a missing variable and left maintenance open until fixed (the tick retries each minute).
- Docker-published ports and per-zone NIC isolation are now evidenced with safe disposable probes in the live closeout below. Audit each real target configuration before powering it on; a future extra NIC must not bypass the firewall.
- `a2-verify.sh` reports `PASS-WITH-SKIPS` when rows were skipped; a dead probe vantage yields `ERROR`, never a green deny. Skipped or destination-filtered runs cannot clear the re-verification flag. Empty runs, matrix generation errors, invalid phases/modes, and failures to record re-verification exit non-zero. A diagnostic `PASS-WITH-SKIPS` is incomplete A2 evidence.

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

- **The nano image does not import the seed by itself.** It ships a default `/conf/config.xml`, so the boot-time importer (which only runs when none exists) exits silently. Hands-off first boot was achieved later by #41 (seeded template, historical note: this rebuild still needed the console importer).
- **Seed fixes found by diffing against a real export:** privilege names; `OPNsense/Gateways`; offload and IPv6 under `OPNsense/Interfaces/settings`; `apikeys` as `key|hash`; user passwords as **bcrypt** (`$2y$`, SHA-512 is rejected at login); an `admins` group with `page-all` (without it root cannot log in to the GUI); container `version` attributes (without them the migrations reset Unbound to disabled); the **whole** `unboundplus` subtree (configd renders `unbound.conf` from `config.xml` and fails on a missing `acls`); `system/timeservers` (it alone enables ntpd).
- **Operator traps:** replacing the seed ISO under a running VM leaves the guest with stale media (mixed old and new blocks, I/O errors past the old size): eject and re-attach the cdrom after every upload (`ide2=none` then the ISO again). Tofu does not notice a changed local ISO and `-replace` needs `Datastore.Allocate` on the store, so upload through the API instead. A Windows checkout (`core.autocrlf`) turns scripts that run on the firewall into CRLF; `.gitattributes` now pins `scripts/firewall/*` and `network/*.xml` to LF (a CRLF shebang made the dead-man job exit 127).
- **The nano image is fetched, checked and decompressed on the workstation** (`seed-build.sh`) and uploaded by Tofu: Proxmox's own download needs `Sys.Audit`, which the stack token deliberately lacks. The role gained `Datastore.AllocateTemplate` only.
- **After a re-import the cron job is gone** (fixed by the seed, #42; historical): add "Opaleye dead-man switch" every minute in System > Settings > Cron, then `labmode.py arm`.
- **`failclosed` hard-stops the VM.** Run right after a push it can lose the last config write (the selected-target rule came back disabled while labmode said t1). Re-run `labmode.py exercise t1` after `failclosed` before verifying again.
- **Maintenance update-source rows can flap**: the firewall's alias refresh and the probe's lookup can land on different Fastly answers (35 s TTL). A fresh `labmode.py maintenance` push followed immediately by the verifier passed.

### Repeat rebuild with the committed seed (2026-10-29)

VM 2000 replaced with `tofu apply -replace=proxmox_virtual_environment_vm.firewall` (nano disk and seed ISO unchanged), then `opnsense-importer` on the console (cdrom), dead-man files fetched from the console and the cron job re-added by hand. `labmode.py arm` and `exercise t1` worked at once and adopted all six bootstrap rules in place (same UUIDs); the probe guests were recreated for one `lab` run: `phase=lab mode=exercise selected=t1 rows=39 skipped=0 PASS` (Unbound, ntpd and update-source rows included). Probes destroyed afterwards. Manual steps in this rebuild: the importer, the dead-man files and the cron job (#41, #42).


### Issue #32 follow-up validation (2026-10-29)

The API was reachable from the workstation and the pending/confirmed markers matched. Issue #31 records rebuild/A2 success, but does not record a deliberately breaking push reverting. TCP 22 to the firewall timed out from this workstation, and the API key received HTTP 403 from `cron/settings/search_jobs`; the revised job has therefore not been installed or exercised live here. This was the initial access limitation; the root web session subsequently allowed temporary SSH setup and the live checks recorded below.

The controller now brackets update-source alias changes with the pending/confirmed markers, including alias-only pushes, and refuses unarmed changes before mutating aliases. The job treats a failed reload as an error and keeps a durable retry marker; subsequent runs restore the saved config again and retry reload before saving another restore point.

To collect the remaining evidence after installing the revised job through an available admin route:

1. Check the every-minute cron job is enabled, run `labmode.py arm`, and wait for a successful job run. On the firewall verify `/var/db/opaleye/confirmed.xml` exists and its two marker aliases match. Keep a separate configuration backup.
2. Run a normal `labmode.py exercise` push with a changed selected target. Record the output, matching API markers, and verify the selected rules persist beyond three minutes.
3. From the VPN admin path, set the pending alias description to a fresh token, disable the managed VPN-to-firewall TCP 443 allow rule, and apply. Do not set the confirmed marker. Use fresh HTTPS connections to verify access is lost (an existing PF state may still pass).
4. Leave the scheduler running without console intervention. Within about three minutes verify a fresh authenticated API connection succeeds, the allow rule is restored, and the markers match the saved config. Record timestamps for push, failed connection, recovery and the scheduler's `reverted` result.
5. Repeat a normal push and verify it persists. Reconcile workstation mode with the actual firewall using `labmode.py exercise` after a rollback; a failed push does not commit workstation state.

Do not mark recovery proven based only on matching markers or offline tests: those do not establish that cron runs or that the installed reload commands restore the admin path.

Offline validation: 208 tests passed under WSL (one skipped) after locally normalizing the existing `tests/stub_ssh.py` CRLF shebang to LF; that unrelated normalization is not committed. Targeted labmode (23) and dead-man (10) tests, Python compilation, and `git diff --check` also passed. Native Windows/Git Bash suite groups fail on POSIX tool/permission assumptions; static policy, seed consistency, and secret guards passed.

### Issue #32 live recovery evidence (2026-10-29)

Executed from the workstation over WireGuard to `https://10.77.9.1`, against OPNsense CE 26.7 (VM 2000). The API key still lacks cron privileges (403), but root web authentication worked with the operator-provided credentials. No permanent API privilege changes were needed.

The revised `opaleye_deadman.py` from commit `0c14f4c` was installed with LF line endings and mode 755. Temporary root/password SSH access used a single VPN-interface allow from workstation `10.77.9.2/32` to firewall `10.77.9.1/32:22`. A separate config backup was saved locally under ignored `.state/`. The existing configd action was present. The enabled every-minute GUI job renders into **nobody's crontab**, not root's: `* * * * * /usr/local/sbin/configctl -d -- opaleye deadman`. `confirmed.xml` was observed being refreshed by cron at 11:16:00 UTC. `configctl filter refresh_aliases` and `configctl filter reload` both succeeded on this version. The temporary SSH allow was deleted and its session closed before the breaking push.

| UTC | Action / observation | Result |
| --- | --- | --- |
| 11:17:17 | `labmode.py` exercise-mode controller pushed selected target `none` | Applied; API confirmation succeeded |
| 11:20:27 | Rechecked after 191 seconds | Both markers still matched the normal-push token; all selected-target rules remained disabled |
| 11:20:35 | Deliberately disabled `opaleye:op-fw-admin@opt4@vpn:443` through `labmode.sync` | Applied; post-apply confirmation request timed out |
| 11:21:16 to 11:22:46 | Fresh authenticated API requests from the VPN | Timed out; admin path unavailable |
| 11:23:04 | Fresh authenticated API request succeeded | Admin HTTPS allow restored to enabled; pending and confirmed markers both returned to the saved normal-push token |
| 11:23:44 | Disabled temporary SSH service/root/password options; pushed exercise mode with target `t1` | Temporary SSH allow absent; normal push applied and confirmed |
| 11:26:55 | Rechecked after a further 190 seconds | Confirmation token unchanged; target `t1` rules still enabled |

The breaking test used the unmodified controller and API client, with a controlled renderer fault injected only in the local test harness: `labmode.desired` returned its usual exercise/none payload except that the admin HTTPS allow had `enabled="0"`. `labmode.sync` performed its normal pending -> rule update -> apply -> confirm sequence. Its confirmation failed at `firewall/alias/searchItem` with a timeout. No console, SSH session, manual restore, or controller recovery write was used during the outage. Cron alone restored access about **149 seconds** after the breaking push. Recovery was established by a fresh authenticated API response, the restored rule, and the original confirmed token; the job's stdout was not captured separately.

SSH was disabled again through the root web interface immediately after recovery. The lab was returned to exercise mode with target `t1`; the post-recovery push persisted for 190 seconds with matching markers and target `t1` rules still enabled. Both issue #32 acceptance checks passed. Live test inputs and raw timestamps are retained locally in ignored `.state/live32-evidence.json`, without committing credentials or configuration backups.

## Hands-off rebuild from a cloned seeded template (#41, 2026-10-29)

Template 2101 was built once on the node with `scripts/make-firewall-template.sh` from the baked nano disk (#42) and a freshly rendered seed ISO. Three console-driver fixes came out of the live run, all in `scripts/firewall_console.py`: the nano image boots to a `login:` prompt (default `root`/`opnsense`, valid only until the seed is imported), root's shell is csh (markers run through `sh -c`), and a failed build must leave no VM or seed ISO behind (cleanup trap). The builder ended with `template 2101 ready (pool lab-firewall); seed ISO deleted`.

VM 2000 (backup taken first) was then replaced by `TF_VAR_firewall_template_vm_id=2101 scripts/lab.sh apply firewall`: destroy 3 s, clone 7 s, **no console or GUI step**. The firewall answered HTTPS on 10.77.9.1 over the VPN within about 30 s, `labmode.py arm` returned 0 and `labmode.py exercise t1` applied. The stale `nano` upload entry was removed from state (`tofu state rm`) because the stack token cannot delete uploads; the file itself stays on the node for an administrator to delete.

A2 `lab` phase on the rebuilt VM (`a2-verify.sh exercise t1 lab`): **39 rows, 0 skipped, PASS** (every deny logged). Run from a Windows workstation, where `netpolicy.py matrix` output carried CRLF and made 8 allow rows read `deny`; stripping CR (`PYTHON` wrapper `python3 "$@" | tr -d '\r'`) gave the PASS. Run it from WSL/Linux to avoid this.

All of these phases are now evidenced; see "A2 on the rebuilt firewall, run from WSL" below.

### Maintenance and exercise re-run on the rebuilt VM (#41, 2026-10-29)

Run from the Windows workstation with the CR-stripping wrapper. Findings:

- The real Elastic VM (M3) now owns `10.77.3.10`; the throwaway elastic probe duplicated its address and was destroyed (`probe_zones` without `elastic`). `a2-verify.sh` cannot source elastic rows without that probe, so they report ERROR and the script exits non-zero; they belong to the A3 run against the real VM (`ONLY_DST`). **Consequence:** `REVERIFY=1 a2-verify.sh exercise none lab` can no longer clear labmode's re-verify flag by itself. After this run the controller is in exercise mode, selected `none`, with `reverify_required: true`; clear it with `labmode.py reverified` only after reading a clean non-elastic table.
- `maintenance` (lab): 37 of 39 non-elastic-sourced rows matched. `t1 -> update_source:443` and `attacker -> update_source:443` read `deny`: the verifier probes whichever address `deb.debian.org` resolves to on that call, and Fastly returns different addresses over time, so it can pick one the firewall's FQDN alias did not hold. From the t1 probe, `199.232.54.132` (current answer) connected and `1.1.1.1` did not. Treat those two rows as unproven until the verifier resolves the alias the same way the firewall does.
- `exercise none` (lab): every non-elastic row matched, including every deny. `exercise t1` (lab): all non-elastic rows matched in the earlier clean run (39 rows PASS before the elastic probe was removed).
- Not run: `vpn`, `home` (need Linux `ip route`), `failclosed` (arms elastic rows too).

### A2 on the rebuilt firewall, run from WSL (#41, 2026-10-29)

`a2-verify.sh` gained `SKIP_SOURCES` (sources with no probe guest report SKIP, not ERROR; an unlisted source that does not answer is still ERROR), CRLF tolerance for Windows Python, and an update-source check that tries every address the name resolves to and re-resolves a few times when an allow is expected (CDN answers rotate; the firewall alias holds what it resolved). Run with `SKIP_SOURCES=elastic` because the real Elastic VM owns `10.77.3.10`; its rows are A3's. WSL used a temporary 0600 copy of the probe key, `ip route`/`ip addr` entries added with `wsl -u root` (removed afterwards) and no change to the Windows tunnel.

| Phase | Result |
| --- | --- |
| `exercise t1 lab` | 32 rows, 7 skipped (elastic source): **PASS-WITH-SKIPS** |
| `maintenance none lab` | 32 rows, 7 skipped: **PASS-WITH-SKIPS** |
| `REVERIFY=1 exercise none lab` | **PASS-WITH-SKIPS**, "exercise-mode denies re-verified", flag cleared |
| `exercise t1 home` | 8 rows, 0 skipped: **PASS** (every deny logged) |
| `failclosed` | 5 rows: **PASS** (VM 2000 stopped, restarted; firewall HTTPS back, mode still exercise/t1) |
| `exercise t1 vpn` | 11 rows, 0 skipped: **PASS** (every deny logged). Run with the Windows tunnel `AllowedIPs` temporarily extended by `192.168.0.161/32, 1.1.1.1/32` (reverted afterwards) and matching temporary WSL host routes. |

Raw tables: `.state/a2-wsl-*.txt` (gitignored).


## Issue #21 acceptance audit (2026-10-29, before live access)

Historical audit; superseded by the live closeout below.

The existing evidence above covers the seeded rebuild, dead-man recovery, controller
expiry timer, NIC audit, and A2 phases. At this point no live environment or probe key had been loaded, so the audit
added no new network evidence. The later live closeout uses the operator-provided
`../env.sh` in WSL and the existing WSL SSH key.

The verifier now refuses to clear the maintenance re-verification flag after a
skipped or destination-filtered run. It also fails empty runs, propagates matrix
and re-verification write failures, and removes its temporary log baseline.
Eleven CLI regression tests in `tests/test_a2_verify.py` exercise these paths with
simulated probe tools under WSL; they do not establish live isolation.
Offline validation: all 229 tests passed under WSL, along with
`tests/static-checks.sh`, Bash syntax checking, Python compilation, and
`git diff --check`. The skipped-source regression fails against the pre-fix
verifier and passes with the fix. Standards and spec reviews found no new issues.
The earlier WSL `REVERIFY=1` result with `SKIP_SOURCES=elastic` records historical
behaviour that is no longer accepted: seven untested rows cannot establish a full
exercise/lab pass. Do not use `labmode.py reverified` to bypass this missing evidence.
Run all lab sources from dedicated safe probe guests, or arrange an authenticated
vantage on the real Elastic VM, without assigning a duplicate address. Then rerun
an unfiltered exercise/lab table after maintenance and record the full table.

Issue #21 remains pending acceptance. The Docker-published-port and per-target NIC
checks are also still missing from the recorded evidence. They need an isolated,
non-vulnerable test workload before a vulnerable target powers on, as A2 requires.
Do not treat their deferral to M4, or the existing later-milestone code, as proof
that the hard gate passed. No later milestone was started by this audit.


## Issue #21 live closeout (2026-10-29, WSL)

The operator supplied `../env.sh`; no credentials were copied into the repository.
WSL's existing SSH key reached the real Elastic VM and three disposable Debian
probe guests. A targeted, encrypted OpenTofu plan created only VM 120 (t1), 121
(t2), and 122 (attacker), cloned from template 2100. No vulnerable target or later
milestone was deployed. Elastic VM 2003 retained its address, so no duplicate
Elastic probe was created and **no sources were skipped**.

| Check | Recorded result |
| --- | --- |
| Exercise, t1 selected, after firewall restart | 39/39 PASS; all TCP denies logged |
| Maintenance, no target selected | 39/39 PASS; update sources reachable, forbidden flows denied and logged |
| Installed controller cron expiry | One-minute window expired automatically; selection refused until re-verification |
| Return to exercise, no target selected | 39/39 PASS; re-verification flag cleared only after the full table |
| Docker-published ports | Two local HTTP positive controls; 8/8 external flows match expected, all denies logged |
| Home side, including direct routes and alternate source addresses | 8/8 PASS; all denies logged |
| Firewall stopped | 5/5 normally allowed flows denied; firewall restarted successfully |
| Full VPN phase | Earlier 11/11 PASS retained at the operator's explicit request; see the prior WSL evidence section |
| NIC audit | Disposable t1/t2/attacker each on one lab bridge; firewall is the only lab guest on the home bridge |

### DNS convergence and update timing

Initial package downloads and maintenance tables exposed a resolver mismatch and
CDN address rotation. The seed now uses only `127.0.0.1` for system DNS, disables
WAN DNS override, and sets Unbound's minimum cache TTL to 600 seconds. The existing
firewall was converged with `opnsense_dns.py --apply`; a second apply reported no
changes. The API user's privileges were preserved. The update alias now resolves
IPv4 only, matching the lab's disabled-IPv6 policy; its second rule push was also
a no-op.

[OPNsense's system DNS settings](https://docs.opnsense.org/manual/settingsmenu.html#general)
describe local resolver selection; the [alias documentation](https://docs.opnsense.org/manual/aliases.html#hosts)
documents the default 300-second hostname refresh. TTL600 reduces churn; an
approved address can still be blocked conservatively between cache expiry and
alias refresh. The verifier therefore retries expected update-source allows for
at least a full default refresh interval (65 attempts, five-second waits plus
probe time). Expected denies receive one pass. Package updates also need retries;
the safe Docker setup uses bounded APT retries. These changes preserve default
deny while the alias catches up. They do not guarantee uninterrupted CDN access.
The failing maintenance tables remain in ignored `.state/live21/` alongside the
successful final table below.

Clones of the older template 2101 need the code-driven DNS convergence in Run
step 5. Rebuilding the template from the current seed carries the same settings
at first boot; this closeout did not rebuild that existing template.

### Safe Docker workload and NIC control

`a2-docker-probe.sh setup` refuses any t1 hostname other than
`opaleye-probe-t1`, requires maintenance mode with no selected target, and installs
`docker.io`, `docker-cli`, and `busybox-static` through the reviewed Debian update
source. It builds `FROM scratch` using the static BusyBox binary, serves a fixed
`A2-safe-static-control` response, and publishes host ports 80 and 8080 to container
8080. It pulls no container image. The container has a read-only root filesystem,
all capabilities dropped, and no-new-privileges. Re-running setup succeeded.

Recorded packages: Docker daemon/CLI `26.1.5+dfsg1-9+deb13u1`, BusyBox static
`1:1.37.0-6+b9`. The resulting local image was
`sha256:2ae779e3f8f940a7be71b300219cf972987fbc580271d019fb0906bf31e81602`.
The HTTP control checked both published ports from inside t1 before the external
checks. External checks use the normal verifier with a supplemental, filtered
plan and `REVERIFY=0`, so they cannot clear the maintenance gate.

| guest | pool bridges |
| --- | --- |
| VM 120 (opaleye-probe-t1) | vmbr2011 |
| VM 121 (opaleye-probe-t2) | vmbr2012 |
| VM 122 (opaleye-probe-attacker) | vmbr2001 |
| VM 2000 (opaleye-firewall) | vmbr0, vmbr2001, vmbr2003, vmbr2011, vmbr2012 |
| VM 2100 (opaleye-probe-template) | vmbr2001 |
| VM 2101 (opaleye-firewall-template) | none |
| VM 2003 (opaleye-elastic) | vmbr2003 |
| VM 2300 (opaleye-elastic-template) | vmbr2003 |

ok: only the firewall VM touches the home bridge; every other guest is on one lab bridge

### Maintenance, complete lab table

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
| attacker | elastic:9200 | maintenance | deny | deny | firewall:lan (deny logged: yes) |
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
| attacker | elastic:8220 | maintenance | deny | deny | firewall:lan (deny logged: yes) |
| t2 | elastic:8220 | maintenance | allow | allow | firewall:opt3 |
| attacker | fw:0 | maintenance | deny | deny | firewall:lan |
| elastic | fw:0 | maintenance | deny | deny | firewall:opt1 |
| t1 | fw:0 | maintenance | deny | deny | firewall:opt2 |
| t2 | fw:0 | maintenance | deny | deny | firewall:opt3 |


`phase=lab mode=maintenance selected=none rows=39 skipped=0 PASS`

### Return to exercise after automatic expiry

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
| attacker | elastic:9200 | exercise | deny | deny | firewall:lan (deny logged: yes) |
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
| attacker | elastic:8220 | exercise | deny | deny | firewall:lan (deny logged: yes) |
| t2 | elastic:8220 | exercise | allow | allow | firewall:opt3 |
| attacker | fw:0 | exercise | deny | deny | firewall:lan |
| elastic | fw:0 | exercise | deny | deny | firewall:opt1 |
| t1 | fw:0 | exercise | deny | deny | firewall:opt2 |
| t2 | fw:0 | exercise | deny | deny | firewall:opt3 |

labmode: exercise-mode denies re-verified



`phase=lab mode=exercise selected=none rows=39 skipped=0 PASS`

### Docker-published port evidence

| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| t1 loopback | t1:80,8080 | exercise | HTTP control | HTTP control | Docker published ports |

| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| attacker | t1:80 | exercise | allow | allow | firewall:lan |
| attacker | t1:8080 | exercise | deny | deny | firewall:lan (deny logged: yes) |
| t2 | t1:80 | exercise | deny | deny | firewall:opt3 (deny logged: yes) |
| t2 | t1:8080 | exercise | deny | deny | firewall:opt3 (deny logged: yes) |
| elastic | t1:80 | exercise | deny | deny | firewall:opt1 (deny logged: yes) |
| elastic | t1:8080 | exercise | deny | deny | firewall:opt1 (deny logged: yes) |


`phase=lab mode=exercise selected=t1 rows=6 skipped=0 PASS`


| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| operator | t1:80 | exercise | deny | deny | firewall:opt4 (deny logged: yes) |
| operator | t1:8080 | exercise | deny | deny | firewall:opt4 (deny logged: yes) |


`phase=vpn mode=exercise selected=t1 rows=2 skipped=0 PASS`

### Home-side evidence

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


`phase=home mode=exercise selected=t1 rows=8 skipped=0 PASS`

### Firewall-down evidence

| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| attacker | t1:80 | firewall down | deny | deny | no forwarding path (VM stopped) |
| t1 | elastic:9200 | firewall down | deny | deny | no forwarding path (VM stopped) |
| t1 | elastic:8220 | firewall down | deny | deny | no forwarding path (VM stopped) |
| t2 | elastic:9200 | firewall down | deny | deny | no forwarding path (VM stopped) |
| t2 | elastic:8220 | firewall down | deny | deny | no forwarding path (VM stopped) |


`phase=failclosed rows=5 PASS`

### Final exercise table after firewall restart

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
| attacker | elastic:9200 | exercise | deny | deny | firewall:lan (deny logged: yes) |
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
| attacker | elastic:8220 | exercise | deny | deny | firewall:lan (deny logged: yes) |
| t2 | elastic:8220 | exercise | allow | allow | firewall:opt3 |
| attacker | fw:0 | exercise | deny | deny | firewall:lan |
| elastic | fw:0 | exercise | deny | deny | firewall:opt1 |
| t1 | fw:0 | exercise | deny | deny | firewall:opt2 |
| t2 | fw:0 | exercise | deny | deny | firewall:opt3 |


`phase=lab mode=exercise selected=t1 rows=39 skipped=0 PASS`

### Controller expiry and final state

The existing WSL cron service was running. `install-tick-timer.sh` replaced the
stale timer pointing at the removed `pencilfish` checkout with this workspace's
per-minute job, reading the ignored `secrets/env.sh` environment hook.
The one-minute maintenance window started at 20:50:01 UTC and expired at
20:51:01; cron restored exercise mode by 20:52:05 UTC (minute scheduling plus API
apply time). No manual `tick` was used for this proof. Target selection was then
refused until the complete 39-row return table cleared the flag.

```text
2026-10-29 20:50:01 UTC
maintenance (selected: none): applied
{"mode": "maintenance", "selected": null, "expires": 1793307061, "reverify_required": true}
2026-10-29 20:52:05 UTC
{"mode": "exercise", "selected": null, "expires": null, "reverify_required": true}
maintenance expired: back to exercise mode
exercise-mode denies not re-verified since maintenance: run: REVERIFY=1 scripts/a2-verify.sh exercise none lab
gate PASS: target selection refused before re-verification
```

The temporary WSL home-side addresses and host routes were removed. The
full VPN phase reuses the previously recorded result at the operator's request;
its two Docker port deny rows were freshly checked. The final selected-target
table was collected after the firewall-down test and a confirming exercise push.

The three disposable probe VMs were removed with a reviewed, targeted OpenTofu
plan containing only their destruction. The firewall and Elastic remain running.
The controller state is preserved at the normal `.state/labmode.json` path in
exercise mode, t1 selected, with no expiry and no re-verification pending.
The WSL timer remains installed, using the normal state path. Keep WSL, cron,
and the VPN available for controller-timed maintenance expiry.

Validation: **232 tests passed under WSL**, including 12 verifier CLI tests and
17 seed tests. Static guards, Python compilation, Bash syntax, and diff whitespace
checks passed. Standards and spec review found no outstanding findings after the
retry-window correction. #21 remains open for Adam's acceptance review; no next
milestone was started by this work.
