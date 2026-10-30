# Guacamole gateway runbook

Issue #51. Part of #2; not part of M6. Foundation for the malware-analysis zone (follow-up issue).

**Status: deployed and verified live on 2026-10-30.** TOTP enrolment, the browser RDP session to the attacker and the browser SSH session to t1 were completed by the operator. The home-LAN denies (`p55`, `p72`) were also probed live.

## Design

| Piece | Where |
| --- | --- |
| Gateway VM (VMID 2002, `10.77.2.10`, pool `lab-gateway`, 2 vCPU / 4 GB / 20 GB on `iso-files`) | `tofu/stacks/gateway`, template `scripts/make-gateway-template.sh` (VMID 2303) |
| Gateway zone (`opt5`, bridge `vmbr2002`, `10.77.2.0/24`, 6th firewall NIC) | `network/plan.json`; seed `network/opnsense-seed.xml` regenerated |
| Guacamole (guacd, web app, Postgres, TLS proxy; Docker, images pinned by digest) | `ansible/playbooks/gateway.yml`, `ansible/roles/gateway` |
| Attacker desktop (XFCE + xrdp) | `ansible/roles/attacker` |
| Target terminal key (key-only, `from=` the gateway) | `ansible/roles/target/tasks/base.yml` |
| Account, password and connection provisioning | `scripts/guacctl.py` |
| Firewall flows and A2 probes `p53`-`p71` | `scripts/netpolicy.py` (`flows`), `network/plan.json` |

Placement: admin path, behind the firewall VM's VPN. Not on the Proxmox host, the firewall VM or Elastic, and no route from the home LAN (probe `p55`).

Firewall (both modes unless noted):

- operator (VPN) to gateway `443` and `22`;
- gateway to attacker `3389`, and to each target `22` (not 80, not the attacker's SSH);
- gateway DNS and NTP to the firewall; update sources in maintenance mode only (it is a maintenance initiator);
- everything else from the gateway is denied: Elastic, Proxmox, the firewall's admin ports, the Internet.

The firewall VM and Elastic are not brokered; they keep their direct VPN routes. Direct operator RDP to the attacker is denied (`p69`): RDP exists only through the gateway.

**Telemetry impact of the desktop:** none expected. The attacker is the adversary and is deliberately not enrolled in Fleet (only targets ingest, `p16`/`p17`/`p51`), so the desktop adds no events to the evidence store. It adds RAM and disk use on the attacker only; targets get no desktop, so DVWA's telemetry is unchanged. The one new target-side event source is the operator's SSH login from the gateway, in the target's auditd/auth streams. Confirm live (see evidence).

## Provision

Secrets stay in the operator environment: `GUAC_ADMIN_PASSWORD` (16+ chars), `ATTACKER_RDP_PASSWORD`.

1. Node, as root: regenerate bridges (`scripts/netpolicy.py bridges`, `scripts/bootstrap-bridges.sh`), then `BRIDGES="... vmbr2002" scripts/bootstrap-proxmox.sh` (new pool `lab-gateway` and token; no other token is re-issued), then `scripts/make-gateway-template.sh`.
2. Firewall: the seed gains a sixth NIC. A running firewall does not pick it up: rebuild it (`scripts/make-firewall-template.sh`, then `scripts/lab.sh apply firewall`), or add the interface in the GUI. Then `labmode.py` applies the new rules; re-verify (step 7).
3. Workstation: `export PROXMOX_VE_API_TOKEN_GATEWAY=...`, `TF_VAR_node_name`, `TF_VAR_ssh_public_key`; `scripts/lab.sh apply gateway`.
4. `labmode.py maintenance --minutes 30 --reason "gateway packages"`. Then, with `ATTACKER_RDP_PASSWORD` exported: `ansible-playbook playbooks/gateway.yml` and `playbooks/attacker.yml`. This fetches the gateway's target key pair to `secrets/gateway/` (gitignored). Back to `labmode.py exercise t1`.
5. Targets: re-run `scripts/target.sh provision t1` (maintenance mode) so the target authorises the gateway key. A rebuilt target gets it automatically while `secrets/gateway/targets_ed25519.pub` exists.
6. `scripts/guacctl.py bootstrap` replaces the default `guacadmin` password and creates the connections (`attacker` RDP, `t1` SSH). Then `scripts/guacctl.py check` must pass.
7. A2: `scripts/a2-verify.sh exercise t1 lab|vpn|home` and `maintenance none ...`. The gateway rows run from the gateway VM over SSH; `SKIP_SOURCES` is unnecessary.

## TOTP enrolment

Single operator account (`guacadmin`), local DB auth plus TOTP, no IdP.

1. Browse to `https://10.77.2.10/` over the VPN (self-signed certificate; the VPN is the trust boundary, accept it once).
2. Log in as `guacadmin` with `GUAC_ADMIN_PASSWORD`. Guacamole shows a QR code: scan it with an authenticator app and enter the code to finish enrolment. Later logins always ask for the code.
3. `scripts/guacctl.py check` should still pass (a login without a code is refused).

Enrol straight after provisioning: until then the account has a password and no second factor, reachable only over the VPN.

## Add a connection

Add the host to `connections()` in `scripts/guacctl.py` (and a firewall flow and probe in `netpolicy.py`/`plan.json` first, or the connection will not connect), then `scripts/guacctl.py connections`. Do not click connections together in the UI for targets: they would not be reproducible. A target with no VM (t2 today) is skipped.

## Recovery

- **Lost TOTP device:** on the gateway, `sudo docker-compose -f /opt/guacamole/compose.yml exec -T postgres psql -U guacamole -d guacamole -c "DELETE FROM guacamole_user_attribute WHERE attribute_name LIKE 'guac-totp%' AND user_id=(SELECT user_id FROM guacamole_user u JOIN guacamole_entity e USING(entity_id) WHERE e.name='guacadmin');"`, then enrol again at next login.
- **Lost admin password:** export a new `GUAC_ADMIN_PASSWORD`, run `scripts/guacctl.py bootstrap` (it overwrites the stored hash).
- **Broken gateway:** it holds no state worth keeping beyond the secrets above. Destroy and re-apply the gateway stack, re-run both playbooks and `guacctl.py bootstrap`; TOTP is enrolled again. The target key pair is regenerated, so re-provision targets afterwards.
- **Target rebuilt:** its host key changes; Guacamole does not pin SSH host keys here, so nothing to clear.
- **Rotating the RDP password:** change `ATTACKER_RDP_PASSWORD`, re-run the attacker playbook and `guacctl.py connections`.

## Done-when evidence (live run 2026-10-30)

| Done when | Evidence | Result |
| --- | --- | --- |
| Reachable only through the VPN, not from the home LAN | A2 `p53` (operator to gateway:443) allow in both modes; `https://10.77.2.10/` answers 200 through the proxy. Home phase, exercise mode, with a host route for `10.77.2.10/32` via the firewall WAN: `p55` (workstation to gateway:443) and `p72` (to gateway:22) both deny, each logged by the firewall (`a2-verify.sh`, `ONLY_DST=gateway`, 2 rows, 0 skipped, **PASS**) | **passed** |
| TOTP required, default password gone | `scripts/guacctl.py check`: "default password gone, TOTP demanded". The check caught that `EXTENSIONS=auth-totp` loaded nothing; `TOTP_ENABLED=true` fixed it | passed; enrolment happens at the operator's first login |
| RDP to the attacker desktop from the browser | gateway to attacker:3389 allowed (`p59`); the operator logged in to the XFCE desktop from the browser. The first attempt failed with "X server could not be started" until `xorgxrdp` was added to the attacker role | **passed** (operator-confirmed) |
| SSH terminal to each target from the browser | the gateway key logs in to t1 as `opaleye`; the operator opened the `t1` terminal from the browser. t2 has no VM | **passed** (operator-confirmed) |
| A2 covers the new flows, both modes | `scripts/a2-verify.sh` lab phase: exercise none, exercise t1 and maintenance, 55 rows each, 0 skipped, **PASS** (gateway rows `p53`-`p71` included; t2 probed with a throwaway probe guest, since removed) | passed |
| `netpolicy.py lint` and `tests/static-checks.sh` | lint passes; the suite has the same 32 Windows-only failures as before this change | passed |

The VPN phase reports FAIL on two older rows only (`proxmox:8006`, `internet:443`): they cannot be sourced from WSL, which has a direct LAN route. Every gateway and operator row in that phase passes.

## Live-run notes

- The firewall VM needs a **sixth NIC**: rebuild template 2101 from the new seed (`opnsense_seed.py iso`), then `tofu apply -replace` the firewall. On the node, grant the new bridge to every stack token that needs it: `pveum acl modify /sdn/zones/localnetwork/vmbr2002 --tokens '<user>!deploy' --roles OpaleyeNet`. Privilege-separated tokens need their own ACL, and in an interactive shell run `set +H` first or `!deploy` is history-expanded.
- ICMP to the firewall is blocked by design, so ping is not a VPN health check: test TCP 443 on `10.77.9.1`.
- Run Ansible and the scripts from a WSL-native checkout: CRLF line endings on a Windows checkout break shell tasks.
- `labmode.py exercise <target>` refuses to leave maintenance until denies are re-verified: `labmode.py exercise none`, then `REVERIFY=1 scripts/a2-verify.sh exercise none lab`, then `labmode.py select t1`.
- `labops.py startup` and `shutdown` now include the gateway, so they report an error for it until the gateway stack is applied.

## Known gaps

- Between the gateway playbook and `guacctl.py bootstrap` the schema's default `guacadmin`/`guacadmin` login exists (VPN-reachable only). Run bootstrap straight after the playbook.
- The target SSH key and the RDP password are stored in plaintext in the gateway's Postgres (inherent to Guacamole connection parameters). Acceptable for a lab behind the VPN; rebuild the gateway to rotate.
- Debian's `docker-compose` v1 is used, as on the targets; if a recreate fails with `KeyError: 'ContainerConfig'`, `docker-compose down` then `up -d`.
