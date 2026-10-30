# Guacamole gateway runbook

Issue #51. Part of #2; not part of M6. Foundation for the malware-analysis zone (follow-up issue).

**Status: code and offline checks only. Nothing here has run against the live firewall, Proxmox or the gateway.** Every Ansible, Tofu, Proxmox and Guacamole step is unverified against the real systems, and the "Done when" items below are open until a live run fills in the evidence table.

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

## Provision (live, not yet done)

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

## Done-when evidence (to fill from a live run)

| Done when | Evidence | Result |
| --- | --- | --- |
| Reachable only through the VPN, not from the home LAN | A2 `p53` allow, `p55` deny (home phase) | pending live run |
| TOTP required, default password gone | `guacctl.py check` | pending live run |
| RDP to the attacker desktop from the browser | manual | pending live run |
| SSH terminal to each target from the browser | manual (t1; t2 has no VM) | pending live run |
| A2 covers the new flows, both modes | `p53`-`p71` in exercise and maintenance | pending live run |
| `netpolicy.py lint` and `tests/static-checks.sh` | offline | lint passes; static checks pass except the Windows-only baseline failures (see PR) |

## Known gaps

- Between the gateway playbook and `guacctl.py bootstrap` the schema's default `guacadmin`/`guacadmin` login exists (VPN-reachable only). Run bootstrap straight after the playbook.
- The target SSH key and the RDP password are stored in plaintext in the gateway's Postgres (inherent to Guacamole connection parameters). Acceptable for a lab behind the VPN; rebuild the gateway to rotate.
- Debian's `docker-compose` v1 is used, as on the targets; if a recreate fails with `KeyError: 'ContainerConfig'`, `docker-compose down` then `up -d`.
