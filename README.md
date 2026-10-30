# Opaleye: an attack and detection lab

A self-contained lab on one Proxmox host for running **manual attacks against deliberately vulnerable targets** and **hunting them in Elastic**, with every network path forced through a firewall VM. The operator reaches everything over a WireGuard VPN, and the whole lab is built and rebuilt from code in this repository.

- **Attack:** from an attacker VM, run an exercise against the selected target (today DVWA).
- **Detect:** the target ships process, network, file, auditd, Docker, Apache and firewall-flow telemetry to Elastic, tagged per exercise.
- **Reset:** a target is destroyed and rebuilt from pinned inputs after its telemetry is confirmed drained; evidence survives.
- **Contain:** exercise mode denies attacker and target Internet egress; maintenance mode opens a time-limited update allowlist.

Terms (Target, Exercise mode, Maintenance mode, Admin path, Gateway VM and so on) are defined in [GLOSSARY.md](GLOSSARY.md). The reasoning behind the design is in [docs/](docs/README.md).

## Contents

1. [Architecture](#architecture)
2. [Using the lab](#using-the-lab) (daily guide)
3. [Command reference](#command-reference)
4. [Building the lab from scratch](#building-the-lab-from-scratch)
5. [Safety rules](#safety-rules)
6. [Troubleshooting](#troubleshooting)
7. [Repository layout](#repository-layout)
8. [Status and documentation](#status-and-documentation)

## Architecture

```text
 operator workstation ── WireGuard (UDP 51820) ──┐
 (home LAN 192.168.0.223)                        │
                                          ┌──────▼───────┐
 home LAN 192.168.0.0/24 ── WAN ──────────┤ firewall VM  │  OPNsense CE, the only lab guest on the home bridge
 (Proxmox 192.168.0.161)                  │   VM 2000    │  default-deny IPv4, IPv6 off, flow logs to Elastic
                                          └─┬──┬──┬──┬──┬┘
        isolated bridges, no host port      │  │  │  │  └─ gateway zone  10.77.2.0/24   Guacamole gateway VM 2002
                                            │  │  │  └──── t2 zone       10.77.12.0/24  (reserved, no VM yet)
                                            │  │  └─────── t1 zone       10.77.11.0/24  target t1 (DVWA) VM 2011
                                            │  └────────── elastic zone  10.77.3.0/24   Elastic VM 2003
                                            └───────────── attacker zone 10.77.1.0/24   attacker VM 2001
```

Every inter-zone path crosses the firewall VM. The Proxmox host is never on a lab path. The VPN subnet is `10.77.9.0/24`.

| Guest | VMID | Address | What it is | How you reach it |
| --- | --- | --- | --- | --- |
| Firewall | 2000 | `10.77.9.1` (VPN side) | OPNsense CE 26.7, WireGuard, DNS/NTP, flow logs | `https://10.77.9.1` (GUI/API, VPN only) |
| Attacker | 2001 | `10.77.1.10` | Debian, attack tooling, XFCE desktop (xrdp) | `ssh opaleye@10.77.1.10` or the Guacamole desktop |
| Gateway | 2002 | `10.77.2.10` | Apache Guacamole (TOTP), browser GUI/terminals | `https://10.77.2.10/` (VPN only) |
| Elastic | 2003 | `10.77.3.10` | Elasticsearch, Kibana, Fleet Server (9.5.5, Basic) | `https://10.77.3.10:5601` (VPN only) |
| Target t1 | 2011 | `10.77.11.10` | Debian, Docker, DVWA + MariaDB, Elastic Agent with Defend | `ssh opaleye@10.77.11.10`; DVWA on port 80 from the attacker only |

Who may talk to whom (full contract: `network/plan.json`, rendered by `scripts/netpolicy.py`):

- **Operator (VPN)** to firewall GUI `443`; attacker, gateway, Elastic and t1 over SSH `22`; Kibana `5601`; gateway `443`. Not to DVWA directly, not to Elasticsearch `9200` or Fleet `8220` (use the SSH tunnel), not to Proxmox.
- **Attacker** to the **selected** target's exercise port (`80`) in exercise mode only. Nothing else: no other target, no Elastic, no Internet.
- **Targets** to Elastic ingestion (`9200`, `8220`) and lab DNS/NTP only. Never to each other, the admin path, Proxmox, home networks or the Internet.
- **Gateway** to the attacker (RDP `3389`) and targets (SSH `22`) only. The firewall VM and Elastic are not brokered; they keep their direct VPN routes.
- **Maintenance mode** additionally lets the attacker, targets and gateway reach the reviewed update sources on `80`/`443`, for a limited time, and closes every attacker-to-target flow.

## Using the lab

This guide is the day-to-day path. Commands run on the **operator workstation** (Linux or WSL; the scripts need LF line endings) from the repository root, with the VPN up.

### 0. One-time workstation setup

1. A WireGuard client config for this lab:

   ```ini
   [Interface]
   PrivateKey = <your client private key>
   Address = 10.77.9.2/32

   [Peer]
   PublicKey = <firewall public key>
   Endpoint = 192.168.0.82:51820
   AllowedIPs = 10.77.0.0/16
   PersistentKeepalive = 25
   ```

   The firewall only accepts the handshake from the workstation's address (`192.168.0.223`). Keys come from the operator secrets store, never the repo.
2. An environment file outside version control (the repo ignores `secrets/` and `.state/`) holding, at minimum: `OPALEYE_STATE_PASSPHRASE`, `PROXMOX_VE_ENDPOINT`, `PROXMOX_VE_INSECURE`, `PVE_NODE`, `TF_VAR_node_name`, `TF_VAR_ssh_public_key`, one `PROXMOX_VE_API_TOKEN_<STACK>` per stack (`FIREWALL`, `ELASTIC`, `TARGETS`, `ATTACKER`, `GATEWAY`), `OPNSENSE_URL`, `OPNSENSE_INSECURE`, `OPNSENSE_API_KEY`, `OPNSENSE_API_SECRET`, `ELASTIC_PASSWORD`, `GUAC_ADMIN_PASSWORD`, `ATTACKER_RDP_PASSWORD`. Load it with `set -a; . path/to/env.sh; set +a`.
3. Tools: `python3`, `tofu` (OpenTofu), `ansible` (with `ansible-galaxy collection install -r ansible/requirements.yml`), `ssh`, `curl`. Your SSH key must be the one given to Tofu as `TF_VAR_ssh_public_key`.

### 1. Connect

1. Activate the WireGuard tunnel.
2. Check it with **TCP**, not ping: `curl -sk -o /dev/null -w '%{http_code}\n' https://10.77.9.1/` (any HTTP code means the tunnel works). The firewall drops ICMP by design.

### 2. Start the lab (if it is powered off)

```bash
python3 scripts/labops.py startup --include-elastic     # firewall first, then Elastic, targets, attacker, gateway
python3 scripts/labmode.py status                        # mode, selected target, expiry
```

`startup` only powers guests on through the Proxmox API; it rebuilds nothing. If the mode is `exercise` with a target selected, you are ready. After a firewall rebuild or a maintenance window, see [Switching modes](#switching-modes-and-selecting-a-target).

### 3. Get to your tools

| You want | Do this |
| --- | --- |
| **Attacker desktop** (browser attacks, GUI tools) | Browse to `https://10.77.2.10/` (accept the self-signed certificate), log in as `guacadmin` with `GUAC_ADMIN_PASSWORD` plus your TOTP code, open **attacker**. |
| **Target terminal** | Same Guacamole page, open **t1**. |
| **Attacker shell** | `ssh opaleye@10.77.1.10` |
| **Hunt in Kibana** | `https://10.77.3.10:5601`, user `elastic`, password in `secrets/elastic/elastic.password` (trust `secrets/elastic/ca/ca.crt`). |
| **Firewall** | `https://10.77.9.1` (GUI). Day-to-day changes go through `labmode.py`, not the GUI. |
| **Elasticsearch/Fleet API from the workstation** | `scripts/elastic-tunnel.sh` in a second terminal (forwards `19200`/`18220`). `labops.py` and the Ansible API tasks need it. |

First Guacamole login (once): scan the QR code with an authenticator app. See [the gateway runbook](docs/runbooks/guacamole-gateway.md) for enrolment, adding a connection and recovery.

### 4. Run an exercise

Exercise 1 is command injection in DVWA's `low` security page, leading to a shell process on the target. It produces an Apache request, a process chain (web worker, shell, child) and a network event.

1. Select the target and open the tunnel (`scripts/elastic-tunnel.sh`).
2. Start the exercise. This writes a marker event that tags the run:

   ```bash
   python3 scripts/labops.py exercise start ex-001 --target t1
   ```

   It refuses unless the firewall is in exercise mode with that target selected, Elastic answers, and the disk is below the watermark.
3. Attack. Either run the scripted version on the attacker, or attack by hand from the attacker desktop (DVWA is at `http://10.77.11.10/`, login `admin` / `password`, security `low`, page **Command Injection**):

   ```bash
   ssh opaleye@10.77.1.10 exercise1 --exercise-id ex-001 --target t1
   ```

4. End it. This writes the end marker and stamps `lab.exercise_id` on that target's events in the window:

   ```bash
   python3 scripts/labops.py exercise end
   python3 scripts/labops.py exercise show ex-001     # the time window and target
   python3 scripts/labops.py exercise tag ex-001      # optional: events still in transit at the end
   ```

5. Hunt in Kibana inside the window, from either side: process to request (a shell child of the web worker, then the matching `POST /vulnerabilities/exec/`), or request to process. Useful data views: `logs-endpoint.events.process-*`, `logs-endpoint.events.network-*`, `logs-apache.access-*`, `logs-auditd_manager.auditd-*`, `logs-lab_firewall.flow-*`. Filter by `lab.exercise_id`, `lab.target_id` and `lab.rebuild_generation`.

The exercise's callback to the attacker (`:4444`) is blocked by design; the attempt shows up as a network event and as firewall flow blocks.

### 5. Reset the target

A reset rebuilds the target VM from pinned inputs. Evidence in Elastic is kept; the attacker VM, firewall and Elastic are untouched.

```bash
python3 scripts/labops.py drain t1                                   # confirms telemetry has shipped
python3 scripts/labmode.py maintenance --minutes 60 --reason "target reset"
python3 scripts/labops.py reset t1                                   # drain check, bump generation, rebuild
python3 scripts/labmode.py exercise none                             # leave maintenance mode
REVERIFY=1 scripts/a2-verify.sh exercise none lab                    # prove the denies again (see below)
python3 scripts/labmode.py select t1
python3 scripts/labops.py attacker-clean                             # clear attacker-side exercise files
```

If the drain check fails (Elastic down, forwarding behind), the reset is refused unless you accept the loss: `--acknowledge-loss "reason"`. A reset is also refused during an active exercise on that target.

### Switching modes and selecting a target

| Command | Effect |
| --- | --- |
| `labmode.py status` | Current mode, selected target, maintenance expiry, whether denies need re-verifying. |
| `labmode.py exercise none` | Exercise mode, no target reachable from the attacker. |
| `labmode.py select t1` | Allow the attacker to reach `t1:80` (exercise mode only). |
| `labmode.py maintenance --minutes N --reason "text"` | Time-limited update allowlist; closes every attacker-to-target flow. Expires on its own (a timer runs `labmode.py tick`). |

Leaving maintenance mode sets a flag: you cannot select a target again until the exercise-mode denies are **re-verified**. That is `REVERIFY=1 scripts/a2-verify.sh exercise none lab`, a full unfiltered probe run from the lab zones (it needs probe guests for any zone without a real VM, here `t2`; see the [M2 runbook](docs/runbooks/m2-firewall-and-networks.md) for probe setup). Every mode change goes pending, applied, then confirmed; if the confirmation never lands, a dead-man job on the firewall restores the last confirmed config.

### 6. Update packages and images (maintenance)

Package installs and image pulls (attacker tooling, target rebuilds, gateway images) only work in maintenance mode:

```bash
python3 scripts/labmode.py maintenance --minutes 30 --reason "packages"
(cd ansible && ansible-playbook playbooks/attacker.yml)      # or gateway.yml, target.yml via scripts/target.sh
python3 scripts/labmode.py exercise none && REVERIFY=1 scripts/a2-verify.sh exercise none lab
python3 scripts/labmode.py select t1
```

Elastic never gets Internet access, even in maintenance mode; its packages are fetched on the workstation, checked against the pinned hashes in `network/plan.json`, and copied over.

### 7. Shut the lab down

```bash
python3 scripts/labops.py shutdown                         # drains running targets, graceful power-off; Elastic stays up
python3 scripts/labops.py shutdown --include-elastic       # graceful Elastic shutdown too
```

Nothing is destroyed. Shutdown is refused during an active exercise. If Elastic is down and a target has undrained events, you must pass `--acknowledge-loss "reason"`.

### 8. Delete evidence (rarely)

Only `scripts/evidence_delete.py` can remove ingested evidence, and nothing else can reach it. It is a dry run until you confirm:

```bash
python3 scripts/evidence_delete.py all                     # prints the cutoff and the exact confirmation phrase
python3 scripts/evidence_delete.py all --before "<T>" --confirm "<phrase>"
python3 scripts/evidence_delete.py exercise:ex-001         # one exercise
```

It is refused during an active exercise. Take an Elasticsearch snapshot first if you might want the data (`lab-daily` runs at 02:30).

### 9. Rebuild or change infrastructure

Each stack (`firewall`, `elastic`, `targets`, `attacker`, `gateway`) has its own Tofu state and Proxmox token:

```bash
scripts/lab.sh plan <stack>        # init | plan | apply | destroy
scripts/lab.sh apply all           # ordered; `destroy all` never touches Elastic
```

Do not hand-repair a compromised or broken target; rebuild it (`labops.py reset t1`). Re-running an apply is always safe. Changing the network plan (`network/plan.json`) needs the seed regenerated (`python3 scripts/opnsense_seed.py template > network/opnsense-seed.xml`) and, for a new zone or NIC, a firewall template rebuild: see the runbooks.

## Command reference

| Command | Purpose |
| --- | --- |
| `scripts/lab.sh <init\|plan\|apply\|destroy> <stack\|all>` | Ordered Tofu runner (state encrypted with `OPALEYE_STATE_PASSPHRASE`). Refuses to destroy Elastic. |
| `scripts/labmode.py` | Exercise/maintenance mode, target selection, dead-man arm/confirm. |
| `scripts/labops.py` | `exercise start/end/tag/show`, `drain`, `reset`, `attacker-clean`, `shutdown`, `startup`, `watermark`, `status`. |
| `scripts/target.sh <provision\|bump\|generation> <t>` | Target VM provisioning and rebuild generation (used by `labops.py reset`). |
| `scripts/evidence_delete.py` | The only evidence deletion command. |
| `scripts/guacctl.py <bootstrap\|connections\|check>` | Guacamole admin password, connections, TOTP check. |
| `scripts/fleetctl.py` | Fleet policies, enrolment tokens, ingest-lag rule for targets. |
| `scripts/elastic-tunnel.sh` | SSH tunnel for the Elasticsearch/Fleet APIs. |
| `scripts/netpolicy.py` | Renders and lints the firewall policy from `network/plan.json` (`check`, `lint`, `matrix`, `rules`, `bridges`). |
| `scripts/a2-verify.sh`, `a3-verify.sh`, `a4-verify.sh`, `a5-verify.sh`, `a10_measure.py` | Acceptance checks A2-A5 and measurement A10 (see [acceptance checks](docs/decisions/acceptance-checks-and-build-plan.md)). |
| `tests/static-checks.sh` | Offline guards: layout, state encryption, no secrets, policy lint, plan sanity. |

## Building the lab from scratch

The lab is code. A full rebuild follows the milestone runbooks in order, each with its own acceptance check; the from-scratch run is recorded in the [M6 runbook](docs/runbooks/m6-end-to-end-validation.md).

1. **Site facts and authority:** [`docs/inventory/site-inventory.md`](docs/inventory/site-inventory.md).
2. **Node bootstrap (root, on the Proxmox node):** `scripts/bootstrap-bridges.sh` (lab bridges, outside the Ludus blocks), then `scripts/bootstrap-proxmox.sh` (pools, role, one privilege-separated token per stack; secrets print once), then the template builders (`make-*-template.sh`).
3. **Stacks in order:** `firewall`, `elastic`, `targets`, `attacker`, `gateway` with `scripts/lab.sh apply`, then each stack's Ansible play (Elastic, evidence pipelines, target, attacker, gateway) and `scripts/guacctl.py bootstrap`.
4. **Firewall first boot:** the OPNsense config is generated from `network/plan.json` as a seed, baked into a template and cloned, with no console or GUI step: [M2 runbook](docs/runbooks/m2-firewall-and-networks.md).
5. **Verify:** `scripts/a2-verify.sh` (isolation and egress, A2 is a hard gate before any vulnerable target runs), then A3-A5, then the exercise.

## Safety rules

- **Vulnerable targets are reachable only from the selected exercise path.** Never add a route, port mapping or NIC that bypasses the firewall VM. `scripts/nicaudit.py` checks that no guest has a second lab NIC or a home-bridge NIC.
- **No secrets in the repo.** Tokens, keys, passwords and the Elastic CA live in the operator environment and `secrets/`. `tests/static-checks.sh` scans for them.
- **Exercise mode is the resting state.** Use maintenance mode only for updates, only for as long as needed, and re-verify the denies afterwards.
- **Evidence has one deletion path** and it asks for confirmation. Resets and shutdowns cannot delete it.
- **The Proxmox host is not part of the lab.** It shares a home network and hosts unrelated guests. No lab guest can reach it (probes `p06`, `p07`, `p13`, `p29`, `p36`, `p66`).
- DVWA is deliberately vulnerable. Treat the target as compromised after every exercise.

## Troubleshooting

| Symptom | Likely cause and fix |
| --- | --- |
| Tunnel is "up" but nothing answers | You pinged. ICMP is blocked; test TCP `443` on `10.77.9.1`. After a firewall rebuild, deactivate and reactivate the tunnel. |
| `labmode.py exercise t1` says denies are not re-verified | Leaving maintenance sets a flag. Run `labmode.py exercise none`, `REVERIFY=1 scripts/a2-verify.sh exercise none lab`, then `labmode.py select t1`. |
| `labmode.py maintenance` says already in maintenance | Wait for expiry or run `labmode.py exercise none`. |
| Package install or image pull times out | You are in exercise mode; enter maintenance mode. A transient CDN address change is retried by the roles; re-run the play. |
| `labops.py` cannot reach Elasticsearch | The tunnel (`scripts/elastic-tunnel.sh`) is not running. |
| `exercise start` refused | Not in exercise mode with that target selected, Elastic down, or disk above the watermark (`labops.py watermark`). |
| `reset` refused | Not in maintenance mode, active exercise on that target, Elastic unreachable, or drain failed (`--acknowledge-loss` to accept the loss). |
| Guacamole login does nothing after the password | TOTP is required; enter the code from your authenticator. Lost it: see the gateway runbook's recovery section. |
| Guacamole RDP says "X server could not be started" | `xorgxrdp` missing on the attacker; re-run `playbooks/attacker.yml` in maintenance mode. |
| `tofu` says backend initialisation is required | In a fresh checkout run `scripts/lab.sh init <stack>`. |
| Scripts fail with `\r` errors | CRLF line endings from a Windows checkout; run from WSL or a Linux clone. |
| Rebuilt firewall: Proxmox 403 on a new bridge | Privilege-separated tokens need their own `SDN.Use` ACL on the bridge; see the gateway runbook's live-run notes. |

## Repository layout

| Path | Contents |
| --- | --- |
| `network/plan.json` | Single source of truth: zones, addresses, VM ids, flows' services, probes, pinned versions and digests. |
| `network/opnsense-seed.xml` | Secret-free firewall config seed generated from the plan. |
| `tofu/stacks/{firewall,elastic,targets,attacker,gateway}` | One OpenTofu stack each: own encrypted state, pool and token. |
| `ansible/` | In-guest configuration: roles `elastic`, `target`, `attacker`, `gateway`; playbooks per guest. Never targets the Proxmox node. |
| `scripts/` | Operator commands, verifiers, node bootstrap and template builders, firewall helpers. |
| `tests/` | Unit tests with fakes (Proxmox, Elastic, OPNsense) and `static-checks.sh`. |
| `docs/` | [Index](docs/README.md): ADRs, decisions, research, site inventory, milestone runbooks. |
| `GLOSSARY.md` | The lab's vocabulary. |
| `secrets/`, `.state/` | Gitignored: secrets, encrypted Tofu state, evidence files. |

Run the offline tests with `python3 -m unittest discover -s tests` and `bash tests/static-checks.sh`. A few tests that call shell scripts fail on a Windows checkout; use Linux or WSL.

## Status and documentation

Everything below was built and validated live on the real host; per-check evidence is in the runbooks.

| Milestone | What | Issue | Runbook |
| --- | --- | --- | --- |
| M0 | Site inventory and authority | #19 | [site inventory](docs/inventory/site-inventory.md) |
| M1 | Foundations: stacks, encrypted state, scoped tokens | #20 | [M1](docs/runbooks/m1-foundations.md) |
| M2 | Firewall VM, zones, VPN, modes, flow logs; config as code and hands-off rebuild | #21, #31, #41, #42 | [M2](docs/runbooks/m2-firewall-and-networks.md) |
| M3 | Elastic VM, Fleet, lab CA, retention, snapshots | #22 | [M3](docs/runbooks/m3-elastic.md) |
| M4 | Target VM with DVWA and evidence arrival | #23 | [M4](docs/runbooks/m4-target.md) |
| M5 | Attacker VM and operator commands | #24 | [M5](docs/runbooks/m5-attacker-operator.md) |
| M6 | End-to-end validation (A6-A10), from-scratch rebuild | #25 | [M6](docs/runbooks/m6-end-to-end-validation.md) |
| Gateway | Guacamole gateway: browser GUI and terminals, TOTP | #51 | [gateway](docs/runbooks/guacamole-gateway.md) |

Known open items: the A2 VPN-path-loss script was not re-run on the rebuilt firewall; Exercise 2 (file upload) needs a research pass; `t2` is reserved but has no VM; the malware-analysis zone that builds on the gateway is a follow-up. The measured storage cost (about 0.6 GB per idle day, about 2 MB per Exercise 1 run) is in the M6 runbook (A10).
