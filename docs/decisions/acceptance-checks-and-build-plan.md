# Acceptance checks and implementation handoff

Supports [Define acceptance checks and the implementation handoff](https://github.com/Adam-Goss/death-demos/issues/10). **Status: confirmed by Adam, 2026-10-27.** Consolidates, and links rather than duplicates, ADR 0001, [#6 flow contract](https://github.com/Adam-Goss/death-demos/issues/6), `first-targets-and-hunt-outcomes.md` (#7), `deployment-and-reset-lifecycle.md` (#8), `telemetry-contracts-and-budgets.md` (#9). This plans validation; it deploys nothing.

## Build milestones (dependency order)

| # | Milestone | Depends on | Exit = acceptance checks |
| --- | --- | --- | --- |
| M0 | **Site inventory and authority**: PVE version/firewall backend, `/etc/network/interfaces`, bridges/VLAN, router, IPv6 state, management path + recovery console, hardware (`pveversion`, `lscpu`, `free -h`, `pvesm status`), backup storage, authority to change shared networking. Pick image approach and pins. | none | A0 |
| M1 | **Foundations**: Tofu/Ansible repo layout, per-stack encrypted state, offline key, scoped Proxmox API token, pools. | M0 | A1 |
| M2 | **Firewall VM + networks**: isolated zones, VPN, NTP/DNS, flow logs, exercise/maintenance modes. | M1 | A2 |
| M3 | **Elastic VM** (own stack/pool, destroy guard): Stack, Fleet, TLS lab CA, lifecycle, snapshots. | M2 | A3 |
| M4 | **Target VM + DVWA**: pinned image, Compose, Agent enrol (Defend, auditd, logs), lab fields. | M3 | A4, A5 |
| M5 | **Attacker VM + operator commands**: exercise-ID/marker command, drain marker, reset, shutdown, evidence deletion. | M4 | A6 |
| M6 | **End-to-end validation**: Exercise 1 hunt, reset, outage, recovery, teardown; measurements. | M5 | A6-A9 |

Each milestone is applied by re-runnable code; a failed target is rebuilt, never hand-repaired (#8).

## Acceptance checks

Record per check: source, destination/port, mode, expected, actual, enforcement point (#6 format). A check passes only with recorded evidence.

| ID | Area | Checks |
| --- | --- | --- |
| A0 | **Inventory** | All M0 facts recorded; allocatable resources ≥ #9 placeholders (else **reopen sizing**); change authority confirmed. |
| A1 | **Clean deploy foundations** | Fresh checkout + state key deploys stacks in order to known state. Re-apply is a no-op. Token cannot reach outside lab pools. No node SSH used. No secrets in repo/images. |
| A2 | **Isolation and egress** | #6 probe matrix for IPv4 **and** IPv6 in exercise mode: attacker→selected target works; target→target, target→Proxmox/home/Internet, attacker→mgmt/home/Internet, home/public→target all denied. Probe Docker-published ports from outside the VM, direct routing, alternate NICs. Denied flows appear in firewall logs. Firewall down fails closed; VPN loss opens no route. Maintenance mode: time-limited allowlist works, is logged, and exercise-mode denies are re-verified after return. |
| A3 | **Elastic and ingestion** | Single node healthy on pinned version/Basic license. Mgmt UI reachable only via VPN; ingestion ports only from lab systems. TLS with lab CA verified. Lifecycle (90d/14d) set per data stream. Daily snapshot to separate storage restores in a test. Destroy guard blocks target/firewall operations from addressing Elastic. |
| A4 | **Evidence arrival** | Target: Defend process+network, auditd, Docker and Apache logs, firewall flow logs all arrive tagged `lab.target_id` and `lab.rebuild_generation`. `@timestamp`/`event.created`/`event.ingested` distinct; ingest-lag alert fires >2 min (or documented Basic-license fallback). Verified: Apache POST body/query visibility and 1,024-byte Filestream fingerprint behaviour; Defend/auditd coexistence. |
| A5 | **Target fresh deploy** | DVWA from code reaches known state; enrol token injected at provision, not in image. |
| A6 | **Manual hunt exercise** | Operator sets `lab.exercise_id` (marker event written). From attacker VM, Exercise 1 (command injection, `low`) yields all three evidence types (Apache request, process parent→shell→child with container attribution, network event). Operator completes the hunt in both directions (process→request, request→process) using only Elastic, within the time window. Limitations in #7 recorded. |
| A7 | **Reset with evidence retained** | After A6: drain marker confirmed in ES with matching generation; reset rebuilds target only (firewall/attacker/Elastic untouched). DB, uploads, app files replaced; `rebuild_generation` increments; old agent/token retired; prior-exercise events still searchable by `exercise_id`. Failed drain refuses reset without acknowledged-loss override. |
| A8 | **Outage and recovery** | Elastic down 5 min then restored: loss within tolerance, recorded. Reset during outage refused by practice/check. Agent restart duplicate check. Interrupted target provisioning converges by rebuild. Interrupted firewall/Elastic apply recovers via re-apply then documented manual path, no auto-destroy. High watermark alerts and blocks new exercises. |
| A9 | **Shutdown, teardown, deletion** | Lab shutdown powers off all guests, deletes nothing; restart restores service and evidence. Teardown of target/firewall/attacker stacks leaves Elastic intact. Evidence deletion works only via its guarded, confirmed command, not reachable from reset/shutdown/broad destroy. |
| A10 | **Measurement** | One idle day + three Exercise 1 runs: record indexed bytes per evidence class, CPU/RAM of ES, Kibana, Fleet Server, Defend; replace placeholders; revisit retention. |

## Remaining decision gaps

Resolve at the named milestone, not now, unless Adam prefers otherwise.

| Gap | Resolve at | Note |
| --- | --- | --- |
| VPN technology; bridge/VLAN IDs, IP ranges | M0/M2 | Depends on inventory. |
| Image approach (cloud image + first boot vs Packer) and pin/checksum record | M0 | From #8. |
| Maintenance-mode update sources and initiators | M2 | From #6/#8. |
| Basic-license ability for ingest-lag alert and exercise block | M3 | Fallback: scheduled script/manual check. |
| Exact Proxmox role ACLs | M1 | After resource model. |
| Drain-check implementation (marker command + query) | M5 | Contract fixed in #9. |
| Exercise 2 (file upload) validation | After M6 | Research pass needed (#7). |
| Backup storage availability | M0 | If none, risk accepted explicitly (#9). |
| Elastic config/secrets backup mechanism | M3 | Offline key from #8. |
| Firewall product (OPNsense vs pfSense CE) | M2 | Recommended: OPNsense CE, pinned. See [research](../research/opnsense-vs-pfsense.md) (#26); confirm via A2. |

## Handoff rules (confirmed)

1. **Gating:** a milestone is not started until the prior one's checks pass with recorded evidence.
2. **A2 is a hard gate** before any vulnerable target is powered on.
3. **Definition of ready-to-use:** A0-A9 pass; A10 recorded but non-blocking.
4. **Handoff form:** one implementation issue per milestone (M0-M6), each linking its checks here.
