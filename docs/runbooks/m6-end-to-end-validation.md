# M6 End-to-end validation runbook

Issue #25. Exit = checks A6-A10 in [acceptance checks](../decisions/acceptance-checks-and-build-plan.md). Design: [operator commands and target interface](../decisions/operator-commands-and-target-interface.md).

**Status (2026-10-30): run from scratch. A6-A10 evidence is recorded; one optional re-run remains (see Open).** The whole lab was wiped and rebuilt from code with newly generated secrets, then A6-A10 were run against it. The remaining open items are listed under "Open" (A10's idle day was waived by Adam, see A10). Nothing below used the earlier lab, its Tofu state or its secrets.

## From-scratch rebuild

| Step | Where | Result |
| --- | --- | --- |
| Wipe old lab: VMs 2000/2001/2003/2011/2012, templates 2100/2101/2300-2302, `lab-*` pools, `opaleye-*@pve` users, roles, lab bridges | node, root (one-off script, dry run first) | done; Ludus VMs, `vmbr0` and uploaded images untouched |
| New secrets: state passphrase, OPNsense API key/secret/root password, WireGuard server and client keys, Elastic password | workstation, gitignored `env.sh.new` | generated, none reused |
| `bootstrap-bridges.sh`, `bootstrap-proxmox.sh` (new tokens) | node, root | done |
| Debian templates 2300, 2301, 2302 (`make-*-template.sh`) | node, root | done |
| Seed ISO + nano image, dead-man bake on a FreeBSD host (OPNsense live ISO, throwaway VM 9001, deleted afterwards), `make-firewall-template.sh` (2101) | workstation + node | done; baked disk checksum matched end to end |
| `lab.sh apply` firewall, elastic, targets, attacker; `labmode.py arm`, `exercise none`, `opnsense_dns.py --apply` (second run: no changes) | workstation (WSL) | done |
| `playbooks/elastic.yml`, `elastic-evidence.yml`, `target.sh provision t1`, `playbooks/attacker.yml` | workstation (WSL) | done (ok=52 / 13 / 28 / 6, failed=0) |

Prerequisite checks on the new lab: A3 services **27/27 PASS** (after the failure-store fix below), A5 **PASS**, A2 lab exercise (no target and t1 selected), maintenance and fail-closed **PASS**, 39 rows, 0 skipped. A4 **PASS-WITH-SKIPS** (16 rows; 3 manual rows skipped; the ingest-lag row passed once the t1 start-up backlog drained).

Probe guests share the real VMs' addresses, so every full re-verification (the flag only clears on an unfiltered, unskipped `exercise/lab` run) was done by gracefully powering off the real attacker, t1 and Elastic, creating probes, verifying, destroying the probes and starting the real VMs again.

## A2 `vpn` and `home` phases on the rebuilt firewall

Run after the A9 teardown, on the freshly rebuilt firewall (exercise mode, t1 selected). Probe guests in attacker, t1 and t2 (the real Elastic VM owns its address). `vpn`: Windows tunnel `AllowedIPs` temporarily `10.77.0.0/16, 192.168.0.161/32, 1.1.1.1/32`, restored afterwards. `home`: aliases `192.168.0.50`, `203.0.113.55` and host routes to the lab addresses via the firewall WAN `192.168.0.82`, removed afterwards. Probes destroyed afterwards.

| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| operator | attacker:22, elastic:22, elastic:5601, t1:22, fw:443 | exercise | allow | allow (5 rows) | firewall:opt4 |
| operator | t1:80, proxmox:8006, internet:443, elastic:9200, elastic:8220 | exercise | deny, logged | deny, deny logged: yes (5 rows) | firewall:opt4 |
| operator | fw:0 (ICMP) | exercise | deny | deny | firewall:opt4 |
| workstation | fw:51820 | exercise | allow | allow | firewall:wan |
| workstation | fw:443, t1:80, attacker:22, elastic:5601 | exercise | deny, logged | deny, deny logged: yes (4 rows) | firewall:wan |
| home_other | fw:51820 | exercise | deny, logged | deny, deny logged: yes | firewall:wan |
| public | t1:80 | exercise | deny, logged | deny, deny logged: yes | firewall:wan |
| workstation | fw:0 (ICMP) | exercise | deny | deny | firewall:wan |

`phase=vpn` 11 rows, 0 skipped, **PASS**; `phase=home` 8 rows, 0 skipped, **PASS**. Not re-run: `a2-vpn-loss.sh` (VPN path loss, needs root route changes), recorded in the M2 runbook.

## A6 Manual hunt exercise

Exercise **`ex-a6d`** on t1, generation 4 (attacker script `exercise1`, DVWA `low`), 2026-10-30, window 15:54:39Z to 15:55:17Z. Evidence counts read from Elasticsearch through the API; the hunt itself was done by Adam in Kibana (reported, no screenshots kept). `ex-002` (generation 1) and `ex-a6c` were earlier runs; `ex-a6c` ran before Defend had settled after t1's reboot and is not used.

| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| operator | exercise start/end markers | exercise | marker pair with `lab.exercise_id` | `exercise-start` 15:54:39.9Z, `exercise-end` 15:55:17.5Z, `ex-a6d`, t1 gen 4 | labops.py |
| attacker | t1:80 `/vulnerabilities/exec/` | exercise | HTTP 200, injected output | `command_output_seen: true`; 1 `POST /vulnerabilities/exec/` in Elastic, `user_agent.original=opaleye-exercise1/ex-a6d`, `lab.target_id=t1` | firewall allow, DVWA, Filestream |
| t1 | process parent->shell->child, container attribution | exercise | present | Defend: `dash` -> `ping` (15:54:39.5Z), `dash` -> `timeout` and `dash` -> `id` (15:54:42.6Z), `entry_meta.type=container`; auditd: 109 events with `container.name` | Defend, auditd |
| t1 | attacker:4444 outbound attempt | exercise | network event, blocked | 1 Defend network event to :4444; 5 firewall flow `block` events | Defend, firewall flow log |
| operator | hunt process -> request, Kibana only | exercise | within the window | **matched** (Adam): `dash` children and their command line in `logs-endpoint.events.process-*`, then the `POST /vulnerabilities/exec/` in `logs-apache.access-*` | Kibana |
| operator | hunt request -> process, Kibana only | exercise | within the window | **matched** (Adam): from the POST, the same `ping`/`timeout`/`id` events within +/-3 s | Kibana |
| operator | #7 limitations | n/a | recorded | unchanged from the [M5 runbook](m5-attacker-operator.md#7-limitations-as-observed-in-this-run); only `low` was run | this file |

**Defend needs a settling period after the VM boots.** On `ex-a6c`, about 5 minutes after t1 rebooted, Defend shipped almost no process events (2 documents in 15:44-15:46Z, against about 250 per 2 minutes later) and the injected chain was missing, while auditd and the firewall log were complete. The same exercise about 14 minutes after boot was complete. Wait about 10 minutes after any t1 start before an exercise, and check the chain with the process query before handing a window to a hunter.

## A7 Reset with evidence retained

| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| operator | `drain t1` | exercise | marker with matching generation arrives | `drained: marker ... generation 1 arrived in Elasticsearch` | labops.py, Elastic Agent |
| operator | `reset t1` | maintenance | only t1 rebuilt; generation 1 -> 2 | targets stack applied, generation 2, one new agent enrolled | labops.py, Tofu targets stack, Ansible |
| operator | provisioning interrupted | maintenance | converges by rebuild | the reset's provision failed on its own at generation 2 (Ansible config not exported); `target.sh provision t1` converged (ok=28) | target.sh |
| t1 | prior-exercise events after reset | exercise | searchable by `exercise_id` | `ex-002`: 3,620 events; generation 1 retained 18,324; generation 2 arriving 5,875 | Elastic |
| t1 | agents | exercise | one t1 agent, old one retired | one `opaleye-t1` agent (enrolled 13:10:56Z) plus the Fleet Server agent | Fleet |
| operator | reset with a failed drain | maintenance | refused without acknowledged loss | `refused: drain check failed; fix forwarding or accept the loss with --acknowledge-loss REASON` (new VM had no Apache log yet) | labops.py |

Not captured: process IDs of the firewall, attacker and Elastic VMs across the first reset. The reset only invokes the targets stack and the unit tests assert nothing else is addressed.

## A8 Outage and recovery

Elastic powered off gracefully for **300 s** while the attacker sent one request per 5 s (150 requests, `a8-outage/N`) to t1.

| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| attacker | t1:80, 150 requests across the outage | exercise | loss within tolerance, recorded | 150 sent, **150 indexed, 0 lost**, 0 duplicates (agent buffered, then shipped) | Elastic Agent |
| operator | `drain`, `shutdown`, `exercise start` during the outage | exercise | refused | all refused: `Elastic is not answering ... No exercise start, reset or shutdown during an outage` (`drain` returns not drained) | labops.py |
| operator | `reset t1` during the outage | maintenance | refused | refused with the same message; generation stayed 2 | labops.py |
| t1 | agent restart mid-stream, 20 requests | exercise | no duplicates | 20 sent, 20 distinct, 0 duplicated | Elastic Agent |
| operator | interrupted target provisioning | maintenance | converges by rebuild | `target.sh provision t1` ok=28; A5 PASS on re-run (the first A5 run right after enrolment failed on agent health, a start-up race) | target.sh |
| operator | interrupted Elastic apply (playbook killed after 60 s) | maintenance | recovers by re-apply | re-apply ok=43 failed=0; A3 services 27/27 PASS | Ansible |
| operator | high watermark | exercise | blocks new exercises | with `ops.high_watermark_pct` forced to 1% against a 5% disk: `refused: Elasticsearch disk at 5% (high watermark 1%): new exercises are blocked` | labops.py |

Not covered: an interrupted **firewall** apply (the re-apply is a no-op on a converged stack, so there was nothing to interrupt), and a Kibana alerting rule for the watermark (the Elastic VM's own agent does not ship filesystem metrics, so the alert is the Basic-license fallback from #9: `scripts/labops.py watermark`, run from cron every few minutes; exit 1 and an `ALERT` line at `ops.high_watermark_pct`, audited as `watermark-alert`; an Elastic outage is an error, never `ok`; proven live: `ok: Elasticsearch disk at 5% (high watermark 90%)` normally and `ALERT: ... (high watermark 1%)` with the limit forced to 1%). Example crontab line: `*/5 * * * * set -a; . ~/secrets/env.sh; set +a; cd <repo> && python3 scripts/labops.py watermark >> .state/watermark.log 2>&1`.

## A9 Shutdown, teardown, deletion

| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| operator | `shutdown --include-elastic` | exercise | drain, all guests off, nothing deleted | t1 drained, then attacker, t1, Elastic, firewall `stopped`; all four VMs still exist | labops.py, Proxmox API |
| operator | `startup --include-elastic` | exercise | service and evidence restored | all four `running`; SSH to Elastic, t1, attacker within 150 s; log docs 73,836 -> 78,557, docs tagged `lab.exercise_id` unchanged at 6,302; mode `exercise`/t1; A5 PASS; A3 27/27 PASS | firewall, Elastic Agent |
| operator | `lab.sh destroy all` | exercise | attacker, targets, firewall destroyed; Elastic untouched | destroyed in the order attacker (1), targets (3), firewall (1); Elastic VM 2003 kept PID 101235 and uptime | lab.sh, Tofu |
| operator | evidence after teardown (firewall rebuilt to reach it) | exercise | intact | docs 81,302 -> 81,366, tagged docs still 6,302; A3 services 27/27 PASS | Elastic |
| operator | `lab.sh destroy elastic` | exercise | refused | `refused: Elastic destroy is evidence deletion; use its guarded command (M3)` | lab.sh guard |
| operator | `evidence_delete.py all` | n/a | dry run lists, nothing deleted | per-stream counts and the exact `--before ... --confirm "..."` command printed; "nothing deleted" | evidence_delete.py |
| operator | `evidence_delete.py all --before T --confirm "wrong phrase"` | n/a | refused | `refused: confirmation must be exactly: DELETE EVIDENCE all up to ... (N documents)`; doc counts unchanged | evidence_delete.py |

Evidence deletion was **not** run to completion (it is the only destructive path and this milestone's goal is to keep the evidence). Its non-reachability from reset, shutdown and `lab.sh` is asserted by `tests/test_evidence_delete.py` and `tests/test_m5_plan.py`.

## A10 Measurement

`scripts/a10_measure.py snapshot LABEL` / `report A B [HOURS]` (tested in `tests/test_a10_measure.py`). **Recorded, non-blocking. Accepted by Adam on 2026-10-30 on the shorter run: no 24-hour idle day will be run.** Window: a **10-minute idle sample scaled to an hour, not a full idle day**, plus three Exercise 1 runs (`ex-101..103`, t1 generation 3). Store-size deltas go negative when Lucene merges segments, so size is estimated as new documents x average bytes per document; raw deltas are in `.state/a10/`.

Average bytes per document and exercise cost (three runs agree within about 10%):

| evidence class | avg bytes/doc | docs per run | est. KB per run |
| --- | --- | --- | --- |
| Defend process | 930-1,240 | 383-457 | 350-550 |
| Defend network | 810-1,000 | 29-32 | 25-28 |
| Defend file/other | 380-540 | 276-319 | 100-170 |
| auditd | 350-440 | 516-540 | 175-225 |
| Apache access | 1,800-1,970 | 4 | 7-8 |
| firewall flow | 510-660 | 33-35 | 16-22 |
| metrics (all classes) | 970-1,300 | 391-425 | 370-540 |
| agent logs | 320-430 | 26-31 | 10-11 |

Idle rate (target running, nothing exercised), per hour: Defend process ~5,850 docs (~6.7 MB), Defend file/other ~3,260 (~1.6 MB), auditd ~10,400 (~3.6 MB), firewall flow ~640 (~0.6 MB), metrics ~11,350 (~11.5 MB), agent logs ~4,640 (~2.1 MB); roughly **26 MB/h, about 0.6 GB/day** for one idle target. Docker and Apache error streams are activity-driven (0 idle).

Component CPU/RAM (point sample; CPU is the lifetime average of the process):

| component | RSS MB | CPU % |
| --- | --- | --- |
| Elasticsearch (heap 4 GB) | ~5,130 | ~31 |
| Kibana | ~1,100 | ~9 |
| Fleet Server component | ~47 | ~0.1 |
| Elastic Agent supervisor / otel collector | ~72 / ~350 | ~0.2 / ~0.3 |
| Defend (`elastic-endpoint`) on t1 | ~100 | ~1.3 |

Placeholders to replace in #9 from these numbers: ~0.6 GB/day idle plus ~2 MB per Exercise 1 run against a 100 GB data disk means retention is dominated by idle host telemetry, not exercises. The idle rate is a 10-minute extrapolation, so treat the daily figure as an estimate and revisit retention if real usage disagrees.

## Findings from this run (fixed in code unless noted)

1. **Failure-store indices kept a replica** (A3 yellow, 1 unassigned shard): the replica fix targeted data stream wildcards, not `.fs-*`. Fixed in `ansible/roles/elastic/tasks/lifecycle.yml`, applied by re-running `elastic-evidence.yml`. **Known limit:** the task only fixes `.fs-*` indices that exist when the playbook runs; a failure-store index created or rolled over later gets the default replica (the `@custom` replica setting did not reach it here) and turns A3 yellow until the playbook is re-run. A durable fix needs a template that reaches failure-store indices; not found yet.
2. **`lab.sh destroy all` destroyed nothing**: `sed "1!G;h;$!d"` in double quotes expanded `$!`. Fixed with single quotes plus `tests/test_elastic_plan.py::test_broad_destroy_runs_every_other_stack_in_reverse_order`.
3. **Environment, not code:** exporting `ELASTIC_PASSWORD` overrides the generated password file and gives HTTP 401 from `fleetctl`; export `ANSIBLE_CONFIG` before `target.sh provision` or Ansible cannot find the roles; the Elastic SSH tunnel dies whenever Elastic is power-cycled and must be restarted; `reset` can race the new VM's SSH (re-run `target.sh provision t1`, as its message says).
4. **After the fail-closed test the firewall had lost the selected-target rules** (attacker to t1:80 timed out until `labmode.py exercise t1` was pushed again), unlike the M2 record where the mode survived. Not root-caused; reconcile with `labmode.py exercise <target>` after any firewall restart.
5. **Maintenance-mode update sources are alias-refresh dependent**: the first t1 provision timed out on a rotating CDN address and passed on retry (known from M2).

6. **Attacker package install failed on a cold clone** (`No package matching 'jq'`, three tries) because the first `apt update` through the maintenance allowlist is ~28 MB and can fail on a rotating CDN address; passed once the cache was warm. The role now retries (`ansible/roles/attacker/tasks/main.yml`, guarded by a test).
7. **Script hygiene:** a retry loop that tests only for `failed=0` treats `unreachable=1` as success; require `unreachable=0 .* failed=0`. This bit the rebuild helper, not the repo code.

## Open (needs you or more time)

- **A2 VPN path loss** (`a2-vpn-loss.sh`, needs root) was not re-run on the rebuilt firewall; every other A2 phase was (lab, maintenance, fail-closed, `vpn`, `home`).
- Final lab state: all four guests running (attacker and t1 rebuilt for A6 after the A9 teardown), `exercise` mode, t1 selected, generation 4.
