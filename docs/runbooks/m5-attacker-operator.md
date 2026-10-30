# M5 Attacker VM and operator commands runbook

Issue #24. Exit = check A6 in [acceptance checks](../decisions/acceptance-checks-and-build-plan.md). Design: [operator commands and target interface](../decisions/operator-commands-and-target-interface.md).

**Status: attacker stack and exercise run live; A6 evidence partly collected (see the A6 section). A6 is NOT passed.** Nothing here has run against the live firewall, Proxmox or Elastic: the VPN was unavailable, and neither A3 (M3) nor A4/A5 (M4, merged as code only) has been run live. M6 must not start, and #24 must not close, until the A6 tables below are filled in from a live run. Every Ansible/Tofu/Fleet/Proxmox call here is unverified against the real systems.

## What exists

| Piece | Where |
| --- | --- |
| Attacker VM (VMID 2001, `10.77.1.10`, pool `lab-attacker`, 2 vCPU / 4 GB) | `tofu/stacks/attacker`, template `scripts/make-attacker-template.sh` (VMID 2302) |
| Attacker config, Exercise 1 script | `ansible/playbooks/attacker.yml`, `ansible/roles/attacker` (`exercise1` on the VM) |
| Marker data stream template | `ansible/roles/elastic/tasks/markers.yml` (re-run the elastic playbook) |
| Exercise ID, drain, reset, shutdown/startup, attacker-clean | `scripts/labops.py` |
| Evidence deletion (separate on purpose) | `scripts/evidence_delete.py` |
| Offline tests (fakes for Elastic, Proxmox, DVWA; stub ssh/lab.sh/ansible) | `tests/test_labops.py`, `test_evidence_delete.py`, `test_exercise1.py`, `test_m5_plan.py` |

## Run (live, not yet done)

1. Node, as root: `BRIDGES="... vmbr2001" scripts/bootstrap-proxmox.sh` (creates pool `lab-attacker` and its token; **re-issue nothing else**), then `scripts/make-attacker-template.sh`.
2. Workstation: `export PROXMOX_VE_API_TOKEN_ATTACKER=...`, `TF_VAR_node_name`, `TF_VAR_ssh_public_key`; `scripts/lab.sh apply attacker`. Re-apply is a no-op.
3. `labmode.py maintenance --minutes 30 --reason "attacker packages"`, `ansible-playbook playbooks/attacker.yml`, then `labmode.py exercise t1` and re-verify denies (`REVERIFY=1 scripts/a2-verify.sh exercise none lab`) as in the [M2 runbook](m2-firewall-and-networks.md).
4. Re-run `playbooks/elastic.yml` (adds the marker template) with `scripts/elastic-tunnel.sh` open.
5. Exercise (tunnel open, `labmode.py select t1`):
   - `scripts/labops.py exercise start ex-001 --target t1`
   - on the attacker (`ssh opaleye@10.77.1.10`): `exercise1 --exercise-id ex-001 --target t1`
   - `scripts/labops.py exercise end` (also stamps `lab.exercise_id` on the window's events; later, `scripts/labops.py exercise tag ID` catches stragglers)
   - hunt in Kibana: both directions (process to request, request to process) inside the window from `labops.py exercise show ex-001`
   - `scripts/labops.py drain t1`, then `labmode.py maintenance --minutes 60 --reason "target reset"` and `reset t1` (A7), then back to exercise mode with denies re-verified, and `attacker-clean`.
6. Lab off/on: `labops.py shutdown [--include-elastic] [--acknowledge-loss REASON]` / `startup [--include-elastic]` (A9). Needs `PROXMOX_VE_ENDPOINT`, `PVE_NODE`, `PROXMOX_VE_API_TOKEN_{ATTACKER,TARGETS,FIREWALL}` (+ `_ELASTIC`).
7. Evidence deletion: `scripts/evidence_delete.py all` (dry run), then re-run with the printed `--confirm` phrase (it includes the document count).

## Guards

- Reset names only a target with a VM (`t1`; elastic, firewall, attacker, `all`, `t2` are refused). It calls `scripts/target.sh bump` then `provision`, which address the targets stack only.
- Shutdown leaves Elastic running by default (Elastic is reached only with `--include-elastic`, graceful power-off, no delete). Nothing in shutdown or reset can issue an Elasticsearch delete (tests assert no DELETE/`_delete_by_query` reaches the fake).
- Evidence deletion is only `evidence_delete.py`, dry-run first, confirmation phrase includes the document count, refused while an exercise is active (local state or unmatched markers).

## Known gaps / decisions for Adam

- **Shutdown vs Elastic**: A9 says shutdown powers off *all* guests; the brief said shutdown must never reach Elastic. Implemented as: excluded by default, graceful `--include-elastic` opt-in. Confirm or change.
- **`lab.exercise_id` is stamped at `exercise end`** on that target's events (same generation) between the start and end markers, widened by plan `ops.tag_slack_s` (3 s) each side for clock skew and Apache's whole-second timestamps. Events still in transit at `end` are picked up by `labops.py exercise tag ID` (safe to re-run; already-tagged events and markers are skipped). Apache requests also carry the id in the User-Agent. Run live on `ex-003`: Apache 4, Defend process 163, Defend network 28, firewall flow 25, auditd 225 events tagged.
- Reset needs maintenance mode (M4 provisioning pulls images); afterwards return with `labmode.py exercise`, re-verify denies, `labmode.py select`.
- Shutdown drains running targets first (Elastic must answer, or `--acknowledge-loss REASON`).
- `exercise end` needs Elastic; during an outage the exercise stays active (blocks shutdown, reset of that target and evidence deletion) until it returns.
- Drain-marker lines are not removed by evidence deletion (they share the Apache access stream); they are recognisable by `user_agent.original: opaleye-drain/<token>`.
- `lab.sh apply all` and `scripts/a1-verify.sh` now include the attacker stack (needs its token, pool and template first).
- The attacker cannot reach the ingestion ports (closed at M3/A3; only t1 and t2 ingest).
- Verified live 2026-10-30: Proxmox shutdown/start calls, the `exercise1` DVWA login flow, the `_cat/allocation` watermark proxy, marker template mappings and the drain line (see A7/A9 below). Still unverified: nothing known.
- Exercise 1's callback to the attacker (`/dev/tcp/10.77.1.10/4444`) is expected to be **blocked** by the firewall; the Defend network event records the attempt.

## A6 evidence

**Collected (live run 2026-10-30, exercise `ex-003`, target t1 generation 1, window 08:08:11.300Z to 08:09:16.730Z from `exercise show`).** The evidence rows below were read from Elasticsearch through the API, **not Kibana**. The Kibana hunt was done by Adam (reported, no screenshots kept). A6 stays open until the A7/A9 touchpoints are run and Adam signs off. `ex-001` and `ex-002` were aborted runs (attacker script defects, since fixed) and have start/end markers but no usable activity.

| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| operator | `exercise start` marker in Elastic | exercise | marker with `lab.exercise_id` | `exercise-start` 08:08:11.300Z and `exercise-end` 08:09:16.730Z, `lab.exercise_id=ex-003`, target t1, generation 1 (2 markers) | labops.py |
| attacker | t1:80 `/vulnerabilities/exec/` | exercise | HTTP 200, injected output | login, `/index.php` and `POST /vulnerabilities/exec/` returned 200; `command_output_seen: true` (`uid=` in the response) | firewall allow, DVWA |
| t1 | Apache request in Elastic | exercise | request found by window / User-Agent | 4 requests, `user_agent.original=opaleye-exercise1/ex-003`, `lab.target_id=t1`, including `POST /vulnerabilities/exec/` (200) | Filestream |
| t1 | process parent->shell->child, container attribution | exercise | present | Defend: `apache2` (group leader) -> `dash` (`sh -c -- ping -c 4 127.0.0.1; id; timeout 5 bash -c ...`, parent start 08:08:09.700Z) -> `id` (08:08:12.760Z), `timeout` and `bash`; `entry_meta.type=container`. auditd execve for `id`/`timeout` carries `container.name=dvwa-dvwa-1`, `container.id=898bb426...`, image `ghcr.io/digininja/dvwa@sha256:80294506...` | Defend, auditd |
| t1 | attacker:4444 outbound attempt | exercise | network event, blocked | Defend network: `connection_attempted` 08:08:12.774Z then `disconnect_received` 08:08:17.775Z (bash, 172.18.0.3 -> 10.77.1.10:4444); auditd `connected-to` outcome `failure`; firewall flow log: 5 `block` events t1 -> 10.77.1.10:4444 | Defend, firewall flow log |
| operator | hunt process->request and request->process in Kibana only | exercise | both within the window | Adam ran both hunts in Kibana over the `ex-003` window and the results matched (process `sh -c ...` command line <-> `POST /vulnerabilities/exec/` request with `user_agent.original=opaleye-exercise1/ex-003`, in both directions). The same pair was also read via the API (command line at 08:08:12.76Z matches the injected `ip` value of the request logged at 08:08:10Z; Apache timestamps have 1 s resolution) | Kibana |
| operator | #7 limitations recorded | n/a | recorded | recorded below | this file |

Observations from this run:

- The Apache access documents have **no `message` field**; search them by `user_agent.original`, `url.path` and `lab.target_id`.
- The Defend process events carry no `container.*` fields; container attribution comes from `process.entry_leader.entry_meta.type=container` there, and from `container.*` on the auditd events.
- The firewall **drops** (not rejects) the callback, so the target's `bash` hangs on the connection; `exercise1` therefore wraps it in `timeout 5` (without it the HTTP POST hits the client's 30 s timeout).
- `exercise start` then `exercise end` with nothing between them leaves a usable marker pair but an empty window; `exercise show` right after `end` can say "no markers" until Elasticsearch refreshes.

### #7 limitations, as observed in this run

- Execution happened inside the DVWA container (`dvwa-dvwa-1`). Nothing here shows container escape or Proxmox host compromise.
- DVWA logs carry no authenticated-user or object fields; identity evidence is the session and source IP only (the Apache request has the attacker IP and the User-Agent).
- Container attribution was unproven before this run. It is now seen, but from two sources: Defend marks the process `entry_meta.type=container` (no `container.*` fields), and auditd carries `container.name`, `container.id` and the image digest.
- Only the `low` path was run.

### Decisions (Adam, 2026-10-30)

- Shutdown leaves Elastic running by default; `--include-elastic` is an explicit graceful opt-in. Confirmed.
- Exercise tagging: Adam chose per-event stamping (option 1). Implemented as above; the marker window is kept as well.

### A3 (M3) prerequisite, re-checked 2026-10-30

`a3-verify.sh services`: 27/27 rows pass (version 9.5.5, green, 1 node, lifecycle 90d/14d on all templates and 50 data streams, snapshot restore 3 docs, TLS with the lab CA, destroy guard, pool ACL denies). The config backup was missing and was produced with `playbooks/elastic-config-backup.yml`. Not re-run here: `a3-verify.sh net vpn|home`, which needs the probe guests.

## A7 / A9 touchpoints (live, 2026-10-30)

The drain marker is now a valid Apache combined-log line (`GET /opaleye-drain?target_id=T&rebuild_generation=N`, User-Agent `opaleye-drain/<token>`). The first live attempt used a free-text line: the Apache access grok rejected it, so it had no `message` and no `lab.*` stamp and the drain check never saw it (it timed out after 180 s). As a valid log line it is parsed and stamped by `lab-stamp` like real evidence and the drain confirms in about 25 s.

| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| operator | `drain t1` | exercise | marker with matching generation arrives in ES | `drained: marker ... for t1 generation 1 arrived in Elasticsearch` (26 s) | labops.py, Elastic Agent |
| operator | `reset t1` (maintenance mode) | maintenance | only t1 rebuilt; generation 1 -> 2 | VM 2011 replaced (new PID); firewall 2000, attacker 2001 and Elastic 2003 kept their PIDs; `rebuild_generation` 2; first provision hit SSH before the new VM was up, a re-run of `target.sh provision t1` completed (28 ok, 0 failed) | labops.py, Tofu targets stack, Ansible |
| t1 | prior exercise events after reset | exercise | still searchable by `exercise_id` | `lab.exercise_id: ex-003` still 773 events; generation 1 events retained; generation 2 events arriving (28,912 by 09:50Z) | Elastic |
| t1 | old agent retired | exercise | one enrolled agent | one agent, enrolled 09:33:24Z, online | Fleet |
| operator | `shutdown` | exercise | firewall, attacker, t1 powered off after drain; Elastic untouched | all three `stopped`; Elastic still running with the same PID | Proxmox API |
| operator | `startup` | exercise | firewall first, then the rest | firewall, t1, attacker `running`; SSH to t1 and Elastic up in about 90 s | Proxmox API |
| operator | state after restart | exercise | mode and denies unchanged | `mode: exercise, selected: t1`; `a2-verify.sh exercise t1 lab` PASS-WITH-SKIPS (28 rows, 11 skipped, none failed); `a5-verify.sh t1` PASS; `a4_verify.py` PASS-WITH-SKIPS once the shutdown backlog cleared (152 events over 120 s lag right after startup, 0 five minutes later) | firewall, Elastic Agent |
| operator | `evidence_delete.py` dry run, then confirm | n/a | dry run lists what would go; confirm deletes | dry run run by Adam: `nothing deleted`, 170,428 documents across the evidence streams (process 53,477; network 586; file 34,896; auditd 77,559; docker 271; apache access 58 and error 28; firewall flow 3,547; markers 6) and the printed `--confirm` phrase. **Confirm step not run**: it deletes every exercise's evidence, so it is held until sign-off | evidence_delete.py |
