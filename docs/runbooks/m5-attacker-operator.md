# M5 Attacker VM and operator commands runbook

Issue #24. Exit = check A6 in [acceptance checks](../decisions/acceptance-checks-and-build-plan.md). Design: [operator commands and target interface](../decisions/operator-commands-and-target-interface.md).

**Status: code and offline tests only. A6 evidence is NOT collected.** Nothing here has run against the live firewall, Proxmox or Elastic: the VPN was unavailable, and neither A3 (M3) nor A4/A5 (M4, merged as code only) has been run live. M6 must not start, and #24 must not close, until the A6 tables below are filled in from a live run. Every Ansible/Tofu/Fleet/Proxmox call here is unverified against the real systems.

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
   - `scripts/labops.py exercise end`
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
- **`lab.exercise_id` is a marker window, not a per-event field** (the `lab-stamp` pipeline maps the field but nothing sets it per event). Apache requests also carry the id in the User-Agent.
- Reset needs maintenance mode (M4 provisioning pulls images); afterwards return with `labmode.py exercise`, re-verify denies, `labmode.py select`.
- Shutdown drains running targets first (Elastic must answer, or `--acknowledge-loss REASON`).
- `exercise end` needs Elastic; during an outage the exercise stays active (blocks shutdown, reset of that target and evidence deletion) until it returns.
- Drain-marker lines are not removed by evidence deletion (they share the Apache access stream).
- `lab.sh apply all` and `scripts/a1-verify.sh` now include the attacker stack (needs its token, pool and template first).
- Attacker (and t2) can reach ingestion ports (M2 known gap, unchanged).
- Unverified live: Proxmox shutdown calls, the DVWA login/CSRF flow in `exercise1`, the `_cat/allocation` watermark proxy, marker template mappings, and the drain line passing the Apache pipeline.
- Exercise 1's callback to the attacker (`/dev/tcp/10.77.1.10/4444`) is expected to be **blocked** by the firewall; the Defend network event records the attempt.

## A6 evidence

**Not collected.** Fill in from a live run (format: source, destination/port, mode, expected, actual, enforcement point).

| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| operator | `exercise start` marker in Elastic | exercise | marker with `lab.exercise_id` | _not run_ | labops.py |
| attacker | t1:80 `/vulnerabilities/exec/` | exercise | HTTP 200, injected output | _not run_ | firewall allow, DVWA |
| t1 | Apache request in Elastic | exercise | request found by window / User-Agent | _not run_ | Filestream |
| t1 | process parent→shell→child, container attribution | exercise | present | _not run_ | Defend |
| t1 | attacker:4444 outbound attempt | exercise | network event, blocked | _not run_ | Defend, firewall flow log |
| operator | hunt process→request and request→process in Kibana only | exercise | both within the window | _not run_ | Kibana |
| operator | #7 limitations recorded | n/a | recorded | _not run_ | this file |
