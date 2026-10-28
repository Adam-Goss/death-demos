# M5 Attacker VM and operator commands runbook

Issue #24. Exit = check A6 in [acceptance checks](../decisions/acceptance-checks-and-build-plan.md). Design: [operator commands and target interface](../decisions/operator-commands-and-target-interface.md).

**Status: code and offline tests only. A6 evidence is NOT collected.** Nothing here has run against the live firewall, Proxmox or Elastic: the VPN was unavailable, and neither A3 (M3, PR #35) nor M4 (#23) has been run live or merged. M6 must not start, and #24 must not close, until the A6 tables below are filled in from a live run. Every Ansible/Tofu/Fleet/Proxmox call here is unverified against the real systems.

## What exists

| Piece | Where |
| --- | --- |
| Attacker VM (VMID 2001, `10.77.1.10`, pool `lab-attacker`, 2 vCPU / 4 GB) | `tofu/stacks/attacker`, template `scripts/make-attacker-template.sh` (VMID 2301) |
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
   - `scripts/labops.py drain t1`, then `reset t1` (A7), `attacker-clean`.
6. Lab off/on: `labops.py shutdown [--include-elastic] [--acknowledge-loss REASON]` / `startup [--include-elastic]` (A9). Needs `PROXMOX_VE_ENDPOINT`, `PVE_NODE`, `PROXMOX_VE_API_TOKEN_{ATTACKER,TARGETS,FIREWALL}` (+ `_ELASTIC`).
7. Evidence deletion: `scripts/evidence_delete.py all` (dry run), then re-run with the printed `--confirm` phrase (it includes the document count).

## Guards

- Reset names only `plan.targets`; `elastic`, `firewall`, `attacker` and `all` are refused. It calls `lab.sh replace targets <vm address>` only; `lab.sh replace` refuses any other stack.
- Shutdown leaves Elastic running by default (Elastic is reached only with `--include-elastic`, graceful power-off, no delete). Nothing in shutdown or reset can issue an Elasticsearch delete (tests assert no DELETE/`_delete_by_query` reaches the fake).
- Evidence deletion is only `evidence_delete.py`, dry-run first, exact confirmation phrase, refused while an exercise is active.

## Known gaps / decisions for Adam

- **Shutdown vs Elastic**: A9 says shutdown powers off *all* guests; the brief said shutdown must never reach Elastic. Implemented as: excluded by default, graceful `--include-elastic` opt-in. Confirm or change.
- **`lab.exercise_id` is a marker window, not a per-event field** (see the decision doc). Apache requests also carry it in the User-Agent.
- `exercise end` needs Elastic; during an outage the exercise stays active (blocks shutdown, reset of that target and evidence deletion) until it returns. Evidence deletion also refuses when Elastic's markers show an unmatched start.
- Agent retirement in reset is **required**: if the Fleet call fails the rebuild is refused (nothing destroyed). It revokes the old agent's key; the fresh enrolment token per rebuild is M4's.
- `lab.sh replace` passes `-replace` and `-target` for the one VM address, so nothing else in the targets stack is applied.
- Shutdown drains running targets first (Elastic must answer, or `--acknowledge-loss REASON`).
- Drain-marker lines are not removed by evidence deletion (they sit in whatever stream the agent ships them to).
- Generation is tracked on the workstation; if `.state` is lost, align with `labops.py generation`.
- `scripts/a1-verify.sh` and `lab.sh apply all` now include the attacker stack (needs its token, pool and template first).
- Attacker (and t2) can reach ingestion ports (M2 known gap, unchanged).
- Unverified live: Fleet `bulk_unenroll` payload, Proxmox shutdown calls, `tofu apply -replace` address, the DVWA login/CSRF flow, the `_cat/allocation` watermark proxy, marker template mappings.
- Exercise 1's callback to the attacker (`/dev/tcp/10.77.1.10/4444`) is expected to be **blocked** by the firewall; the Defend network event records the attempt.

## Reconcile when M4 merges

1. VM ids (`plan.targets.*.vm_id`), `tofu_address`, `rebuild_generations` variable and resource naming vs M4's targets stack (merge conflicts likely in `network/plan.json` and `tofu/stacks/targets/versions.tf` header comment).
2. Inventory host aliases `t1`/`t2`, `playbooks/targets.yml`, `rebuild_generation` extra var.
3. Agent host name `opaleye-<t>`; drain log path, sudo and Filestream shipping; initial generation 1.
4. DVWA credentials and setup state; User-Agent in Apache log format.
5. Add `targets` to `scripts/a1-verify.sh`/`static-checks.sh` only if M4 changed those lists.

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
