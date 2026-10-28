# Operator commands and the target interface (M5)

Supports issue #24. Builds on `deployment-and-reset-lifecycle.md` (#8), `telemetry-contracts-and-budgets.md` (#9), `first-targets-and-hunt-outcomes.md` (#7). Written while M4 (#23) was unmerged: this file is the **contract M5 assumes from M4**; reconcile when M4 merges (list in [the runbook](../runbooks/m5-attacker-operator.md#reconcile-when-m4-merges)).

## Decisions

| Question | Decision |
| --- | --- |
| Attacker stack | **Own Tofu stack, pool `lab-attacker`, token and state** (`tofu/stacks/attacker`). A target reset (targets stack) cannot rebuild it; "attacker-side state is cleared separately" (#8) is `labops.py attacker-clean`. |
| Exercise ID | `labops.py exercise start ID --target T` writes an `exercise-start` marker to data stream `logs-lab_marker.events-default` with `lab.exercise_id`, `lab.target_id`, `lab.rebuild_generation`; `exercise end` writes `exercise-end`. One active exercise (#9). Refuses unless the firewall is in exercise mode with T selected, Elastic answers, and disk is below the high watermark (90%, #9: "stop new exercises"). |
| Finding an exercise's events | Target events are **not** stamped with `lab.exercise_id`. An exercise = the marker window on its target (`exercise show ID`). Apache requests also carry it in the User-Agent (`opaleye-exercise1/<id>`, combined log format). Per-event stamping is not attempted; revisit at A6 if the window is too coarse. |
| Generation | Tracked on the workstation (`.state/labops.json`), **starts at 1** at first deploy, +1 per reset, passed to Tofu as `TF_VAR_rebuild_generations` (JSON map) and to Ansible as `rebuild_generation`. `labops.py generation T N` aligns it. |
| Drain marker | `labops.py drain T` SSHes to the target and appends `OPALEYE_DRAIN_MARKER token=<hex> target_id=T rebuild_generation=N` to `/var/log/opaleye/drain.log`. That file is shipped by the Elastic Agent, so arrival proves the same pipeline drained. Confirmed by searching `logs-*` for the token with matching `lab.rebuild_generation`. Mechanism-agnostic about the data stream. |
| Reset | `labops.py reset T [--acknowledge-loss REASON]`: T must be in `plan.targets`; no active exercise on T; **Elastic must answer (no override)**; drain must pass unless loss is acknowledged with a reason of 5+ characters (audited); old agent revoked via Fleet (**failure refuses the rebuild**); `lab.sh replace targets <address>` (rebuilds that one VM resource); generation +1 once Tofu succeeds; then `ansible playbooks/targets.yml --limit T`. Touches no other stack. |
| Shutdown | `labops.py shutdown`: graceful ACPI shutdown through the Proxmox API (no stop/delete/config call exists in the client), order attacker, targets, firewall. **Elastic is left running unless `--include-elastic`**, which only adds a graceful shutdown with Elastic's own token. Refused during an active exercise. Running targets are drained first (same check and override as reset: `--acknowledge-loss REASON`; Elastic must answer or loss be acknowledged). `startup` is the reverse (firewall first). |
| Evidence deletion | `scripts/evidence_delete.py`: separate file, not imported by or referenced from reset, shutdown, `lab.sh` or `pve.py` (tests assert it). `all` or `exercise:ID`; dry run by default; needs `--confirm` with the phrase the dry run prints (`DELETE EVIDENCE <scope> (<N> documents)`, so it matches what was previewed); refused during an active exercise, judged from local state **and** Elastic's own markers (unmatched start); exercise scope also removes firewall flow rows in the window; metrics never touched; audited. |

Elastic's 9200 is reached over an SSH tunnel (`scripts/elastic-tunnel.sh`), not directly over the VPN: the firewall allows the operator only Kibana and SSH (probes p32, p45, p48, p49), so the management-interface wording in ADR 0001 is met by Kibana on 5601 and the tunnel originates on the VM.

## Contract assumed from M4 (not in this branch)

1. Targets stack: `for_each` VM resources addressed `proxmox_virtual_environment_vm.target["t1"]`, a variable `rebuild_generations` (`map(number)`) stamped as `lab.rebuild_generation`; VM ids `plan.targets.<t>.vm_id` (2011, 2012 chosen here).
2. Inventory hosts named `t1`, `t2` in group `targets`; playbook `ansible/playbooks/targets.yml` accepting `rebuild_generation`.
3. Agent host name `opaleye-<t>` (Fleet `local_metadata.host.name`), used to revoke the old agent.
4. User `opaleye` with the operator's key and passwordless sudo; `/var/log/opaleye/drain.log` created at provision with a header of at least 1,024 bytes (Filestream fingerprint default) and shipped with `lab.target_id`/`lab.rebuild_generation` fields.
5. DVWA on port 80, default credentials, database created at provision (`/setup.php` done), Apache logging the User-Agent.
