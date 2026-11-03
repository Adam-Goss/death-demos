---
name: lab-teardown
description: Take the Opaleye lab down safely: graceful lab shutdown, destroying a Tofu stack (never Elastic), or the full target reset flow.
disable-model-invocation: true
---

# Lab teardown

Three jobs: **shutdown** (power off, nothing destroyed), **destroy a stack** (the VMs go, evidence stays), and **target reset** (rebuild one target from pinned inputs). Procedure: [README "Using the lab"](../../../README.md#using-the-lab) steps 5, 7 and 9; detail in the [M5](../../../docs/runbooks/m5-attacker-operator.md) and [M4](../../../docs/runbooks/m4-target.md) runbooks and [ADR 0001](../../../docs/adr/0001-isolate-the-attack-lab-behind-a-firewall-vm.md).

**Preconditions, step 0 for every run** — the live checkout (not a git worktree), the env file sourced with `ELASTIC_PASSWORD` unset, the VPN checked over TCP, and healthy workstation timers (`python3 scripts/labops.py doctor`; a drain check needs Elastic reachable, so an unhealthy tunnel is the first thing to fix). The four are spelled out once in the [skills runbook](../../../docs/runbooks/lab-skills.md#preconditions-for-every-skill); read it and check them before anything below.

**Every step here is destructive or mode-changing. Confirm each one with the user before running it, naming what it removes.** Two hard rules:

- **Elastic is never destroyed.** `lab.sh` refuses `destroy elastic`, `destroy all` skips it, and the Tofu VM carries `prevent_destroy`. `--include-elastic` on `shutdown` means a **graceful power-off only**. Removing ingested evidence is a separate, confirmed command: `python3 scripts/evidence_delete.py` ([README step 8](../../../README.md#8-delete-evidence-rarely)). Do not propose changing those guards.
- **`--acknowledge-loss "<reason>"` accepts the loss of telemetry that never shipped.** Never pass it on your own: ask the user, record the reason they give in the command and in your report.

## Steps

Ask which job this is, then follow that section. Stop at a failing criterion and report it with its output.

### A. Lab shutdown

1. **No exercise running**: `python3 scripts/labops.py status` shows no active exercise (shutdown is refused otherwise; end it with `/lab-exercise-run` or `labops.py exercise end`). Criterion: the state shows `"active": null`.
2. **Confirm the scope**: Elastic stays up by default; `--include-elastic` shuts it down gracefully too. Criterion: the user chooses.
3. **Shut down**: `python3 scripts/labops.py shutdown` or `python3 scripts/labops.py shutdown --include-elastic`. It drains running targets first (order: gateway, attacker, targets, Elastic, firewall). Criterion: exit 0; every guest reports `stopped`. Guests that did not stop are reported, nothing is forced: retry or use the Proxmox console.
4. **If the drain check fails** (Elastic down or forwarding behind), the shutdown is refused. Prefer fixing the tunnel or Elastic (`/lab-troubleshoot`). Only if the user accepts the loss, re-run with `--acknowledge-loss "<their reason>"`.
5. **Analysis VMs** are not part of lab shutdown; they are off by default and handled in `/lab-malware-analysis`.

### B. Destroy a stack

1. **Name the stack and the blast radius**: `firewall`, `targets`, `attacker` or `gateway`. `elastic` is refused by design. Criterion: the user names a stack that is not `elastic`.
2. **Show what goes**: `scripts/lab.sh plan <stack>` first, then state the VMs that would be removed. Criterion: the user approves.
3. **Destroy**: `scripts/lab.sh destroy <stack>`. `scripts/lab.sh destroy all` destroys the other stacks in reverse order and never touches Elastic. The `analysis` stack is only ever named explicitly. Criterion: exit 0.
4. **Rebuild path**: a destroyed stack comes back with `/lab-deploy` (apply, then the stack's Ansible play). Say so in the report.

### C. Target reset

A reset rebuilds the target VM from pinned inputs; Elastic evidence, the attacker VM, firewall and Elastic are untouched. Run the steps **in this order** ([README step 5](../../../README.md#5-reset-the-target)):

```bash
python3 scripts/labops.py drain t1                                   # confirms telemetry has shipped
python3 scripts/labmode.py maintenance --minutes 60 --reason "target reset"
python3 scripts/labops.py reset t1                                   # drain check, bump generation, rebuild
python3 scripts/labmode.py exercise none                             # leave maintenance mode
REVERIFY=1 scripts/a2-verify.sh exercise none lab                    # prove the denies again
python3 scripts/labmode.py select t1
python3 scripts/labops.py attacker-clean                             # clear /srv/exercise on the attacker
```

0. **Can you finish?** Ask this **before** the mode switch, because leaving maintenance sets the re-verify flag and `select` stays refused until a clean A2 run clears it. `REVERIFY=1` demands **one unfiltered exercise/lab run, zero skipped rows, exit 0** (`scripts/a2-verify.sh` lines 214-218; `SKIP_SOURCES` is refused), and **as the lab stands that run cannot pass**: measured live on 2026-11-03, 82 rows, 0 skipped, 24 `ERROR` — `flare` 15, `remnux` 5, `t2` 4. The analysis sources are unreachable from the workstation **by design** (only the gateway may enter that zone), and routing the probes through the gateway (`PROBE_SSH="ssh -J opaleye@10.77.2.10 ..."`) breaks the attacker and Elastic rows, because the gateway reaches the attacker on RDP only and Elastic not at all. A probe guest fixes `t2`; nothing in one run fixes both ends. Every source with a running VM did match its contract.

   This is tracked as **issue #64** (`a2-verify.sh` needs a per-source vantage); do not work around it by relaxing the guard. Before any maintenance window: tell the user the exit path is a **per-vantage A2 set** (as in the [malware-analysis runbook](../../../docs/runbooks/malware-analysis.md)'s A2 table) followed by `python3 scripts/labmode.py reverified` on their explicit instruction, with the reason recorded — the operator's decision, never the agent's shortcut. Without it the reset leaves the lab in exercise mode with **no selectable target** and exercises blocked. Criterion: the user knows the cost and agrees.
1. **Preflight**: the tunnel is up (`labops.py` needs Elasticsearch) and no exercise is active on that target. Criterion: `python3 scripts/labops.py drain t1` exits 0.
2. **Maintenance window**: confirm with the user, then open it with a reason. Criterion: `labmode.py status` shows maintenance with an expiry.
3. **Reset**: confirm, then `python3 scripts/labops.py reset t1`. Criterion: exit 0 and `python3 scripts/labops.py generation t1` shows the incremented generation.
4. **Leave maintenance and re-verify**: `labmode.py exercise none`, then the `REVERIFY=1` A2 run. Leaving maintenance sets a flag; until the denies are re-verified, `select` is refused. Criterion: A2 passes and `labmode.py select t1` succeeds.
5. **Attacker-side state**: `python3 scripts/labops.py attacker-clean` clears `/srv/exercise`. It is never done by the reset itself. Criterion: exit 0.

## Failure handling

- `reset` refused: not in maintenance mode, an active exercise on that target, Elastic unreachable, or a failed drain. Fix the cause first; `--acknowledge-loss` only with the user's reason.
- **`reset` fails *after* bumping the generation.** It bumps, then provisions, so a provisioning failure leaves the target recorded at the new generation with the old VM — a half-reset. Finish it with `bash scripts/target.sh provision <t>` (idempotent, rebuilds at the bumped generation); never hand-repair the VM. Three causes seen live on 2026-11-03:
  - `scripts/target.sh: line 35: scripts/lab.sh: Permission denied` — git records `lab.sh` as non-executable while `target.sh` calls it directly (**issue #65**). `chmod +x scripts/lab.sh` in the live checkout, then re-provision.
  - `Backend initialization required` — the `targets` stack was never initialised in this checkout and `target.sh` has no init step: `bash scripts/lab.sh init targets`, then re-provision.
  - the Ansible play reports `UNREACHABLE ... port 22: Connection timed out` — `target.sh` does not wait for the rebuilt VM's sshd. Wait for `ssh -o BatchMode=yes opaleye@<ip> true` to answer, then re-provision.
- After a finished rebuild, prove it: `python3 scripts/labops.py drain <t>` and `bash scripts/a5-verify.sh <t>` (the target reached its known state from code, pinned image digests, no enrolment token in the image).
- `labmode.py maintenance` says already in maintenance: wait for expiry or `labmode.py exercise none`.
- A firewall API error leaves a change unconfirmed: the dead-man job on the firewall restores the last confirmed config within about a minute. Re-check `labmode.py status` before retrying.
- Do not hand-repair a broken or compromised target: rebuild it with the reset flow above.

## Done

Report: the job, every destructive command actually run, whether `--acknowledge-loss` was used and with which reason, the resulting mode and selected target, and the state of Elastic (untouched).
