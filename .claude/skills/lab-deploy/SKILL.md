---
name: lab-deploy
description: Bring the Opaleye lab up: power a powered-off lab on, or build/rebuild its Tofu stacks and in-guest configuration in order, then verify with the acceptance checks.
disable-model-invocation: true
---

# Lab deploy

Two jobs share this skill: **powering a built lab on** (nothing is rebuilt) and **building or rebuilding stacks**. Procedure: [README "Using the lab"](../../../README.md#using-the-lab) steps 2 and 9 and ["Building the lab from scratch"](../../../README.md#building-the-lab-from-scratch); per-stack detail in the [M1](../../../docs/runbooks/m1-foundations.md), [M2](../../../docs/runbooks/m2-firewall-and-networks.md), [M3](../../../docs/runbooks/m3-elastic.md), [M4](../../../docs/runbooks/m4-target.md), [M5](../../../docs/runbooks/m5-attacker-operator.md) and [gateway](../../../docs/runbooks/guacamole-gateway.md) runbooks. Follow those documents where they are more specific than this skill; do not restate their steps from memory.

**Preconditions, step 0 for every run** — the live checkout (not a git worktree), the env file sourced with `ELASTIC_PASSWORD` unset, the VPN checked over TCP, and healthy workstation timers (`labops.py doctor`). The four are spelled out once in the [skills runbook](../../../docs/runbooks/lab-skills.md#preconditions-for-every-skill); read it and check them before step 1.

**Confirm with the user before every `lab.sh apply`, before `labops.py startup`, before entering maintenance mode, and before any Ansible play.** An apply replaces VMs; a startup powers real guests on. Never run `lab.sh destroy` from this skill: that is `/lab-teardown`.

## Steps

Each step ends when its criterion holds. Stop at a failing criterion and report it with its output.

1. **Which job**: ask whether this is a power-on, a change to one stack, or a from-scratch/rebuild run, and which stacks. Criterion: the user names the job and the stacks. If the answer is "power on", do steps 2-4 and 9-10 only.
2. **Preconditions checked** (the four from the skills runbook) and the lab answers: `python3 scripts/labmode.py status` prints the mode. Criterion: all four hold and the mode is known. A tunnel that was up before a firewall rebuild must be deactivated and reactivated.
3. **Power on** (skip for a stack rebuild of a running lab), with the user's confirmation: `python3 scripts/labops.py startup --include-elastic` (firewall first, then Elastic, targets, attacker, gateway; it powers guests on and rebuilds nothing). Criterion: every guest reports `running`. A guest that does not start is reported, never forced; retry or use the Proxmox console. `startup` warns when the workstation timers are unhealthy. Elastic and the gateway matter beyond their own stacks — Elastic for policies, drains and enrolment, the gateway for any jump into the analysis zone — so offer to start them even when only one stack is being rebuilt. The analysis VMs are deliberately not started here (`/lab-malware-analysis`).
4. **Elastic API reachable**: the Elastic SSH tunnel must run for `labops.py`, the Ansible API tasks and `fleetctl.py` (`scripts/elastic-tunnel.sh` in another terminal, or the installed tunnel timer). Criterion: `python3 scripts/labops.py doctor` prints `doctor: ok`, or its `PROBLEM:` lines are understood and accepted for this run (a stopped firewall expects no flow events).
5. **Plan the change** (stack runs only). Work in a **login shell** (`tofu` lives in `/snap/bin`; a non-login shell fails with `tofu: command not found`) and call the runner through `bash`, because a checkout synced from `/mnt/c` or unzipped on Windows loses the exec bit (#65):
   ```bash
   bash scripts/lab.sh init <stack>     # once per stack per checkout; without it: "Backend initialization required"
   bash scripts/lab.sh plan <stack>
   ```
   Then read the plan **before showing it**: a stack whose `TF_VAR_*` inputs are missing plans a **replacement** of a VM that is perfectly healthy. Two live cases to recognise, one per stack:

   - `TF_VAR_firewall_template_vm_id` unset defaults to `0`, the firewall stack's `clone` block disappears, and `plan firewall` says `proxmox_virtual_environment_vm.firewall must be replaced` (`vm_id 2101 -> null # forces replacement`).
   - `targets` used to be worse, because the plan looked routine: `TF_VAR_rebuild_generation` unset resolved the generation to `1`, which disagrees with the state and trips the VM's `replace_triggered_by`, so `plan targets` reported a plain `1 to add, 1 to change, 1 to destroy` and wound the counter back (`input = 7 -> 1`). Its only warning was `will be replaced due to changes in replace_triggered_by` — a line that reads like a legitimate rebuild, not the firewall case's blunt `must be replaced`. Since #71 `lab.sh` derives the map from `.state/targets/*.generation`, so leave the variable **unset** and the plan says *No changes*. A non-empty value exported by hand still wins over the derivation: if one is set in the environment, unset it rather than trusting it. Deciding to replace a target is a **target reset** (`python3 scripts/labops.py reset <t>`, which confirms the drain marker first), never a hand apply of this stack.

   Criterion: every add, change and destroy in the plan is explained, and the user approves it. **A replacement you cannot explain is a missing variable, not a change to apply** — stop and fix the environment.
6. **Apply, in order**: `bash scripts/lab.sh apply <stack>`, or `bash scripts/lab.sh apply all` for the whole ordered set (`firewall`, `elastic`, `targets`, `attacker`, `gateway`). The `analysis` stack is only ever run by name, never by `all`. Re-running an apply is safe. Criterion: each apply exits 0 and did what the approved plan said. `apply all` also reinstalls the workstation timers; a warning there does not fail the deployment.
7. **In-guest configuration**, for the stacks that were (re)built. Package installs and image pulls need **maintenance mode** (`python3 scripts/labmode.py maintenance --minutes N --reason "<text>"`, confirmed with the user first):
   - Elastic: `(cd ansible && ansible-playbook playbooks/elastic.yml)`, then `playbooks/elastic-evidence.yml`. Elastic never gets Internet access: its packages are fetched on the workstation (`python3 scripts/fleetctl.py fetch-packages`, then `upload-packages`) and checked against the pins in `network/plan.json`.
   - Target: `bash scripts/target.sh provision t1` (Tofu apply at the current generation plus the target play). Needs maintenance mode and the tunnel.
   - Attacker, gateway: `playbooks/attacker.yml`, `playbooks/gateway.yml`.
   - Gateway admin: `python3 scripts/guacctl.py bootstrap` the first time (replaces the default `guacadmin` password, then creates the connections), `guacctl.py connections` afterwards. TOTP is enrolled by the operator at the first browser login.
   Criterion: each play ends with no failed tasks. A package install that times out means exercise mode, not a broken play.
8. **Back to the resting state and verify**: leave maintenance (`python3 scripts/labmode.py exercise none`, which also pushes a rebuilt firewall's rules), then prove the denies and select the target:
   ```bash
   python3 scripts/netpolicy.py lint exercise none
   REVERIFY=1 bash scripts/a2-verify.sh exercise none lab      # A2 is a hard gate before any vulnerable target runs
   python3 scripts/nicaudit.py                            # no guest has a second lab NIC or a home-bridge NIC
   python3 scripts/labmode.py select t1
   ```
   A2's `lab` phase needs probe guests for zones without a real VM (`t2`): see the [M2 runbook](../../../docs/runbooks/m2-firewall-and-networks.md). Criterion: A2 passes (or passes with understood `SKIP` rows) and `nicaudit.py` exits 0. Then, as relevant to what was rebuilt: `bash scripts/a3-verify.sh services`, `bash scripts/a4-verify.sh t1`, `bash scripts/a5-verify.sh t1`.
9. **Workstation timers for this checkout**: a deployment is not finished until the tick, flow-shipper and tunnel timers point at the live checkout. Run `/lab-workstation-setup` (it installs and proves them, and prints the crontab command for the operator when the harness refuses the edit — never work around that refusal). Criterion: `bash scripts/ops-timers.sh status` exits 0 and `python3 scripts/labops.py doctor` prints `doctor: ok`.
10. **Report ready**: `python3 scripts/labmode.py status` shows exercise mode with the target selected. Criterion: it holds, or the gap is named.

## Failure handling

- `tofu` wants a backend init: `bash scripts/lab.sh init <stack>`. Normal in the live checkout — only `firewall` and `elastic` were initialised there on 2026-11-03.
- `tofu: command not found`: not a login shell. `command -v tofu` should print `/snap/bin/tofu`.
- `scripts/lab.sh: Permission denied`: the live checkout's shell scripts have no exec bit; call them as `bash scripts/lab.sh ...`.
- Proxmox 403 on a new bridge after a firewall rebuild: the privilege-separated token needs its own `SDN.Use` ACL; see the gateway runbook's live-run notes.
- `select` refused because the denies are not re-verified: that flag is cleared by the `REVERIFY=1` A2 run in step 8.
- Scripts failing with `\r`: a Windows checkout. Run from WSL or a Linux clone.
- A broken target is rebuilt, never hand-repaired (`/lab-teardown`'s reset flow).

## Done

Report: what was powered on or applied, the plays that ran, the verifier results (A2 first), the mode and selected target, and anything skipped with the reason.
