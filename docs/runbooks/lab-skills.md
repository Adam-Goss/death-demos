# Lab skills runbook

Issue #60. The day-to-day procedures of the [project README](../../README.md#using-the-lab) packaged as Claude Code skills in [`.claude/skills/`](../../.claude/skills), so an agent can run the lab with the operator. The skills are **procedure, not implementation**: they call the repo's existing commands and cite the README section or runbook they follow. When a procedure changes, the document changes and the skill follows it; nothing here is a second copy of a runbook.

## The skills

| Skill | Job | Follows |
| --- | --- | --- |
| `lab-status` | Read-only sweep: VPN (TCP), guest power, mode and selected target, `doctor`, watermark, ingest lag, policy lint, NIC audit, gateway, analysis Internet state | README "Using the lab" and command reference, [ops timers](ops-timers.md) |
| `lab-deploy` | Power a powered-off lab on; build or rebuild stacks, their Ansible plays and `guacctl.py bootstrap`; verify (A2 first) | README steps 2 and 9, "Building the lab from scratch", [M1](m1-foundations.md)-[M5](m5-attacker-operator.md), [gateway](guacamole-gateway.md) |
| `lab-teardown` | Graceful shutdown, destroying a stack (never Elastic), the target reset flow | README steps 5, 7 and 9, [M4](m4-target.md), [M5](m5-attacker-operator.md) |
| `lab-exercise-run` | Preflight, exercise markers, the attack (scripted or by hand), tagging, Kibana filters, an offered reset | README step 4, [M5](m5-attacker-operator.md), [M6](m6-end-to-end-validation.md) |
| `lab-maintenance` | A time-limited window, the update plays, then exercise mode and re-verified denies | README step 6, [M2](m2-firewall-and-networks.md), [M3](m3-elastic.md) |
| `lab-troubleshoot` | Symptom to diagnosis to fix | README troubleshooting table and every runbook |
| `lab-malware-analysis` | Operate the analysis zone: power on, isolation, the Internet window, sample markers, snapshot reset | [malware analysis](malware-analysis.md), [ADR 0002](../adr/0002-one-isolated-windows-analysis-vm.md) |
| `lab-workstation-setup` | Install and prove the workstation timers in the live checkout (#61) | [ops timers](ops-timers.md) |

Each is `disable-model-invocation: true`: the operator invokes them (`/lab-status`), they are never picked up on a guess. They assume **WSL** (the scripts need LF endings), the live checkout, the operator env file sourced from the operator's own path, and the VPN up.

## Safety contract

Every skill states these, and the guard is in the commands themselves, not in the skill:

- Confirm with the user before every destructive, mode-changing or power step: `apply`, `destroy`, `reset`, `shutdown`, `startup`, maintenance mode, the analysis Internet toggle, an analysis reset.
- `--acknowledge-loss` is never passed on the agent's own judgement: the user is asked, and their reason is recorded in the command and the report.
- Elastic destroy is not offered. `lab.sh` refuses it, `destroy all` skips it, and `--include-elastic` means a graceful **shutdown**. Evidence removal is `scripts/evidence_delete.py` (dry run plus confirmation phrase) and nothing else.
- The analysis zone stays isolated: Internet off by default and before any detonation, windows time-limited and never silently extended, rules never widened.
- No secrets are echoed; they are read from the operator env and `secrets/` only.
- A broken or compromised target is rebuilt, never hand-repaired.

## Drift guard

`tests/test_skills.py` (in `tests/static-checks.sh` and the unittest discovery) reads the skill files as data and fails when a skill drifts from the repo:

- the seven skills of #60 exist, each with frontmatter whose `name` matches its directory, a description long enough to be a trigger, and `disable-model-invocation: true`;
- every `scripts/`, `network/`, `tests/` and `playbooks/` path a skill names exists, and every relative link resolves;
- every subcommand a skill names in a command span exists in that script's CLI — `labops.py`, `labmode.py` and `fleetctl.py` from their argparse choices (including the second level, `exercise start`, `analysis-sample end`), `netpolicy.py` and `guacctl.py` from their usage docstrings, `lab.sh`, `target.sh` and `ops-timers.sh` from their `case` branches;
- each skill cites the document it is based on, and the README usage guide links each skill.

The check is deliberately not vacuous: `test_the_command_tables_are_not_empty` fails if a script's CLI stops being readable this way, and a planted `labops.py exercise stop` / `lab.sh nuke all` was confirmed to fail the suite.

## Verification record

**Offline, in a clean checkout (2026-11-03):** `python3 -m unittest tests.test_skills` passes (11 tests). The read-only commands the skills lean on were run here without the lab: `netpolicy.py check`, `netpolicy.py lint exercise none|t1`, `netpolicy.py lint exercise none online` all `ok`; `labmode.py status` prints the state JSON; `labops.py`, `labmode.py` and `fleetctl.py --help` exit 0 and `guacctl.py` prints its usage (exit 2); the `lab-status` and `lab-malware-analysis` power-state snippets run and degrade to `unknown (set PROXMOX_VE_ENDPOINT and PVE_NODE)` with no token in the environment.

**Still to do, live on the lab:** run each skill once against the real lab from WSL with the VPN up, and record the result here — `lab-status` and `lab-troubleshoot` end to end; `lab-deploy` as `plan` only plus a power-on; `lab-maintenance` with a short window; `lab-exercise-run` with a throwaway exercise id; `lab-teardown` reset flow on `t1`; `lab-malware-analysis` with a one-minute Internet window and an `analysis-reset`. Note anything the skill got wrong about the live commands as a correction to the skill, not as a local workaround.
