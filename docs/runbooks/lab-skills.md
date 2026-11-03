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

Each is `disable-model-invocation: true`: the operator invokes them (`/lab-status`), they are never picked up on a guess.

## Preconditions for every skill

Every skill checks these four before its first step and stops on a failure; they are the live-run findings of #52 and #61, not README material. This section is the single copy: the skills cite it.

1. **The live checkout, not a git worktree.** Deployments and `labops.py` run in the directory that holds `.state/*.tfstate` and `secrets/env.sh` (WSL: `~/wrasse-live`); a worktree has neither. With more than one candidate, ask which. To bring its scripts current, extract `git archive HEAD scripts network` from the repository over it: that keeps LF endings (**never copy from a Windows checkout**: `\r` breaks the shell scripts) and leaves `.state/` and `secrets/` untouched.
2. **The environment file, sourced** (`set -a; . secrets/env.sh; set +a`). It must end with `unset ELASTIC_PASSWORD`, or `fleetctl.py` uses a stale password instead of `secrets/elastic/elastic.password` and Kibana answers 401.
3. **The VPN, checked over TCP**: `curl -sk -o /dev/null -w '%{http_code}\n' https://10.77.9.1/`. Any HTTP code is a pass; ICMP is dropped by design, so a ping proves nothing. After a firewall rebuild, deactivate and reactivate the tunnel.
4. **The workstation timers, healthy**: `python3 scripts/labops.py doctor`. Stale cron lines fail **silently**: no firewall flow events reach Elastic, and `labmode.py tick` never closes maintenance mode or the analysis Internet window. The fix is `/lab-workstation-setup`, which prints the crontab command for the operator when the harness refuses the edit — a skill never works around that refusal.

The guests a command needs may also be off: **Elastic** for policies, drains and enrolment; the **gateway** for any jump into the analysis zone (`ssh -J opaleye@10.77.2.10`). `/lab-status` reports their power state and `/lab-deploy` offers to start them.

## Safety contract

Every skill states these, and the guard is in the commands themselves, not in the skill:

- Confirm with the user before every destructive, mode-changing or power step: `apply`, `destroy`, `reset`, `shutdown`, `startup`, maintenance mode, the analysis Internet toggle, an analysis reset.
- `--acknowledge-loss` is never passed on the agent's own judgement: the user is asked, and their reason is recorded in the command and the report.
- Elastic destroy is not offered. `lab.sh` refuses it, `destroy all` skips it, and `--include-elastic` means a graceful **shutdown**. Evidence removal is `scripts/evidence_delete.py` (dry run plus confirmation phrase) and nothing else.
- The analysis zone stays isolated: Internet off by default and before any detonation, windows time-limited and never silently extended, rules never widened.
- No secrets are echoed; they are read from the operator env and `secrets/` only.
- A crontab edit the harness refuses is **printed for the operator, never worked around** (`/lab-workstation-setup`).
- A broken or compromised target is rebuilt, never hand-repaired.

## Drift guard

`tests/test_skills.py` (in `tests/static-checks.sh` and the unittest discovery) reads the skill files as data and fails when a skill drifts from the repo:

- the eight skills exist, each with frontmatter whose `name` matches its directory, a description long enough to be a trigger, and `disable-model-invocation: true`;
- every `scripts/`, `network/`, `tests/` and `playbooks/` path a skill names exists, and every relative link resolves;
- every subcommand a skill names **in a command span** (a fenced block or inline code, same line: prose mentioning a script is not an invocation) exists in that script's CLI — `labops.py`, `labmode.py` and `fleetctl.py` from their argparse choices, including the second level (`exercise start`, `analysis-sample end`); `netpolicy.py` and `guacctl.py` from their usage docstrings; `lab.sh`, `target.sh` and `ops-timers.sh` from their `case` branches;
- every `--flag` named on a line that mentions exactly one of those scripts appears in that script's source (a line naming none or several is attributed to nothing);
- each skill cites the document it is based on, and the README usage guide links each skill.

The check is deliberately not vacuous: `test_the_command_tables_are_not_empty` fails if a script's CLI stops being readable this way, and planted errors (`labops.py exercise stop`, `lab.sh nuke all`, `labops.py shutdown --force-it`) were each confirmed to fail the suite.

**What it cannot guard:** prose claims about behaviour, and the one piece of non-command code the skills carry — the read-only power-state snippet in `/lab-status` step 2, which imports `labpower` and `pve` because no repo command prints guest power state. It is the likeliest place for future drift. Giving `labops.py` a `power-status` command would remove it; that is a repo change, which #60 put out of scope.

## Verification record

**Offline, in a clean checkout (2026-11-03):** `python3 -m unittest tests.test_skills` passes (12 tests). The rest of the suite on this Windows checkout fails 32 tests that shell out to `scripts/*.sh` with mangled paths (`/bin/bash: C:Users...scriptslab.sh: No such file or directory`) — the README's documented "a few tests that call shell scripts fail on a Windows checkout"; none of them touches the skills. Run the suite in WSL for a clean pass. The read-only commands the skills lean on were run here without the lab: `netpolicy.py check`, `netpolicy.py lint exercise none|t1`, `netpolicy.py lint exercise none online` all `ok`; `labmode.py status` prints the state JSON; `labops.py`, `labmode.py` and `fleetctl.py --help` exit 0 and `guacctl.py` prints its usage (exit 2); the `lab-status` and `lab-malware-analysis` power-state snippets run and degrade to `unknown (set PROXMOX_VE_ENDPOINT and PVE_NODE)` with no token in the environment.

**Review pass (2026-11-03):** a standards review verified every command, subcommand, flag, path and link in the eight skills against the scripts and `network/plan.json` and found no invented flag or wrong behaviour claim; a spec review against #60 and its comment found two real errors, now fixed — `lab-maintenance` claimed a window could be extended by re-running `labmode.py maintenance` (it refuses while one is open; the skill now closes and reopens), and `lab-deploy` ran `labops.py startup` without a confirmation point.

**Still to do, live on the lab:** run each skill once against the real lab from WSL with the VPN up, and record the result here — `lab-status` and `lab-troubleshoot` end to end; `lab-deploy` as `plan` only plus a power-on; `lab-maintenance` with a short window; `lab-exercise-run` with a throwaway exercise id; `lab-teardown` reset flow on `t1`; `lab-malware-analysis` with a one-minute Internet window and an `analysis-reset`. Note anything the skill got wrong about the live commands as a correction to the skill, not as a local workaround.
