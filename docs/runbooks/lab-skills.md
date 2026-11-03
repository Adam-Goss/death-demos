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

Four more things the live checkout imposes, all found by running the skills on 2026-11-03:

- **Use a login shell.** `tofu` is at `/snap/bin/tofu`, which a non-login `bash -c` does not have on `PATH`: `lab.sh plan` then fails with `tofu: command not found`. Check `command -v tofu` before any Tofu step.
- **Call shell scripts with `bash`.** In the live checkout `scripts/lab.sh`, `scripts/ops-timers.sh` and `scripts/tunnel-keepalive.sh` are not executable (`-rw-r--r--`), so `scripts/lab.sh plan x` gives `Permission denied`. `bash scripts/lab.sh plan x` always works, so the skills use that form.
- **The env file may be missing variables that matter.** `PROXMOX_VE_API_TOKEN_ANALYSIS` is absent from the live `secrets/env.sh`, so `nicaudit.py` aborts with `KeyError: 'PROXMOX_VE_API_TOKEN_ANALYSIS'` and the analysis hosts' power state reads `unknown`. More dangerously, `TF_VAR_firewall_template_vm_id` is unset and defaults to `0`, which drops the firewall stack's `clone` block: **`plan firewall` then reports the firewall VM "must be replaced"**. Never apply a plan whose replacement you cannot explain; check the stack's variables first.
- **Restarting the Elastic tunnel is one command**: `bash scripts/tunnel-keepalive.sh` starts it in the background if port 19200 is closed, instead of occupying a terminal with `scripts/elastic-tunnel.sh`.

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

### Live run, 2026-11-03 (WSL, `/home/adam/wrasse-live`, VPN up)

**`/lab-status`, run end to end.** All ten steps executed. Result: the five lab guests `running`; mode `exercise` with **no target selected**; no active exercise or sample; Elasticsearch disk 5% (watermark 90%); 0 lagging events; `netpolicy.py lint` ok for exercise, exercise+t1, maintenance and exercise+online; `guacctl.py check` ok (default password gone, TOTP demanded); analysis Internet `off`; analysis generations flare 3, remnux 7. The Elastic VM now reports 16 GB (the #62 resize). Two checks did not pass, and both were real:

- `labops.py doctor`: `Elastic is not reachable ... <urlopen error timed out>`, repeatably, while every timer line read `ok`. Port 19200 had no listener and there was no `ssh -N` process: **the tunnel was down for more than ten minutes with cron running**. `bash scripts/tunnel-keepalive.sh` restored it in one go (19200 answered `401`, i.e. a live listener), after which `doctor: ok` with 31 firewall flow events in the last 15 minutes, and the tunnel was still up 90 seconds later. `.state/tunnel.log` ends in `Connection to 10.77.3.10 closed by remote host`, so it had been dropped from the far side, not misconfigured.
- `nicaudit.py`: aborted with `KeyError: 'PROXMOX_VE_API_TOKEN_ANALYSIS'`. The live env file has no analysis token, so the NIC audit and the analysis hosts' power state are **unknown, not a pass**.

**`/lab-troubleshoot`, exercised on those two symptoms** (ground state first, then the narrowest fix): diagnosed the dead tunnel from `doctor` + `pgrep` + a direct `19200` probe rather than from the timer lines, fixed it with the keepalive, and confirmed with `doctor`. The missing token was reported, not worked around.

**`/lab-deploy`, dry run only** (`plan`, no apply). `plan elastic`: **No changes**. `plan firewall`: **`proxmox_virtual_environment_vm.firewall must be replaced`** — traced to `TF_VAR_firewall_template_vm_id` being unset, which defaults to `0` and drops the stack's `clone` block (`vm_id 2101 -> null # forces replacement`). **An apply would have destroyed and recreated the firewall VM.** `plan targets`, `attacker`, `gateway`: `Backend initialization required` — only `firewall` and `elastic` are initialised in this checkout. Also found here: `tofu` is only on `PATH` in a login shell, and `scripts/lab.sh` has no exec bit. All four are now in the preconditions above and in the skills.

**`/lab-exercise-run`, run live end to end** as `ex-skill-001` on `t1` (generation 5). Preflight passed (VPN 200, tunnel `401`, disk 5%, `doctor: ok` with 235 flow events), `labmode.py select t1` applied, the marker was written, and the scripted attack on the attacker VM reported `command_output_seen: true` with the designed-to-fail callback `bash -c 'echo opaleye-ex-skill-001 > /dev/tcp/10.77.1.10/4444'`. `exercise end` tagged 234 events and a later `exercise tag` another 188. Counted straight from Elasticsearch, `lab.exercise_id: ex-skill-001` holds **309 events**: 87 `logs-endpoint.events.process-*`, 31 `logs-endpoint.events.network-*`, 4 `logs-apache.access-*`, 20 `logs-lab_firewall.flow-*`. One thing the skill now warns about: **`exercise show` immediately after `end` printed `(no end marker: exercise still running or never ended)`** — the marker was written (both markers were in `logs-lab_marker*` straight away) but not yet searchable; minutes later `show` printed the full window. The lab was left in exercise mode with `t1` selected and no active exercise; **`t1` has run a vulnerable app and should be treated as compromised until it is reset.**

**A2 reconnaissance (read-only, no mode change), 2026-11-03.** `bash scripts/a2-verify.sh exercise t1 lab` against the live state: **82 rows, 0 skipped, 24 `ERROR`, verdict FAIL**. Every source with a running VM matched its contract — attacker 14 deny / 1 allow, t1 14 / 4, gateway 11 / 5, elastic 8 / 1 — so the **live isolation is correct**. The 24 errors are sources that cannot be probed at all: `flare` 15, `remnux` 5, `t2` 4. `t2` has no VM (a probe guest fixes it, which is a firewall-stack apply). The analysis sources are a harder case: the firewall lets **only the gateway** into that zone, so the workstation cannot reach them, and probing them through the gateway (`PROBE_SSH="ssh -J opaleye@10.77.2.10 ..."`) breaks the attacker and Elastic rows, because the gateway reaches the attacker on RDP only and Elastic not at all. **One unfiltered zero-error run therefore cannot be produced since the analysis zone was added, so `REVERIFY=1` cannot succeed** — the per-vantage A2 set in the [malware-analysis runbook](malware-analysis.md) is what the live evidence actually uses, and `labmode.py reverified` is the only way to clear the flag afterwards. That is a gap in the repo, not in a skill: a fix would be per-source `PROBE_SSH` (or an analysis phase) in `a2-verify.sh`, and it wants its own issue. Until then the skills state the cost before the mode switch and leave the decision with the operator.

**The re-verify constraint, found while sequencing the remaining runs.** `REVERIFY=1 scripts/a2-verify.sh exercise none lab` only clears the flag on an unfiltered exercise/lab run with **zero skipped rows** (`a2-verify.sh` lines 214-218), and `SKIP_SOURCES` is explicitly refused. A clean run therefore needs probe guests for every zone without a running VM (`t2` always, plus `flare`/`remnux` while the analysis VMs are off), and creating them is a firewall-stack apply — which in this environment plans a **replacement of the firewall VM** until `TF_VAR_firewall_template_vm_id` is set. So **any maintenance window entered now leaves the lab unable to select a target** until that probe work is done; `labmode.py reverified` is the manual escape and is the operator's decision, not the agent's. `/lab-maintenance` and `/lab-teardown` now ask about this *before* the mode switch rather than discovering it afterwards.

**Still to do, live:** `/lab-maintenance` with a short window, `/lab-exercise-run` with a throwaway exercise id (it needs `labmode.py select t1` first — nothing is selected), `/lab-teardown`'s reset flow on `t1`, and `/lab-malware-analysis` with a one-minute Internet window plus an `analysis-reset` (needs the analysis token added first). Each changes lab state, so each waits for the operator. Note anything a skill gets wrong about the live commands as a correction to the skill, not as a local workaround.
