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
2. **The environment file, sourced** (`set -a; . secrets/env.sh; set +a`) **and parsing**: run `bash -n secrets/env.sh` first. A single unbalanced quote makes bash swallow the rest of the file, so the variables after it are silently missing while everything before it works — seen live on 2026-11-03, where a duplicate token line with a stray quote cost `GUAC_ADMIN_PASSWORD`, `ATTACKER_RDP_PASSWORD` and the closing `unset ELASTIC_PASSWORD`. Never read the error as "the variable is not configured" without checking the syntax. The file must end with `unset ELASTIC_PASSWORD`, or `fleetctl.py` uses a stale password instead of `secrets/elastic/elastic.password` and Kibana answers 401.
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

**A2 reconnaissance (read-only, no mode change), 2026-11-03.** `bash scripts/a2-verify.sh exercise t1 lab` against the live state: **82 rows, 0 skipped, 24 `ERROR`, verdict FAIL**. Every source with a running VM matched its contract — attacker 14 deny / 1 allow, t1 14 / 4, gateway 11 / 5, elastic 8 / 1 — so the **live isolation is correct**. The 24 errors are sources that cannot be probed at all: `flare` 15, `remnux` 5, `t2` 4. `t2` has no VM (a probe guest fixes it, which is a firewall-stack apply). The analysis sources are a harder case: the firewall lets **only the gateway** into that zone, so the workstation cannot reach them, and probing them through the gateway (`PROBE_SSH="ssh -J opaleye@10.77.2.10 ..."`) breaks the attacker and Elastic rows, because the gateway reaches the attacker on RDP only and Elastic not at all. **One unfiltered zero-error run therefore cannot be produced since the analysis zone was added, so `REVERIFY=1` cannot succeed** — the per-vantage A2 set in the [malware-analysis runbook](malware-analysis.md) is what the live evidence actually uses, and `labmode.py reverified` is the only way to clear the flag afterwards. That is a gap in the repo, not in a skill: a fix would be per-source `PROBE_SSH` (or an analysis phase) in `a2-verify.sh`. Filed as **#64**. Until then the skills state the cost before the mode switch and leave the decision with the operator.

**The re-verify constraint, found while sequencing the remaining runs.** `REVERIFY=1 scripts/a2-verify.sh exercise none lab` only clears the flag on an unfiltered exercise/lab run with **zero skipped rows** (`a2-verify.sh` lines 214-218), and `SKIP_SOURCES` is explicitly refused. A clean run therefore needs probe guests for every zone without a running VM (`t2` always, plus `flare`/`remnux` while the analysis VMs are off), and creating them is a firewall-stack apply — which in this environment plans a **replacement of the firewall VM** until `TF_VAR_firewall_template_vm_id` is set. So **any maintenance window entered now leaves the lab unable to select a target** until that probe work is done; `labmode.py reverified` is the manual escape and is the operator's decision, not the agent's. `/lab-maintenance` and `/lab-teardown` now ask about this *before* the mode switch rather than discovering it afterwards.

### Second live session, 2026-11-03 afternoon

**`/lab-malware-analysis`, sections A-C.** Both analysis VMs were already running (REMnux up 4 h), so nothing needed powering on. `nicaudit.py` passed once the analysis token was available and shows the expected bridges: FLARE 2020 and REMnux 2305 on `vmbr2020` alone, the firewall the only guest touching `vmbr0`. The access path checked out (`guacctl.py check` ok; `ssh -J opaleye@10.77.2.10 opaleye@10.77.20.11` answered). The Internet window behaved as designed **except for its timing**:

- `analysis-sample start skill-sample-001` was accepted before the window, as its ordering rule requires.
- `analysis-online on --minutes 1` applied, printed the detonation warning, and **egress was real**: from REMnux, `https://1.1.1.1/` returned `301`.
- After the deadline, `status` reported `expired; the firewall rules close at the next tick` at **30 s, 75 s and 135 s**, and REMnux still reached the Internet. `.state/tick.log` later showed `analysis internet expired: off`, so the tick did close it, but **minutes late** (the #52 live run measured about 45 s). The skill's rule earns its place: close it by hand and require `status` to say **`off`**, never `expired`, before a detonation. Closed by hand here: `analysis-online off` applied, and REMnux's egress went to `000` (blocked).
- `analysis-sample end` tagged **663** events and a repeat `tag` another **2**; `lab.sample_id: skill-sample-001` matches **665** events, and `lab.zone: analysis` **58,422**.

**The operator environment file, two real faults.** Sourcing printed `secrets/env.sh: line 31: unexpected EOF while looking for matching '`. Line 28 was a **duplicate `PROXMOX_VE_API_TOKEN_GATEWAY` with an unbalanced quote**, so bash swallowed lines 29-34: `GUAC_ADMIN_PASSWORD`, `ATTACKER_RDP_PASSWORD` **and the closing `unset ELASTIC_PASSWORD` never ran**. The visible symptoms were `guacctl.py check` failing with `set GUAC_ADMIN_PASSWORD` where it had passed an hour earlier, and a stale `ELASTIC_PASSWORD` left in the environment, which is exactly the Kibana 401 the preconditions warn about. Repaired (duplicate line removed, 0600 backup at `secrets/env.sh.bak-before-60`), and the analysis token added as `export PROXMOX_VE_API_TOKEN_ANALYSIS="$(cat .../secrets/proxmox/analysis.token)"` — the token was already on disk at **`secrets/proxmox/analysis.token`**, it simply was not exported. Separately, `secrets/env.sh.bak-before-52` was mode **755**: a token file anyone could read. After the repair, each of the six stack tokens answers `200` on its own pool, and `plan firewall` reports **No changes** — the replacement trap from the morning was the unset `TF_VAR_firewall_template_vm_id`, now set.

**`fleetctl.py ingest-lag` fails: 295 lagging events, every one `auditd_manager.auditd target=remnux`.** Clock drift was the obvious suspect, since the analysis zone deliberately gets no NTP — but the clocks agree (workstation 12:13:47Z, REMnux 12:13:48Z, t1 12:13:49Z), so this is a genuine shipping backlog out of the analysis zone. Consistent with that zone's telemetry being best effort; cause not established.

**`/lab-maintenance`, run live.** `drain t1` confirmed the marker arrived, `maintenance --minutes 30 --reason "..."` applied, and one update play inside the window succeeded: `playbooks/gateway.yml`, **ok=24 changed=3 failed=0**.

**`/lab-teardown`'s reset, run live — and it found a repo bug.** `labops.py reset t1` drained, bumped the generation to 6, then died: **`scripts/target.sh: line 35: scripts/lab.sh: Permission denied`**, because git records `scripts/lab.sh` as `100644` while `target.sh` calls it directly. The generation is bumped **before** the rebuild, so the target was left recorded at generation 6 with the old VM: the reset is not atomic. Filed as **#65**. Two further stumbles on the way to a finished rebuild, both worth knowing:

- the **`targets` stack had never been initialised** in this checkout (`tofu init`), and `target.sh` has no init step, so the rebuild failed again until `bash scripts/lab.sh init targets` was run;
- `target.sh provision` **does not wait for the rebuilt VM's sshd**, so the Ansible play failed `UNREACHABLE` on a VM that was still booting. Re-running the provision is the fix (the analysis reset path does wait, `LABOPS_SSH_WAIT`; the target path does not).

Past those three, the rebuild finished and proved itself: provision `ok=30 changed=17 failed=0`, `labops.py drain t1` confirmed a generation-6 marker in Elasticsearch, and `bash scripts/a5-verify.sh t1` returned **PASS** on every row — both DVWA image digests equal to the pins in `network/plan.json`, the login page `200`, security level `low`, the database created, the Agent `HEALTHY` and no enrolment token on disk outside the agent's own store. So the reset flow does work; it is the three stumbles above that stand between a clean checkout and a finished reset.

**Trying to clear the re-verify gate honestly (2026-11-03, after the reset).** Two attempts, and the gate is still closed:

1. **Per-source vantage.** `a2-verify.sh` takes one global `PROBE_SSH`, so an external wrapper was used to route only `10.77.20.0/24` sources through the gateway (`ssh -J opaleye@10.77.2.10`) and everything else direct — the fix #64 proposes, without touching the repo. It works for **REMnux**: its five rows went from 5 `ERROR` to fully probed (2 allow, 3 deny). `flare` stayed 15 `ERROR` because FLARE is **Windows** and cannot run the POSIX probe commands (`/dev/tcp`), which is why #52's evidence used a Linux probe guest at its address. Run verdict: 82 rows, 0 skipped, 19 `ERROR` (flare 15, t2 4), FAIL.
2. **Probe guests for `t2` and `flare`** (plan reviewed first: `2 to add, 0 to change, 0 to destroy`, at `10.77.12.10/24` on `vmbr2012` and `10.77.20.10/24` on `vmbr2020`), with FLARE powered off so the probe could take its address. `Apply complete! Resources: 2 added`, but **neither probe answered SSH within four minutes** (`10.77.12.10` direct, `10.77.20.10` through the gateway), so the matrix again reported 19 `ERROR`, `REVERIFY=1` recorded nothing, and `labmode.py select t1` was refused with `exercise-mode denies not re-verified since maintenance`. The probes were destroyed (`2 destroyed`) and FLARE powered back on.

**Diagnosed: the probe guests were never broken.** A third run kept one probe up (`t2` only, so FLARE was left alone; plan reviewed: `1 to add`) and asked what the failure actually was:

- **Direct route** to `10.77.12.10:22`: `Connection timed out`. Correct and by design — `netpolicy.py matrix` has **no `operator -> t2` allow row at all**; only `gateway -> t2`. The same is true of `flare` and `remnux` (`operator -> deny`, `gateway -> allow`). A probe guest in any of those zones is reachable **only through the gateway**, so the first wrapper, which jumped `10.77.20.*` but not `10.77.12.*`, was denied on a route it should not have used.
- **Gateway route**: `Host key verification failed`, sixteen times. The guest was up and sshd was answering the whole time. Probe guests are recreated at fixed addresses, so each new one has a **new host key**, and a stale `known_hosts` entry fails hard — `StrictHostKeyChecking=accept-new` only covers an *unknown* host, not a conflicting one. `scripts/target.sh` already does `ssh-keygen -R` after a rebuild for exactly this reason; the probe path has no equivalent.

After `ssh-keygen -R 10.77.12.10`, the probe answered immediately through the gateway: `probe-ok`, `Linux 6.12.113+deb13-cloud-amd64`, `eth0 10.77.12.10/24`. With the wrapper corrected to jump `10.77.12.*` as well, the `t2` rows probed (2 allow, 2 deny) and only `flare`'s 15 remained.

**The gate then cleared on its own merits.** Final run: FLARE powered off, the reviewed `1 to add` applied for `probe["flare"]`, both probe addresses' host keys cleared, both probes answering through the gateway, then

```
phase=lab mode=exercise selected=none rows=82 skipped=0 PASS
labmode: exercise-mode denies re-verified
```

`labmode.py select t1` applied, both probe guests destroyed (`0 added, 0 changed, 2 destroyed`), FLARE powered back on, analysis Internet `off`, `doctor: ok` with 1,154 firewall flow events. **No `labmode.py reverified` bypass was used.** This is the first full-matrix A2 pass that includes the analysis zone — the existing evidence in the [malware-analysis runbook](malware-analysis.md) is per-vantage — and it corrects the earlier conclusion recorded here: `REVERIFY=1` is not unachievable, it simply cannot be satisfied by the stock invocation. The recipe is four things, now in `/lab-teardown` step 0: probe guests for every zone with no running **Linux** VM (so `flare` as well as `t2`, because Windows cannot run the POSIX probes), the gateway as the vantage for every zone the operator may not enter, `ssh-keygen -R` on each probe address, and the gateway, Elastic, attacker and `t1` up for their own rows. Issue #64 remains the repo-side fix: `a2-verify.sh` takes one global `PROBE_SSH`, so the per-source routing needs a wrapper until it honours a vantage per source — and the probe path should clear host keys the way `target.sh` already does after a rebuild.

**Issue #64 is now fixed in the repo (no wrapper needed).** `netpolicy.py vantage <mode>` derives one probe vantage per lab-zone source from the probe table — a source whose SSH port the operator may not reach is probed through the single host the firewall does let in, which is the gateway for `t2`, `flare` and `remnux` — and `a2-verify.sh` builds each source's SSH command from that map, so the stock `REVERIFY=1 scripts/a2-verify.sh exercise none lab` covers every zone. `PROBE_SSH_<SOURCE>` (e.g. `PROBE_SSH_FLARE`) still replaces one source's command for an unusual run, and a `PROBE_SSH` that already jumps is left alone rather than jumped twice. The second gap in the comments is closed too: `RESET_HOST_KEYS="t2 flare"` clears those sources' stale `known_hosts` entries before probing, as `target.sh` does after a rebuild (nothing is cleared unasked — silently dropping a conflicting key for a real VM would hide the one thing that check is for), and the verifier prints the SSH error behind each unreachable source once, so the stale-host-key failure above no longer reads as a dead probe guest. The rest of the recipe is unchanged: probe guests for every zone with no running Linux VM (FLARE is Windows and can never be a probe source) and the real VMs up for their own rows.

**`labops.py analysis-reset`, run live (the last unexercised step).** Exit 0 in about two minutes for both hosts: Internet forced off first (already off), drain markers from REMnux and FLARE confirmed in Elasticsearch, both VMs reverted to `clean`, powered on, re-enrolled with a fresh token and registered — **REMnux generation 7 → 8** (agent `8fd0802f…`) and **FLARE 3 → 4** (agent `1f9356f9…`), each reported as `analysis; no firewall flow attribution`. No `--acknowledge-loss` was needed, since both agents were already enrolled. Two details for whoever reads the output next:

- `channel 0: open failed: connect failed: Connection refused` / `stdio forwarding failed` appears before each successful enrolment. That is the documented retry — a reverted VM is `running` before sshd answers — and **not** a failure. Do not re-issue starts.
- the host keys were cleared (`ssh-keygen -R 10.77.20.10 10.77.20.11`) **before** the run, and the output shows both keys being learned fresh. A rollback restores the snapshot's host keys, and `labops.py` SSHes with `StrictHostKeyChecking=accept-new`, which does not override a *conflicting* entry — so without that clearing the enrolment step can fail exactly like the A2 probes did. `labops.py` could do this itself, as `target.sh` does after a rebuild.

**Coverage: every skill has now been exercised live at least once**, which is the acceptance criterion of #60.

| Skill | Live evidence |
| --- | --- |
| `/lab-status` | All ten steps, twice; found the dead tunnel and the missing analysis token |
| `/lab-troubleshoot` | Dead tunnel, broken `env.sh`, the A2 probe route and host keys, the half-reset |
| `/lab-deploy` | `plan` on all five stacks, `init targets`, and three reviewed probe-guest applies |
| `/lab-exercise-run` | `ex-skill-001` on `t1` end to end; 309 events tagged |
| `/lab-maintenance` | 30-minute window with `playbooks/gateway.yml` (`ok=24 changed=3`) |
| `/lab-teardown` | Full `t1` reset to generation 6, A5 PASS, `attacker-clean`, and the re-verify exit path (`rows=82 skipped=0 PASS`) |
| `/lab-malware-analysis` | Isolation, Guacamole, the Internet window, sample markers (665 events), and `analysis-reset` (generations 8 and 4) |
| `/lab-workstation-setup` | Verified under #61; `doctor: ok` throughout this session |

`labops.py shutdown` is the one command inside these skills not exercised, since it powers the lab off; it is the same `labpower` path as `startup`, which was.

**Lab left as:** exercise mode with `t1` selected (rebuilt at generation 6, A5 PASS), denies re-verified, analysis zone reverted to `clean` and offline, probe guests destroyed, `doctor: ok`.
