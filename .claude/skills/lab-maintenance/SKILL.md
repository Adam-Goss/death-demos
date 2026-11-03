---
name: lab-maintenance
description: Run an Opaleye lab maintenance window: open a time-limited update allowlist, update attacker, gateway, target and Elastic packages, then return to exercise mode and re-verify the denies.
disable-model-invocation: true
---

# Lab maintenance

Package installs and image pulls only work in **maintenance mode**: a time-limited allowlist to the reviewed update sources that also closes every attacker-to-target flow. Procedure: [README step 6](../../../README.md#6-update-packages-and-images-maintenance) and [switching modes](../../../README.md#switching-modes-and-selecting-a-target); detail in the [M2](../../../docs/runbooks/m2-firewall-and-networks.md), [M3](../../../docs/runbooks/m3-elastic.md) and [M4](../../../docs/runbooks/m4-target.md) runbooks.

**Preconditions, step 0 for every run** — the live checkout (not a git worktree), the env file sourced and ending in `unset ELASTIC_PASSWORD` (a stale value makes `fleetctl.py` fail with a Kibana 401), the VPN checked over TCP, and healthy workstation timers (`python3 scripts/labops.py doctor`): **the maintenance window expires through the `tick` timer, so stale timers mean nothing closes it.** The four are spelled out once in the [skills runbook](../../../docs/runbooks/lab-skills.md#preconditions-for-every-skill); read it and check them before step 1.

**Exercise mode is the resting state.** Stay in maintenance only as long as the updates need, and never leave the window open at the end of a session. **Confirm with the user before entering maintenance mode and before each play.**

## Steps

Stop at a failing criterion and report it with its output.

1. **Scope the window, and check you can leave it again**: which guests are being updated (attacker, gateway, target, Elastic) and roughly how long. No exercise may be active (`python3 scripts/labops.py status`). Then the part that is easy to discover too late: leaving maintenance sets the re-verify flag, and step 6's `REVERIFY=1` run only clears it on **one unfiltered exercise/lab run with zero skipped rows and exit 0**. That is achievable (done live on 2026-11-03: `rows=82 skipped=0 PASS`) but needs preparation — probe guests for `t2` and `flare` with FLARE powered off, the gateway as the vantage for every zone the operator may not enter, and `ssh-keygen -R` on the probe addresses. **`/lab-teardown` step 0 is the full recipe; read it before opening the window.** If that preparation is not possible now, tell the user before the switch: the window will otherwise leave the lab with no selectable target, and the only other way out is `labmode.py reverified` on their explicit instruction. Criterion: the user confirms the scope, the minutes, and that the exit path is available.
2. **Elastic packages first, on the workstation**: Elastic never gets Internet access, even in maintenance mode. `python3 scripts/fleetctl.py fetch-packages` downloads the integration zips here and `upload-packages` verifies them against the pins in `network/plan.json` before uploading to Kibana. A pin mismatch stops the update: report it, do not relax the check. Criterion: `upload-packages` exits 0, or Elastic is out of scope.
3. **Open the window**: `python3 scripts/labmode.py maintenance --minutes N --reason "<text>"`. The reason is recorded; use the user's words. Criterion: `python3 scripts/labmode.py status` shows maintenance mode with an expiry. The window expires on its own through the `tick` timer, so **if the timers are stale nothing closes it** (`scripts/ops-timers.sh status`, `/lab-workstation-setup`).
4. **Update the guests in scope**:
   ```bash
   (cd ansible && ansible-playbook playbooks/attacker.yml)    # attacker tooling, XFCE/xrdp
   (cd ansible && ansible-playbook playbooks/gateway.yml)     # Guacamole images
   scripts/target.sh provision t1                             # target: Tofu at the current generation plus the target play
   (cd ansible && ansible-playbook playbooks/elastic.yml)     # Elastic, from the uploaded packages only
   ```
   Criterion: each play ends with no failed tasks. A timeout usually means the window closed or the source is not in the allowlist: check `labmode.py status` first, then re-run (a transient CDN address change is retried by the roles).
5. **Watch the clock**: a window is at most 120 minutes and `labmode.py maintenance` **refuses while one is already open** ("already in maintenance (until ...); wait for expiry or run `exercise`"). To extend, ask the user first, then close and reopen: `python3 scripts/labmode.py exercise none`, then `maintenance --minutes N --reason "<text>"`. Egress drops in between (re-run the play afterwards if it was mid-download), and closing sets the re-verify flag, which step 6 clears anyway. Criterion: the user approved the extension and `labmode.py status` shows the new expiry.
6. **Return to the resting state and re-verify the denies**:
   ```bash
   python3 scripts/labmode.py exercise none
   REVERIFY=1 scripts/a2-verify.sh exercise none lab
   python3 scripts/labmode.py select t1
   ```
   Leaving maintenance sets a flag: a target cannot be selected again until the exercise-mode denies are re-verified by that full unfiltered A2 run (it needs probe guests for zones without a real VM, here `t2`: see the [M2 runbook](../../../docs/runbooks/m2-firewall-and-networks.md)). Criterion: A2 passes and `select` succeeds.
7. **Confirm the lab is healthy**: `python3 scripts/labops.py doctor` and `python3 scripts/netpolicy.py lint exercise t1`. Criterion: `doctor: ok` (or understood problems) and the lint exits 0.

## Analysis zone

The analysis VMs do not use maintenance mode: their updates go through a time-limited Internet window and a new `clean` snapshot (`/lab-malware-analysis`, [malware-analysis runbook](../../../docs/runbooks/malware-analysis.md)). Never update them in place without re-taking the snapshot: the next analysis reset would undo it.

## Failure handling

- `maintenance` says already in maintenance: wait for the expiry or `labmode.py exercise none` (step 5).
- `fleetctl.py` gets a Kibana 401: `secrets/env.sh` in the live checkout carries a stale `ELASTIC_PASSWORD`. It must end with `unset ELASTIC_PASSWORD` so `fleetctl.py` reads `secrets/elastic/elastic.password` (`/lab-workstation-setup`).
- Elastic or the gateway powered off: the policy, drain and enrolment tasks cannot run. Offer to start them (`/lab-deploy`) before the plays.
- A firewall API error means the push was not confirmed: the firewall's dead-man job restores the last confirmed config within about a minute. Re-check `labmode.py status` before retrying.
- A play that fails halfway leaves the guest half-updated: re-run it (the roles are idempotent) inside the window, and never work around a block by widening a rule.
- If the A2 re-verification fails, stay out of exercise use and hand the failure to `/lab-troubleshoot`: an unverified deny is a hard gate, not a warning.

## Done

Report: the window (minutes and reason), the plays that ran and their results, whether the window was extended, the A2 re-verification result, and the end state (mode, selected target, `doctor`).
