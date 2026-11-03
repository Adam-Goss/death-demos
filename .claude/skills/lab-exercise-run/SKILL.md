---
name: lab-exercise-run
description: Run an Opaleye exercise end to end: preflight the lab, start the exercise marker, run or hand over the attack, end and tag it, then point the operator at the evidence in Kibana.
disable-model-invocation: true
---

# Lab exercise run

Exercise 1 is command injection in DVWA's `low` security page, leading to a shell process on the target: it produces an Apache request, a process chain (web worker, shell, child) and a network event. Procedure: [README step 4](../../../README.md#4-run-an-exercise) and the [M5 runbook](../../../docs/runbooks/m5-attacker-operator.md); the hunt is described in the [M6 runbook](../../../docs/runbooks/m6-end-to-end-validation.md).

Run from WSL in the live checkout with the env file sourced and the VPN up.

**Attacks are the operator's work, not the agent's.** Run the scripted exercise only when the user asks for it; otherwise hand them the manual steps and wait. **Ask before any mode change, reset or `--acknowledge-loss`.**

## Steps

Stop at a failing criterion and report it with its output.

1. **Exercise id and target**: the id must match `^[a-z0-9][a-z0-9._-]{2,63}$` (the house style is `ex-001`) and only one exercise runs at a time. Criterion: the user gives an id and a target, and `python3 scripts/labops.py status` shows no active exercise.
2. **Preflight** (this is exactly what `exercise start` refuses on, checked first so the refusal is never a surprise):
   - VPN over TCP: `curl -sk -o /dev/null -w '%{http_code}\n' https://10.77.9.1/`.
   - Elastic tunnel up for `labops.py`: `scripts/elastic-tunnel.sh` in another terminal, or the tunnel timer.
   - `python3 scripts/labmode.py status`: **exercise mode with that target selected**, no maintenance window, denies re-verified.
   - `python3 scripts/labops.py watermark`: below the plan's high watermark.
   - `python3 scripts/labops.py doctor`: timers and firewall flow shipping healthy, so the run's evidence actually arrives.
   Criterion: all five pass.
3. **Fix the state if needed, with the user's agreement**: not in exercise mode or no target selected is `python3 scripts/labmode.py exercise none`, then (if the re-verify flag is set) `REVERIFY=1 scripts/a2-verify.sh exercise none lab`, then `python3 scripts/labmode.py select <target>`. A disk at the watermark is freed only through guarded evidence deletion, never by this skill. Anything else goes to `/lab-troubleshoot`. Criterion: step 2 now passes.
4. **Start the exercise**: `python3 scripts/labops.py exercise start <id> --target <t>`. This writes the start marker that tags the run. Criterion: it prints the exercise, the target and the generation.
5. **Run the attack** — one of:
   - *Scripted, when the user asks*: `ssh opaleye@10.77.1.10 exercise1 --exercise-id <id> --target <t>`.
   - *By hand (hand these over and wait)*: open `https://10.77.2.10/` (accept the self-signed certificate), log in as `guacadmin` with `GUAC_ADMIN_PASSWORD` plus the TOTP code, open the **attacker** desktop, browse to `http://10.77.11.10/`, log in `admin` / `password`, set security `low`, page **Command Injection**. Or `ssh opaleye@10.77.1.10` for a shell.
   Criterion: the user confirms the attack ran (or the script exits 0). The callback to the attacker on `:4444` is **blocked by design**: the attempt is itself evidence (a network event and firewall flow blocks), not a fault.
6. **End and tag**:
   ```bash
   python3 scripts/labops.py exercise end            # end marker; stamps lab.exercise_id on the window's events
   python3 scripts/labops.py exercise show <id>      # the window and target
   python3 scripts/labops.py exercise tag <id>       # events still in transit at the end; safe to repeat
   ```
   Criterion: `end` exits 0. If it warns that events were not tagged, re-run `exercise tag <id>` after a minute.
7. **Point at the evidence**: Kibana `https://10.77.3.10:5601` (user `elastic`, password in `secrets/elastic/elastic.password`, trust `secrets/elastic/ca/ca.crt`). Data views: `logs-endpoint.events.process-*`, `logs-endpoint.events.network-*`, `logs-apache.access-*`, `logs-auditd_manager.auditd-*`, `logs-lab_firewall.flow-*`. Filters: `lab.exercise_id: <id>`, `lab.target_id: <t>`, `lab.rebuild_generation: <n>` (from step 4), inside the window from `exercise show`. The hunt goes either way: process to request (a shell child of the web worker, then the matching `POST /vulnerabilities/exec/`) or request to process. Criterion: the user can see the run's events, or the gap is reported (`labops.py doctor`, `fleetctl.py ingest-lag`).
8. **Offer a reset**: the target ran a deliberately vulnerable app and is **treated as compromised**. Offer the reset flow (`/lab-teardown` section C: `drain`, maintenance, `reset`, `exercise none`, `REVERIFY=1` A2, `select`, `attacker-clean`) and only run it if the user agrees. Criterion: the user accepts or declines explicitly.

## Failure handling

- `exercise start` refused: not exercise mode with that target selected, Elastic down, or the disk at the watermark. Step 2 names which.
- `exercise start` says one is still active: `python3 scripts/labops.py exercise end` first (ask: ending someone else's run closes its window).
- No events in Kibana: check the tunnel and the shipper (`labops.py doctor`), the ingest lag (`fleetctl.py ingest-lag`), and that you are filtering on the right generation; then `exercise tag <id>`.
- Never leave an exercise active: it blocks shutdown, reset and evidence deletion.

## Done

Report: the exercise id, target and generation, how the attack was run, the markers written, the tag result, the Kibana filters to use, and whether a reset was run or declined.
