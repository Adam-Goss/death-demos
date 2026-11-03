---
name: lab-status
description: One-shot read-only health check of the Opaleye lab: VPN, guest power, mode and selected target, Elastic ingest and disk, firewall policy, NICs and gateway.
disable-model-invocation: true
---

# Lab status

A read-only sweep, safe to run at any time, including during an exercise. Every command below only reads; **this skill changes nothing** — no mode switch, no power action, no apply. When a check fails, hand the fix to `/lab-troubleshoot`, `/lab-workstation-setup` or `/lab-deploy` and say so.

Sources: [README "Using the lab"](../../../README.md#using-the-lab) and [command reference](../../../README.md#command-reference), [ops-timers runbook](../../../docs/runbooks/ops-timers.md), [malware-analysis runbook](../../../docs/runbooks/malware-analysis.md).

**Preconditions, step 0** — the live checkout (not a git worktree: it is the one holding `.state/*.tfstate` and `secrets/env.sh`), the env file sourced with `ELASTIC_PASSWORD` unset, and the VPN up. The four preconditions are spelled out once in the [skills runbook](../../../docs/runbooks/lab-skills.md#preconditions-for-every-skill); the fourth, the workstation timers, is step 4 below rather than a precondition, because reporting on it is this skill's job. Checking from the wrong checkout reports another lab's state: say which directory the report came from.

## Steps

Run them all, even when an early one fails (note what the failure makes unknowable), then report one table.

1. **VPN, over TCP not ping**: `curl -sk -o /dev/null -w '%{http_code}\n' https://10.77.9.1/`. Any HTTP code means the tunnel works; ICMP is dropped by design, so a failed ping proves nothing. With no answer, every lab-side check below is `unknown`.
2. **Guest power state.** No repo command prints it, so read it through the repo's own modules — read-only, power-state `GET`s with each stack's token (`scripts/pve.py` has no delete or config call at all). This snippet is the single copy; the other skills point here for power state:
   ```bash
   python3 - <<'PY'
   import sys; sys.path.insert(0, "scripts")
   import labpower, netpolicy, pve
   plan = netpolicy.load_plan()
   guests = [(g.label, g.stack, g.vmid) for g in labpower.guests(plan, True)]
   guests += [(name, "analysis", h["vm_id"]) for name, h in plan["analysis"]["hosts"].items()]
   for label, stack, vmid in guests:
       try:
           print("%-9s %5d %s" % (label, vmid, pve.from_env(stack).status(vmid)))
       except (SystemExit, pve.PveError) as e:
           print("%-9s %5d unknown (%s)" % (label, vmid, e))
   PY
   ```
   Expected: the five lab guests `running`, and the two analysis VMs (`flare`, `remnux`) `stopped` — they are off by default and a lab startup does not touch them. Elastic being off blocks policies, drains and enrolment; the gateway being off blocks every jump into the analysis zone. `/lab-deploy` starts them, with the user's confirmation.
3. **Mode and selection**: `python3 scripts/labmode.py status` — mode, selected target, maintenance expiry, the analysis Internet deadline, and whether the denies still need re-verifying. `python3 scripts/labops.py status` adds the operator state: any active exercise or sample, and the last recorded actions.
4. **Elastic tunnel, timers and firewall evidence**: `python3 scripts/labops.py doctor` — the three workstation timers, Elasticsearch reachable, and firewall flow events in the last `flow_stale_minutes` (15). Then `bash scripts/ops-timers.sh status`, which names a **`STALE`** line: a cron line pointing at a checkout that no longer exists fails **silently** every minute, so firewall evidence stops arriving and `labmode.py tick` never closes maintenance mode or the analysis Internet window. This is the single most important row in the report. Each `PROBLEM:` line names its own fix; stale or missing timers are `/lab-workstation-setup`. A stopped firewall expects no flow events.
5. **Disk watermark**: `python3 scripts/labops.py watermark`. At or over the plan's high watermark, new exercises are blocked and the only way down is guarded evidence deletion.
6. **Ingest lag**: `python3 scripts/fleetctl.py ingest-lag` fails when events were indexed later than `ingest_lag_seconds` after their timestamp. Needs the tunnel.
7. **Firewall policy**: `python3 scripts/netpolicy.py lint exercise <selected|none>` (add `online` when the analysis Internet window is on, and use `maintenance` when that is the current mode) proves the rendered ruleset still matches the A2 probe contract; `python3 scripts/netpolicy.py matrix exercise <selected|none>` prints the expected rows. These read `network/plan.json` and push nothing. A live probe run (`scripts/a2-verify.sh`) is a deployment-time gate, not part of this check.
8. **No path around the firewall**: `python3 scripts/nicaudit.py` exits non-zero if any guest has a second lab NIC or a home-bridge NIC.
9. **Gateway**: `python3 scripts/guacctl.py check` exits 1 if the default `guacadmin` password still works or TOTP is not being asked for.
10. **Analysis zone Internet**: `python3 scripts/labops.py analysis-online status`. `expired; the firewall rules close at the next tick` means the deadline has passed but the minute's `tick` has not run yet. Anything other than `off` is worth flagging.

## Failure handling

This skill reports; it does not repair. For each failed check, name the owner and stop there:

- VPN silent, or silent after a firewall rebuild: reactivate the tunnel, then `/lab-troubleshoot`.
- A guest `unknown` for want of a token, or `PROXMOX_VE_ENDPOINT`/`PVE_NODE` unset: the env file is not sourced, or not the live checkout's. Say which directory you ran in.
- Guests `stopped` that should be running: `/lab-deploy` (it asks before powering anything on).
- Timers stale or missing, or `doctor` reporting no flow events while the firewall runs: `/lab-workstation-setup`.
- **`ops-timers.sh status` all `ok` but `doctor` says Elastic is not reachable**: the tunnel is down and the crontab check cannot see that — it only reads the cron lines. Confirm with `curl -sk -m 10 -o /dev/null -w '%{http_code}\n' https://127.0.0.1:19200/` (`000` means no listener), then restart it with one command: `bash scripts/tunnel-keepalive.sh`. Re-run `doctor`. Seen live on 2026-11-03: down for over ten minutes with cron running and every timer line `ok`; one keepalive run fixed it and it stayed up. If it keeps dying, look at `.state/tunnel.log` (`Connection to 10.77.3.10 closed by remote host`) and say so rather than looping.
- `nicaudit.py` aborting with `KeyError: 'PROXMOX_VE_API_TOKEN_ANALYSIS'`: the env file has no analysis token, so the audit cannot read pool `lab-analysis`. The audit result is **unknown, not a pass** — report it that way and ask the operator to add the token ([malware-analysis runbook](../../../docs/runbooks/malware-analysis.md), "Provision (once)").
- `fleetctl.py ingest-lag` failing with a Kibana 401: `secrets/env.sh` must end with `unset ELASTIC_PASSWORD`.
- `netpolicy.py lint`, `nicaudit.py` or `guacctl.py check` failing: a policy, NIC-path or gateway-credential problem. These are hard gates, not warnings — report them as such and hand them to `/lab-troubleshoot`.
- Analysis Internet not `off`: `/lab-malware-analysis` (never leave a window open at the end of a session).

## Done

Report a single table: check, result, and the fix (skill or command) for each failure. Say plainly which checks were `unknown` because the VPN, the tunnel or a token was missing, and end with one line: resting state (exercise mode, target selected, analysis offline, doctor ok) or not.
