---
name: lab-status
description: One-shot read-only health check of the Opaleye lab: VPN, guest power, mode and selected target, Elastic ingest and disk, firewall policy, NICs and gateway.
disable-model-invocation: true
---

# Lab status

A read-only sweep, safe to run at any time, including during an exercise. Every command below only reads; **this skill changes nothing** — no mode switch, no power action, no apply. When a check fails, hand the fix to `/lab-troubleshoot`, `/lab-workstation-setup` or `/lab-deploy` and say so.

Sources: [README "Using the lab"](../../../README.md#using-the-lab) and [command reference](../../../README.md#command-reference), [ops-timers runbook](../../../docs/runbooks/ops-timers.md), [malware-analysis runbook](../../../docs/runbooks/malware-analysis.md).

Run from WSL in the live checkout with the env file sourced and the VPN active.

## Steps

Run them all, even when an early one fails (note what the failure makes unknowable), then report one table.

1. **VPN, over TCP not ping**: `curl -sk -o /dev/null -w '%{http_code}\n' https://10.77.9.1/`. Any HTTP code means the tunnel works; ICMP is dropped by design, so a failed ping proves nothing. With no answer, every lab-side check below is `unknown`.
2. **Guest power state** (Proxmox API, read-only; needs the per-stack tokens in the env file):
   ```bash
   python3 - <<'PY'
   import sys; sys.path.insert(0, "scripts")
   import labpower, netpolicy, pve
   plan = netpolicy.load_plan()
   for g in labpower.guests(plan, True):
       try:
           print("%-9s %5d %s" % (g.label, g.vmid, pve.from_env(g.stack).status(g.vmid)))
       except (SystemExit, pve.PveError) as e:
           print("%-9s %5d unknown (%s)" % (g.label, g.vmid, e))
   PY
   ```
   The analysis VMs are not in that list (they are off by default): `/lab-malware-analysis` covers them.
3. **Mode and selection**: `python3 scripts/labmode.py status` — mode, selected target, maintenance expiry, the analysis Internet deadline, and whether the denies still need re-verifying. `python3 scripts/labops.py status` adds the operator state: any active exercise or sample, and the last recorded actions.
4. **Elastic tunnel, timers and firewall evidence**: `python3 scripts/labops.py doctor` — the three workstation timers, Elasticsearch reachable, and firewall flow events in the last `flow_stale_minutes`. Each `PROBLEM:` line names its own fix; stale or missing timers are `/lab-workstation-setup`. A stopped firewall expects no flow events.
5. **Disk watermark**: `python3 scripts/labops.py watermark`. At or over the plan's high watermark, new exercises are blocked and the only way down is guarded evidence deletion.
6. **Ingest lag**: `python3 scripts/fleetctl.py ingest-lag` fails when events were indexed later than `ingest_lag_seconds` after their timestamp. Needs the tunnel.
7. **Firewall policy**: `python3 scripts/netpolicy.py lint exercise <selected|none>` (add `online` when the analysis Internet window is on, and use `maintenance` when that is the current mode) proves the rendered ruleset still matches the A2 probe contract; `python3 scripts/netpolicy.py matrix exercise <selected|none>` prints the expected rows. These read `network/plan.json` and push nothing. A live probe run (`scripts/a2-verify.sh`) is a deployment-time gate, not part of this check.
8. **No path around the firewall**: `python3 scripts/nicaudit.py` exits non-zero if any guest has a second lab NIC or a home-bridge NIC.
9. **Gateway**: `python3 scripts/guacctl.py check` exits 1 if the default `guacadmin` password still works or TOTP is not being asked for.
10. **Analysis zone Internet**: `python3 scripts/labops.py analysis-online status`. `expired; the firewall rules close at the next tick` means the deadline has passed but the minute's `tick` has not run yet. Anything other than `off` is worth flagging.

## Done

Report a single table: check, result, and the fix (skill or command) for each failure. Say plainly which checks were `unknown` because the VPN, the tunnel or a token was missing, and end with one line: resting state (exercise mode, target selected, analysis offline, doctor ok) or not.
