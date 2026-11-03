---
name: lab-troubleshoot
description: Diagnose and fix a broken Opaleye lab from a symptom: tunnel, mode, Elastic ingest, firewall rules, target, gateway or timers. Applies safe fixes, asks before destructive ones.
disable-model-invocation: true
---

# Lab troubleshoot

Symptom to diagnosis to fix. The authoritative symptom table is the [README troubleshooting section](../../../README.md#troubleshooting); the step-by-step repairs live in the runbooks ([M2 firewall and networks](../../../docs/runbooks/m2-firewall-and-networks.md), [M3 Elastic](../../../docs/runbooks/m3-elastic.md), [M4 target](../../../docs/runbooks/m4-target.md), [M5 attacker and operator](../../../docs/runbooks/m5-attacker-operator.md), [M6 end-to-end](../../../docs/runbooks/m6-end-to-end-validation.md), [gateway](../../../docs/runbooks/guacamole-gateway.md), [ops timers](../../../docs/runbooks/ops-timers.md), [malware analysis](../../../docs/runbooks/malware-analysis.md)). **Read the row and the runbook section before acting**; do not improvise a repair from memory.

**Preconditions, step 0 for every run** — the live checkout (not a git worktree), the env file sourced with `ELASTIC_PASSWORD` unset, the VPN checked over TCP, and the workstation timers (`python3 scripts/labops.py doctor`). The four are spelled out once in the [skills runbook](../../../docs/runbooks/lab-skills.md#preconditions-for-every-skill); read it and check them before diagnosing, because **three of the four are themselves the most common cause**: the wrong checkout, a stale `ELASTIC_PASSWORD`, a dropped tunnel or a silently dead cron line.

**Apply read-only diagnosis and reversible fixes freely. Ask the user first for anything that changes mode, power, infrastructure or evidence** — maintenance mode, `apply`, `reset`, `destroy`, `shutdown`, `evidence_delete.py`, `--acknowledge-loss`.

## Steps

1. **Capture the symptom**: the exact command, its full output and what the user expected. Criterion: you can quote the failing command and its error.
2. **Establish the ground state** before theorising: run `/lab-status` (or at least the VPN TCP check, `labmode.py status`, `labops.py status` and `labops.py doctor`). Most "broken lab" reports are a dropped tunnel, a stale timer or the wrong mode. Criterion: you know the mode, the selected target, whether Elasticsearch answers, and which guests are running.
3. **Match the symptom** to a README row below and read the referenced document. Criterion: one row fits the evidence. If none does, say so and investigate from the evidence rather than guessing, narrowing by layer: tunnel, firewall rule, guest power, in-guest service, Elastic ingest.

   | Symptom | First look | Where the fix is |
   | --- | --- | --- |
   | Tunnel "up", nothing answers | `curl -sk https://10.77.9.1/` (TCP, not ping) | README row 1: reactivate the tunnel after a firewall rebuild |
   | `select`/`exercise t1` says denies are not re-verified | `labmode.py status` | README: `exercise none`, `REVERIFY=1 scripts/a2-verify.sh exercise none lab`, `select t1` |
   | Already in maintenance | `labmode.py status` expiry | README: wait for expiry or `labmode.py exercise none` |
   | Package install or image pull times out | `labmode.py status` | `/lab-maintenance` (exercise mode blocks egress); re-run the play on a CDN change |
   | `labops.py` cannot reach Elasticsearch | `labops.py doctor` | `scripts/elastic-tunnel.sh`, or the tunnel timer: [ops timers](../../../docs/runbooks/ops-timers.md) |
   | No firewall flow events arriving | `labops.py doctor`, `scripts/ops-timers.sh status` | `/lab-workstation-setup` (a `STALE` line fails silently in cron) |
   | `exercise start` refused | `labmode.py status`, `labops.py watermark` | `/lab-exercise-run` preflight |
   | `reset` refused | `labmode.py status`, `labops.py drain t1` | `/lab-teardown` section C |
   | Guacamole login does nothing after the password | `guacctl.py check` | TOTP code; recovery in the [gateway runbook](../../../docs/runbooks/guacamole-gateway.md) |
   | Guacamole RDP: "X server could not be started" | — | `playbooks/attacker.yml` in maintenance mode (`xorgxrdp`) |
   | `tofu` wants backend initialisation | — | `scripts/lab.sh init <stack>` |
   | Scripts fail with `\r` | `file scripts/lab.sh` | CRLF checkout: run from WSL or a Linux clone |
   | Proxmox 403 on a new bridge after a firewall rebuild | — | Per-stack token needs its own `SDN.Use` ACL: gateway runbook live-run notes |
   | Analysis zone has no Internet, or still has it | `labops.py analysis-online status` | [malware-analysis runbook](../../../docs/runbooks/malware-analysis.md) and `/lab-malware-analysis` |
   | Firewall rules look wrong | `netpolicy.py lint <mode> <selected> [online]` | [M2 runbook](../../../docs/runbooks/m2-firewall-and-networks.md); rules come from `network/plan.json`, never the GUI |
   | A mode change did not stick | `labmode.py status` | The firewall dead-man job reverts an unconfirmed push within about a minute; re-push with `labmode.py` |

4. **Apply the smallest fix that the document prescribes**, one at a time, and re-run the check that failed. Criterion: the original command now succeeds. Ask before any state-changing step, naming what it changes.
5. **When the fix is a rebuild**, hand over rather than improvising: a broken or compromised target is rebuilt (`/lab-teardown` section C), a stack is re-applied (`/lab-deploy`), the analysis VMs revert to their `clean` snapshot (`/lab-malware-analysis`). **Never hand-repair a target that ran an exercise**: treat it as compromised.
6. **Leave the lab in its resting state**: exercise mode, target selected, denies re-verified, analysis Internet off. Criterion: `/lab-status` reports the resting state, or the remaining gap is named.

## Boundaries

- Never widen a firewall rule, add a route, a port or a NIC to work around a block: the block is usually the design ([ADR 0001](../../../docs/adr/0001-isolate-the-attack-lab-behind-a-firewall-vm.md), README "Safety rules"). The exercise callback to `:4444` being blocked, the operator not reaching DVWA or Elasticsearch `9200`, and the analysis zone having no route out are all expected.
- Never echo secrets. Read them from the operator env and `secrets/` only; quote error text, not credentials.
- Day-to-day firewall changes go through `labmode.py`, not the OPNsense GUI.
- If a symptom turns out to be a bug or a missing guard in the repo, report it (and raise an issue) instead of patching around it.

## Done

Report: the symptom, the evidence that identified it, the fix applied (with every state-changing command named), whether the original command now works, and the lab's end state.
