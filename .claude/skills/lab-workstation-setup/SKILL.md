---
name: lab-workstation-setup
description: Install and verify the lab's workstation timers (labmode tick, firewall flow shipper, Elastic tunnel) in the live checkout.
disable-model-invocation: true
---

# Lab workstation setup

Run after a deployment, after moving or recreating the live checkout, or when `labops.py doctor` reports a problem. The timers are described in `docs/runbooks/ops-timers.md`; this skill performs the setup and proves it works.

**Known issue.** The timers were once hand-installed cron lines naming a checkout that was later removed. Cron failed silently: no firewall flow events reached Elastic for days, and the analysis Internet window and maintenance mode had no expiry. A **stale** line is the failure to look for; `scripts/ops-timers.sh status` names it.

## Steps

Each step ends when its criterion holds. Stop at a failing criterion and report it with its output.

1. **Find the live checkout**: the directory holding `.state/firewall.tfstate` and `secrets/env.sh`, which is where deployments and `labops.py` run (WSL: `~/wrasse-live`). Criterion: exactly one such directory found. With several, ask which one.
2. **Bring its scripts current**: it must contain `scripts/ops-timers.sh`. If it does not, extract `git -c core.eol=lf archive HEAD scripts network` from this repository over the live checkout, which leaves `.state/` and `secrets/` as they are. The `-c core.eol=lf` matters from a Windows checkout: `.gitattributes` pins only a few paths to LF, so the rest arrives CRLF (see precondition 1). Criterion: `bash scripts/ops-timers.sh status` runs in the live checkout (any exit code).
3. **Environment file**: `secrets/env.sh` exists, matches the operator's current env file (ask where it is, for example `env.sh.new`), and ends with `unset ELASTIC_PASSWORD` so `fleetctl.py` reads `secrets/elastic/elastic.password`. Keep a `.bak` copy before replacing. Criterion: `grep -c '^unset ELASTIC_PASSWORD' secrets/env.sh` is 1.
4. **Prerequisites**: the cron service runs (`pgrep -x cron`; WSL: `sudo service cron start`), the VPN is up (the firewall URL in `OPNSENSE_URL` answers), and the lab SSH key opens `opaleye@10.77.3.10` without a prompt (`ssh -o BatchMode=yes`). Criterion: all three answer.
5. **Install**: from the live checkout, `bash scripts/ops-timers.sh install`. This edits the user crontab; when that is refused, print the exact command for the operator to run and wait.
6. **Verify**: `bash scripts/ops-timers.sh status` exits 0, then after two minutes `python3 scripts/labops.py doctor` exits 0 with firewall flow events counted while the firewall runs. Criterion: doctor prints `doctor: ok`. Each `PROBLEM:` line names its fix.

## Done

Report the three timer lines as `ok`, the doctor result, and anything skipped (for example a stopped firewall means no flow events are expected).
