# Workstation timers runbook

Three jobs run on the operator workstation (WSL, cron) and the lab depends on them:

| Timer | What it does | If it is dead |
| --- | --- | --- |
| `opaleye-labmode-tick` | `labmode.py tick` every minute | maintenance mode and the analysis Internet window never expire on their own |
| `opaleye-firewall-flow` | `firewall_flow.py` ships the firewall's flow logs to Elastic | firewall evidence stops arriving (nothing fails loudly) |
| `opaleye-elastic-tunnel` | `tunnel-keepalive.sh` starts `elastic-tunnel.sh` when port 19200 is closed | the flow shipper and `labops.py` cannot reach Elasticsearch |

## Install and check

```
scripts/ops-timers.sh install    # all three, for THIS checkout; replaces lines by tag, so re-running after moving the checkout repairs them
scripts/ops-timers.sh status     # exit 1 if one is missing, points at a directory that no longer exists, or runs in another checkout
scripts/ops-timers.sh remove
python3 scripts/labops.py doctor # timers + Elastic reachable + firewall flow events in the last 15 minutes (exit 1 on any problem)
```

`scripts/lab.sh apply all` installs them at the end, and `labops.py startup` warns when they are not healthy. A failed install never fails a deployment.

Needs: the cron service (WSL: `sudo service cron start`), `secrets/env.sh` (the tick and flow jobs read it; `unset ELASTIC_PASSWORD` in it so `fleetctl.py` uses `secrets/elastic/elastic.password`), the VPN, and an SSH key for the Elastic VM without a passphrase (the tunnel runs unattended with `BatchMode`).

## Setup by skill

`/lab-workstation-setup` (`.claude/skills/lab-workstation-setup/SKILL.md`) does the whole setup in the live checkout and proves it: finds the checkout, brings its scripts current, refreshes `secrets/env.sh`, checks cron, the VPN and the tunnel key, installs the timers and confirms with `labops.py doctor`. Run it after a deployment, after the live checkout moves, or when `doctor` reports a problem. It is user-invoked only: it edits the crontab, and the agent prints the command for you to run when that edit is refused.

## Known issue: silent stale timers

Hand-installed timers name the checkout they were installed from. When that checkout is removed or renamed, cron fails silently every minute: firewall flow logs stop reaching Elastic and the analysis Internet window and maintenance mode never expire. Detect it with `scripts/ops-timers.sh status` (`STALE`) or `labops.py doctor`; fix it by running `scripts/ops-timers.sh install` from the live checkout.

## What happened without this

The three lines were installed by hand and named a checkout that was later removed, so cron failed silently every minute: no firewall events reached Elastic after 2026-10-30, and the analysis Internet window would not have closed itself. `ops-timers.sh status` reports exactly that as `STALE`.

## Limits

- The jobs live on the workstation: a sleeping laptop or a stopped WSL pauses the shipping and the auto-off. `labops.py doctor` is how you notice.
- The flow shipper polls every five seconds; a burst of more than about 100 rows between polls can be lost (see `firewall_flow.py`).
