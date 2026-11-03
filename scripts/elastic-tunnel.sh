#!/usr/bin/env bash
# SSH tunnel for the workstation's Elastic API calls (Ansible API tasks, a3-verify.sh services).
# The firewall lets the operator reach Elastic only on 5601 and 22, so 9200/8220 are forwarded over SSH
# and originate on the VM itself. Foreground; stop with ctrl-c. VPN up, key as given to Tofu.
set -eu
host=$(python3 -c "import json;print(json.load(open('$(dirname "$0")/../network/plan.json'))['hosts']['elastic']['ip'])")
# BatchMode and the keep-alives let cron (tunnel-keepalive.sh) run it unattended: no prompt, and a dead link exits so it is replaced.
exec ssh -N -o BatchMode=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=accept-new \
  -L 19200:127.0.0.1:9200 -L 18220:127.0.0.1:8220 "opaleye@$host"
