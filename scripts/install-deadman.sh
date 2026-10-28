#!/usr/bin/env bash
# Installs the dead-man switch on the firewall (issue #32): copies the job and a configd action over SSH as root.
# Usage: scripts/install-deadman.sh <firewall-ssh-host>   (admin SSH is a one-off, like the manual first boot)
# Then add the cron job in the GUI (System > Settings > Cron: every minute, command "Opaleye dead-man switch")
# and run `labmode.py arm`.
set -euo pipefail
cd "$(dirname "$0")/.."
host=${1:?usage: install-deadman.sh <firewall-ssh-host>}
scp scripts/firewall/opaleye_deadman.py "root@$host:/usr/local/sbin/opaleye_deadman.py"
ssh "root@$host" 'chmod 755 /usr/local/sbin/opaleye_deadman.py && mkdir -p /var/db/opaleye &&
cat > /usr/local/opnsense/service/conf/actions.d/actions_opaleye.conf <<CONF
[deadman]
command:/usr/local/sbin/opaleye_deadman.py
parameters:
type:script
message:Opaleye dead-man switch
description:Opaleye dead-man switch
CONF
service configd restart'
echo "installed. Next: GUI cron job for \"Opaleye dead-man switch\" every minute, then: python3 scripts/labmode.py arm"
