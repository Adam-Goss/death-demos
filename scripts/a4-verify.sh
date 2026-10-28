#!/usr/bin/env bash
# A4 evidence (issue #23): run from the workstation, VPN up, scripts/elastic-tunnel.sh running, after the target has
# produced traffic. Usage: a4-verify.sh <target> [generation]. Paste the unedited table into docs/runbooks/m4-target.md.
set -u
cd "$(dirname "$0")/.."
exec python3 scripts/a4_verify.py "${1:?usage: a4-verify.sh <target> [generation]}" ${2:+"$2"}
