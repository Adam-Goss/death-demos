#!/usr/bin/env bash
# A3 evidence (issue #22): Elastic and ingestion, run against the live lab with the VPN up.
#   a3-verify.sh services          health, version, TLS, lifecycle, snapshot restore, destroy guard
#   a3-verify.sh net <lab|vpn|home>  reachability of the Elastic ports from each vantage (a2-verify.sh, elastic rows only)
# `net lab` needs probe guests without the elastic one: TF_VAR_probe_zones='["attacker","t1","t2"]'.
# Run `net` in exercise mode with a target selected (labmode.py select t1); env as for a2-verify.sh.
set -u
cd "$(dirname "$0")/.."
case ${1:-} in
  services) exec python3 scripts/a3_verify.py ;;
  net) ONLY_DST=elastic exec scripts/a2-verify.sh exercise "${3:-t1}" "${2:?lab|vpn|home}" ;;
  *) echo "usage: a3-verify.sh services | net <lab|vpn|home> [target]" >&2; exit 2 ;;
esac
