#!/usr/bin/env bash
# Build the OPNsense seed ISO (issue #31) that the firewall stack attaches when seeded.
# Thin wrapper over the generator: config comes from network/plan.json, secrets only from the
# operator environment (see scripts/opnsense_seed.py). Output lands in .state/ (gitignored).
set -eu
cd "$(dirname "$0")/.."
mkdir -p .state
python3 scripts/opnsense_seed.py iso --out .state/opnsense-seed.iso
echo ".state/opnsense-seed.iso built"
# Pre-installed nano image: fetched here, not by Proxmox (the stack token has no Sys.* privilege).
# Unset OPNSENSE_NANO_URL/OPNSENSE_NANO_SHA256 to skip (installer path).
if [ -n "${OPNSENSE_NANO_URL:-}" ]; then
  : "${OPNSENSE_NANO_SHA256:?set OPNSENSE_NANO_SHA256 with OPNSENSE_NANO_URL}"
  python3 scripts/fetch_nano.py "$OPNSENSE_NANO_URL" "$OPNSENSE_NANO_SHA256" .state/opnsense-nano.raw
fi
