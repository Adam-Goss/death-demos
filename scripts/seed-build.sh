#!/usr/bin/env bash
# Build the OPNsense seed ISO (issue #31) that the firewall stack attaches when seeded.
# Thin wrapper over the generator: config comes from network/plan.json, secrets only from the
# operator environment (see scripts/opnsense_seed.py). Output lands in .state/ (gitignored).
set -eu
cd "$(dirname "$0")/.."
mkdir -p .state
python3 scripts/opnsense_seed.py iso --out .state/opnsense-seed.iso
echo ".state/opnsense-seed.iso built"
