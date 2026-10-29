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
  python3 - "$OPNSENSE_NANO_URL" "$OPNSENSE_NANO_SHA256" .state/opnsense-nano.raw <<'PY'
import bz2, hashlib, os, shutil, sys, urllib.request
url, want, out = sys.argv[1:4]
if os.path.exists(out) and os.path.exists(out + ".sha256") and open(out + ".sha256").read() == want:
    print(out, "up to date"); sys.exit(0)
tmp = out + ".bz2"
h = hashlib.sha256()
with urllib.request.urlopen(url) as r, open(tmp, "wb") as f:
    for chunk in iter(lambda: r.read(1 << 20), b""):
        h.update(chunk); f.write(chunk)
if h.hexdigest() != want:
    os.remove(tmp); sys.exit("nano image sha256 mismatch: " + h.hexdigest())
with bz2.open(tmp, "rb") as src, open(out, "wb") as dst:
    shutil.copyfileobj(src, dst, 1 << 20)
os.remove(tmp)
open(out + ".sha256", "w").write(want)
print(out, "built")
PY
fi
