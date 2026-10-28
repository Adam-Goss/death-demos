#!/usr/bin/env bash
# Render the OPNsense seed (issue #31) into a small ISO that the firewall stack attaches.
# Secrets come from the operator environment only; the output lands in .state/ (gitignored).
#   OPNSENSE_ROOT_PASSWORD   root password for the rebuilt VM
#   OPNSENSE_API_KEY, OPNSENSE_API_SECRET   the opaleye-api credential labmode.py already uses
#   OPNSENSE_WG_PRIVATE_KEY  firewall WireGuard private key (wg genkey)
set -eu
cd "$(dirname "$0")/.."
: "${OPNSENSE_ROOT_PASSWORD:?}" "${OPNSENSE_API_KEY:?}" "${OPNSENSE_API_SECRET:?}" "${OPNSENSE_WG_PRIVATE_KEY:?}"
tmpl=seed/opnsense/config.xml.tmpl
[ -f "$tmpl" ] || { echo "missing $tmpl: export config.xml and run scripts/seed-sanitize.py" >&2; exit 1; }
python3 -c 'import importlib.util as u,sys
sp = u.spec_from_file_location("s", "scripts/seed-sanitize.py"); m = u.module_from_spec(sp); sp.loader.exec_module(m)
bad = m.leaks(open(sys.argv[1]).read())
sys.exit("template holds: %s" % bad if bad else 0)' "$tmpl"
mkdir -p .state
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir -p "$work/conf"
hash() { printf '%s' "$1" | openssl passwd -6 -stdin; }
# Values go through python so XML-special characters are escaped and nothing touches argv.
ROOT_PASSWORD_HASH=$(hash "$OPNSENSE_ROOT_PASSWORD") API_SECRET_HASH=$(hash "$OPNSENSE_API_SECRET") \
API_KEY=$OPNSENSE_API_KEY WG_PRIVATE_KEY=$OPNSENSE_WG_PRIVATE_KEY \
python3 - "$tmpl" "$work/conf/config.xml" <<'PY'
import os, re, sys
from xml.sax.saxutils import escape
text = open(sys.argv[1]).read()
def sub(m):
    return escape(os.environ[m.group(1)])  # KeyError = unknown placeholder: fail loudly
open(sys.argv[2], "w").write(re.sub(r"@@([A-Z_]+)@@", sub, text))
PY
rm -f .state/opnsense-seed.iso
if command -v xorriso >/dev/null; then
  xorriso -as mkisofs -quiet -V OPNSEED -o .state/opnsense-seed.iso "$work"
elif command -v hdiutil >/dev/null; then
  hdiutil makehybrid -quiet -iso -joliet -default-volume-name OPNSEED -o .state/opnsense-seed.iso "$work"
else echo "need xorriso or hdiutil" >&2; exit 1; fi
echo ".state/opnsense-seed.iso built"
