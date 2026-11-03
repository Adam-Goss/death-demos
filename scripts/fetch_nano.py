#!/usr/bin/env python3
"""Fetch the pre-installed OPNsense nano image, verify its sha256 and decompress it (issue #31).

  fetch_nano.py URL SHA256 OUT

Runs on the operator workstation, not on Proxmox: the stack token has no Sys.* privilege, which
Proxmox's own download needs. Skips the download when OUT is already built for this sha256.
"""
import bz2
import hashlib
import os
import shutil
import sys
import urllib.request

CHUNK = 1 << 20


def fetch(url, sha256, out):
    """Return "built" or "up to date"; exit on a checksum mismatch (the download is discarded)."""
    stamp = out + ".sha256"
    if os.path.exists(out) and os.path.exists(stamp) and open(stamp).read() == sha256:
        return "up to date"
    tmp = out + ".bz2"
    digest = hashlib.sha256()
    with urllib.request.urlopen(url) as r, open(tmp, "wb") as f:
        for chunk in iter(lambda: r.read(CHUNK), b""):
            digest.update(chunk)
            f.write(chunk)
    if digest.hexdigest() != sha256:
        os.remove(tmp)
        raise SystemExit("nano image sha256 mismatch: " + digest.hexdigest())
    with bz2.open(tmp, "rb") as src, open(out, "wb") as dst:
        shutil.copyfileobj(src, dst, CHUNK)
    os.remove(tmp)
    with open(stamp, "w") as f:
        f.write(sha256)
    return "built"


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    print(sys.argv[3], fetch(*sys.argv[1:4]))
