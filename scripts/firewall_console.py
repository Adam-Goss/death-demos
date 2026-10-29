#!/usr/bin/env python3
"""Drive the OPNsense serial console once, to import the config seed into the template disk (#41).

  firewall_console.py SOCKET [DEVICE]

Used only by scripts/make-firewall-template.sh, on the Proxmox node as root, against the template
builder VM's serial socket (/var/run/qemu-server/<vmid>.serial0). Clones of the template never see a
console. Success is read from exit status (a computed marker), never from the importer's prose.
"""
import socket
import sys
import time

LOGIN = b"login: "
PASSWORD = b"Password:"
MENU = b"Enter an option:"
# The nano image ships root/opnsense until the seed replaces it (which is what we are importing).
NANO_USER = "root"
NANO_PASSWORD = "opnsense"
PROMPT = b"# "
IMPORTED = b"IMPORT-OK-42"
VERIFIED = b"CONFIG-OK-42"
# 6*7 is expanded by the shell, so the echoed command line never contains the marker itself.
CONFIG_CHECK = "grep -q opaleye-api /conf/config.xml && echo CONFIG-OK-$((6*7))"


class ConsoleError(Exception):
    pass


class UnixLink:
    """Serial socket with a short read timeout so callers can poll a deadline."""

    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(0.1)
        self.sock.connect(path)

    def read(self, n):
        try:
            return self.sock.recv(n)
        except socket.timeout:
            return b""

    def write(self, data):
        self.sock.sendall(data)


def _expect(link, marker, timeout, seen):
    """Wait for `marker` (or any of a tuple of markers); return the one that matched."""
    markers = marker if isinstance(marker, tuple) else (marker,)
    deadline = time.monotonic() + timeout
    while True:
        for m in markers:
            if m in seen[0]:
                return m
        if time.monotonic() > deadline:
            raise ConsoleError("timed out waiting for %r; last output: %r" % (marker, seen[0][-200:]))
        chunk = link.read(4096)
        if chunk:
            seen[0] += chunk
        else:
            time.sleep(0.01)


def _send(link, line, seen):
    seen[0] = b""
    link.write(line.encode() + b"\n")


def import_seed(link, device="cd0", timeout=300):
    """Menu -> shell -> opnsense-importer -> check the config landed -> power off."""
    seen = [b""]
    link.write(b"\n")  # the menu may already have been printed before we connected
    _expect(link, MENU, timeout, seen)
    _send(link, "8", seen)
    _expect(link, PROMPT, timeout, seen)
    _send(link, "opnsense-importer %s && echo IMPORT-OK-$((6*7))" % device, seen)
    _expect(link, IMPORTED, timeout, seen)
    _send(link, CONFIG_CHECK, seen)
    _expect(link, VERIFIED, timeout, seen)
    _send(link, "poweroff", seen)


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        raise SystemExit(__doc__)
    try:
        import_seed(UnixLink(sys.argv[1]), *sys.argv[2:3])
    except ConsoleError as e:
        raise SystemExit("console import failed: " + str(e))
