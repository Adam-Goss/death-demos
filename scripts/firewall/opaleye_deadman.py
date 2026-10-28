#!/usr/local/bin/python3
"""Dead-man switch that runs ON the firewall (issue #32). Cron runs it every minute.

labmode.py brackets every rule push with two marker aliases, opaleye_pending and opaleye_confirmed, whose
descriptions carry a token. Equal tokens: the config is confirmed, and this job keeps a copy of it. Different
tokens: a push was made and not yet confirmed; if it stays that way past GRACE seconds the controller was cut
off, so the last confirmed config is put back and the filter reloaded. Stdlib only (OPNsense ships python3).

Env (tests): DEADMAN_CONFIG, DEADMAN_STATE, DEADMAN_GRACE, DEADMAN_NOW, DEADMAN_RELOAD ('' = skip).
"""
import os
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

PENDING, CONFIRMED = "opaleye_pending", "opaleye_confirmed"
RELOAD = ["configctl filter refresh_aliases", "configctl filter reload"]


def markers(config):
    try:
        root = ET.parse(config).getroot()
    except (OSError, ET.ParseError):
        return None, None  # mid-write or unreadable: do nothing this minute
    found = {a.findtext("name"): (a.findtext("description") or "") for a in root.iter("alias")}
    return found.get(PENDING), found.get(CONFIRMED)


def run(config, state, grace, now, reload_cmds):
    os.makedirs(state, exist_ok=True)
    good, since = os.path.join(state, "confirmed.xml"), os.path.join(state, "pending_since")
    pending, confirmed = markers(config)
    if pending is None or confirmed is None:
        return "unarmed"
    if pending == confirmed:
        shutil.copyfile(config, good + ".new")
        os.replace(good + ".new", good)
        if os.path.exists(since):
            os.remove(since)
        return "confirmed"
    first = None
    try:
        with open(since) as f:
            tok, ts = f.read().split()
        first = int(ts) if tok == pending else None
    except (OSError, ValueError):
        pass
    if first is None:
        with open(since, "w") as f:
            f.write("%s %d" % (pending, now))
        return "pending"
    if now - first < grace:
        return "pending"
    if not os.path.exists(good):
        return "no-backup"
    shutil.copyfile(good, config + ".revert")
    os.replace(config + ".revert", config)
    os.remove(since)
    for cmd in reload_cmds:
        subprocess.run(cmd.split(), check=False)
    return "reverted"


def main():
    env = os.environ
    reload_cmds = RELOAD if "DEADMAN_RELOAD" not in env else [c for c in [env["DEADMAN_RELOAD"]] if c]
    print(run(env.get("DEADMAN_CONFIG", "/conf/config.xml"), env.get("DEADMAN_STATE", "/var/db/opaleye"),
              int(env.get("DEADMAN_GRACE", "120")), int(env.get("DEADMAN_NOW") or time.time()), reload_cmds))


if __name__ == "__main__":
    sys.exit(main())
