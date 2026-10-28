"""Lab guest power sequencing for shutdown/startup (issue #24). Power-state calls only, through scripts/pve.py."""
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pve  # noqa: E402

Guest = collections.namedtuple("Guest", "label stack vmid")
WANT = {"shutdown": "stopped", "startup": "running"}


def guests(plan, include_elastic):
    """Shutdown order: attacker, targets, [elastic], firewall."""
    g = [Guest("attacker", "attacker", plan["attacker"]["vm_id"])]
    g += [Guest(t, "targets", v["vm_id"]) for t, v in plan["targets"].items() if "vm_id" in v]
    if include_elastic:
        g.append(Guest("elastic", "elastic", plan["elastic"]["vm_id"]))
    g.append(Guest("firewall", "firewall", plan["firewall"]["vm_id"]))
    return g


def order(plan, action, include_elastic):
    g = guests(plan, include_elastic)
    return g if action == "shutdown" else g[::-1]  # startup: firewall first, attacker last


def running_targets(plan, include_elastic=False):
    """Targets currently running (so their forwarding should be drained before they are powered off)."""
    client = pve.from_env("targets")
    return [g.label for g in guests(plan, include_elastic) if g.stack == "targets" and client.status(g.vmid) == "running"]


def run(plan, action, include_elastic, wait, poll, say):
    """Gracefully shut down or start the guests in order. Returns the vmids that did not reach the wanted state."""
    want, failed, clients = WANT[action], [], {}
    for g in order(plan, action, include_elastic):
        c = clients.setdefault(g.stack, pve.from_env(g.stack))
        if c.status(g.vmid) == want:
            say("%s (%d): already %s" % (g.label, g.vmid, want))
            continue
        c.shutdown(g.vmid, int(wait)) if action == "shutdown" else c.start(g.vmid)
        ok = c.wait(g.vmid, want, wait, min(poll, 2))
        say("%s (%d): %s" % (g.label, g.vmid, want if ok else "NOT " + want))
        if not ok:
            failed.append(g.vmid)
    return failed
