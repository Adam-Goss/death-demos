#!/usr/bin/env python3
"""Exercise / maintenance mode controller for the lab firewall (issue #21).

  labmode.py exercise [target|none]          rules for exercise mode, optional selected target
  labmode.py select <target|none>            change the selected target (exercise mode only)
  labmode.py maintenance --minutes N --reason TEXT
                                             time-limited update allowlist; closes all attacker->target flows
  labmode.py tick                            run from a timer: leaves maintenance once it has expired
  labmode.py reverified                      record that exercise-mode denies were re-verified (a2-verify.sh)
  labmode.py denylog SRC DST PORT            exit 0 if the firewall logged that block
  labmode.py status

Env: OPNSENSE_NO_SAVEPOINT=true (OPNsense core has no savepoint API: apply without auto-revert),
     OPNSENSE_URL, OPNSENSE_API_KEY, OPNSENSE_API_SECRET, OPNSENSE_INSECURE=true (self-signed),
     LABMODE_STATE_DIR (default .state), LAB_PLAN. Every change goes savepoint -> apply -> confirm, so a
     change that cuts the controller off reverts on its own. State and audit log stay on the workstation.
"""
import argparse
import getpass
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netpolicy  # noqa: E402
import opnsense  # noqa: E402

PREFIX = "opaleye:"
PROTO = {"tcp": "TCP", "udp": "UDP", "any": "any"}


def now():
    return int(os.environ.get("LABMODE_NOW") or time.time())


def desired(plan, mode, selected):
    """OPNsense payloads keyed by description. One rule per port: ports are not a list in the rule form."""
    out = {}
    for seq, r in enumerate(netpolicy.render_rules(plan, mode, selected), start=1):
        for port in (r["ports"] or [""]):
            desc = PREFIX + r["id"] + (":%s" % port if port != "" else "")
            out[desc] = {"enabled": "1" if r["enabled"] else "0", "action": r["action"], "quick": "1",
                         "interface": r["iface"], "direction": "in", "ipprotocol": r["family"],
                         "protocol": PROTO[r["proto"]], "source_net": r["src"], "destination_net": r["dst"],
                         "destination_port": str(port), "log": "1" if r["log"] else "0",
                         "sequence": str(seq), "description": desc}
    return out


def sync(client, plan, mode, selected):
    client.ensure_alias(netpolicy.UPDATE_ALIAS, plan["update_sources"], "Opaleye maintenance update sources")
    want = desired(plan, mode, selected)
    have = client.rules(PREFIX)
    adds = [d for d in want if d not in have]
    sets = [d for d in want if d in have and any(str(have[d].get(k)) != v for k, v in want[d].items())]
    dels = [d for d in have if d not in want]
    if not (adds or sets or dels):
        return False
    rev = client.savepoint()
    for d in adds:
        client.add_rule(want[d])
    for d in sets:
        client.set_rule(have[d]["uuid"], want[d])
    for d in dels:
        client.del_rule(have[d]["uuid"])
    client.apply(rev)
    client.cancel_rollback(rev)  # reached only if apply answered; otherwise the firewall reverts itself
    return True


class Lab:
    def __init__(self):
        self.plan = netpolicy.load_plan(os.environ.get("LAB_PLAN", netpolicy.DEFAULT_PLAN))
        d = os.environ.get("LABMODE_STATE_DIR", ".state")
        os.makedirs(d, exist_ok=True)
        self.state_path, self.log_path = os.path.join(d, "labmode.json"), os.path.join(d, "labmode.log")
        try:
            with open(self.state_path) as f:
                self.st = json.load(f)
        except FileNotFoundError:
            self.st = {"mode": None, "selected": None, "expires": None, "reverify_required": False}

    def client(self):
        url, key, sec = (os.environ.get(k) for k in ("OPNSENSE_URL", "OPNSENSE_API_KEY", "OPNSENSE_API_SECRET"))
        if not (url and key and sec):
            raise SystemExit("set OPNSENSE_URL, OPNSENSE_API_KEY, OPNSENSE_API_SECRET")
        return opnsense.Client(url, key, sec, os.environ.get("OPNSENSE_INSECURE") == "true",
                               allow_no_savepoint=os.environ.get("OPNSENSE_NO_SAVEPOINT") == "true")

    def commit(self, event, **detail):
        with open(self.state_path, "w") as f:
            json.dump(self.st, f)
        with open(self.log_path, "a") as f:
            f.write(json.dumps(dict(ts=now(), event=event, user=getpass.getuser(), mode=self.st["mode"],
                                    selected=self.st["selected"], **detail)) + "\n")

    def set_mode(self, event, mode, selected, **detail):
        changed = sync(self.client(), self.plan, mode, selected)
        print("%s (selected: %s): %s" % (mode, selected or "none", "applied" if changed else "no changes"))
        self.st.update(mode=mode, selected=selected, expires=detail.pop("expires", None))
        self.commit(event, **detail)

    def need_target(self, name):
        if name not in (None, "none") and name not in self.plan["targets"]:
            raise SystemExit("unknown target %s" % name)
        return None if name in (None, "none") else name

    def exercise(self, target):
        target = self.need_target(target)
        if target and self.st["reverify_required"]:
            raise SystemExit("exercise-mode denies not re-verified since maintenance: run: REVERIFY=1 scripts/a2-verify.sh exercise none lab")
        back = self.st["mode"] == "maintenance"
        self.set_mode("exercise", "exercise", target)
        if back:
            self.st["reverify_required"] = True
            self.commit("reverify-required")

    def select(self, target):
        if self.st["mode"] != "exercise":
            raise SystemExit("not in exercise mode")
        self.exercise(target)

    def maintenance(self, minutes, reason):
        if self.st["mode"] == "maintenance":
            raise SystemExit("already in maintenance (until %s); wait for expiry or run `exercise`" % self.st["expires"])
        limit = self.plan["maintenance"]["max_minutes"]
        if not reason.strip():
            raise SystemExit("--reason is required")
        if not 0 < minutes <= limit:
            raise SystemExit("--minutes must be 1..%d" % limit)
        self.set_mode("maintenance-on", "maintenance", None, expires=now() + minutes * 60,
                      minutes=minutes, reason=reason)

    def tick(self):
        if self.st["mode"] == "maintenance" and self.st["expires"] is not None and now() >= self.st["expires"]:
            sync(self.client(), self.plan, "exercise", None)
            print("maintenance expired: back to exercise mode")
            self.st.update(mode="exercise", selected=None, expires=None, reverify_required=True)
            self.commit("maintenance-expired")

    def reverified(self):
        self.st["reverify_required"] = False
        self.commit("reverified")

    def denylog(self, src, dst, port):
        for row in self.client().firewall_log():
            if row.get("action") == "block" and row.get("src") == src and row.get("dst") == dst \
                    and str(row.get("dstport")) == str(port):
                return 0
        print("no logged block for %s -> %s:%s" % (src, dst, port), file=sys.stderr)
        return 1


def main(argv):
    ap = argparse.ArgumentParser(prog="labmode.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for c in ("exercise", "select"):
        sub.add_parser(c).add_argument("target", nargs="?" if c == "exercise" else None, default="none")
    m = sub.add_parser("maintenance")
    m.add_argument("--minutes", type=int, required=True)
    m.add_argument("--reason", default="")
    for c in ("tick", "reverified", "status"):
        sub.add_parser(c)
    d = sub.add_parser("denylog")
    d.add_argument("src"), d.add_argument("dst"), d.add_argument("port")
    a = ap.parse_args(argv[1:])

    lab = Lab()
    try:
        if a.cmd == "exercise":
            lab.exercise(a.target)
        elif a.cmd == "select":
            lab.select(a.target)
        elif a.cmd == "maintenance":
            lab.maintenance(a.minutes, a.reason)
        elif a.cmd == "tick":
            lab.tick()
        elif a.cmd == "reverified":
            lab.reverified()
        elif a.cmd == "denylog":
            return lab.denylog(a.src, a.dst, a.port)
        elif a.cmd == "status":
            print(json.dumps(lab.st))
    except opnsense.ApiError as e:
        print("firewall API error (change left unconfirmed, firewall will revert): %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
