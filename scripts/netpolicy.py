#!/usr/bin/env python3
"""Lab network policy (issue #21). Single source: network/plan.json.

plan flows -> rendered firewall ruleset (render_rules) -> checked against the literal
probe table in the plan (lint). The probe table is written by hand and is the A2 contract;
the rules are derived from flows, so the two only agree when the flows are right.

  netpolicy.py matrix <exercise|maintenance> [selected]   A2 probe rows, TSV
  netpolicy.py rules  <exercise|maintenance> [selected]   rendered ruleset, JSON
  netpolicy.py lint   <exercise|maintenance> [selected]   exit 1 on any mismatch
  netpolicy.py check                                       plan sanity, exit 1 on errors
  netpolicy.py bridges                                     /etc/network/interfaces.d stanzas
"""
import ipaddress
import json
import os
import sys

DEFAULT_PLAN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "network", "plan.json")
# Networks the lab must never overlap: Ludus (10.1.0.0/16, 192.0.2.0/24, 198.51.100.0/24) and the home LAN.
RESERVED = ["10.1.0.0/16", "192.0.2.0/24", "198.51.100.0/24", "192.168.0.0/24"]
V6_ZONES = ("attacker", "elastic", "t1", "t2", "gateway", "operator", "workstation")
UPDATE_ALIAS = "opaleye_update_sources"
SELF = "(self)"


def load_plan(path=DEFAULT_PLAN):
    with open(path) as f:
        return json.load(f)


def _svc(plan, name):
    s = plan["services"][name]
    return s["proto"], s["ports"]


def flows(plan):
    """Allowed flows. src/dst: 'zone:x', 'host:x', 'fw', 'alias:update_sources'."""
    labzones = ["zone:attacker", "zone:elastic", "zone:t1", "zone:t2", "zone:gateway"]
    out = []

    def add(fid, src, dst, svc=None, proto=None, ports=None, modes=("exercise", "maintenance"), selected=None, log=False):
        if svc:
            proto, ports = _svc(plan, svc)
        out.append(dict(id=fid, src=src, dst=dst, proto=proto, ports=ports, modes=modes, selected=selected, log=log))

    add("vpn-handshake", ["host:workstation"], "fw", "wireguard")
    for s in ("dns", "ntp"):
        add("lab-" + s, labzones, "fw", s)
    # The attacker is the adversary: it must never write to the evidence store. Targets only.
    add("telemetry", ["zone:t1", "zone:t2"], "host:elastic", "ingest")
    add("op-fw-admin", ["zone:vpn"], "fw", "fw_admin")
    add("op-attacker-ssh", ["zone:vpn"], "host:attacker", "ssh")
    add("op-kibana", ["zone:vpn"], "host:elastic", "kibana")
    add("op-elastic-ssh", ["zone:vpn"], "host:elastic", "ssh")
    # Guacamole gateway (#51): the operator reaches it over the VPN; it alone brokers GUI/terminal sessions.
    add("op-gateway-web", ["zone:vpn"], "host:gateway", "gateway_web")
    add("op-gateway-ssh", ["zone:vpn"], "host:gateway", "ssh")
    add("gw-attacker-rdp", ["host:gateway"], "host:attacker", "rdp")
    for t in plan["targets"]:
        add("op-%s-ssh" % t, ["zone:vpn"], "host:" + t, "ssh")
        add("gw-%s-ssh" % t, ["host:gateway"], "host:" + t, "ssh")
        add("exercise-" + t, ["zone:attacker"], "host:" + t, proto="tcp", ports=plan["targets"][t]["exercise_ports"],
            modes=("exercise",), selected=t, log=True)
    add("maint-updates", ["host:" + h for h in plan["maintenance"]["initiators"]], "alias:update_sources",
        proto="tcp", ports=[80, 443], modes=("maintenance",), log=True)
    return out


def _zone_of(plan, ent):
    kind, _, name = ent.partition(":")
    return name if kind == "zone" else plan["hosts"][name]["zone"]


def _net(plan, ent):
    if ent == "fw":
        return SELF
    kind, _, name = ent.partition(":")
    if kind == "alias":
        return UPDATE_ALIAS
    if kind == "zone":
        return plan["zones"][name]["cidr"]
    return plan["hosts"][name]["ip"] + "/32"


def render_rules(plan, mode, selected):
    """Complete ordered ruleset; conditional rules are present but disabled when not active."""
    rules = []
    for zname, z in plan["zones"].items():
        iface = z["iface"]
        rules.append(dict(id="v6-block@" + iface, iface=iface, action="block", family="inet6", proto="any",
                          src="any", dst="any", ports=[], enabled=True, log=True))
        for fl in flows(plan):
            for src in fl["src"]:
                if plan["zones"][_zone_of(plan, src)]["iface"] != iface:
                    continue
                active = mode in fl["modes"] and (fl["selected"] is None or fl["selected"] == selected)
                rules.append(dict(id="%s@%s@%s" % (fl["id"], iface, src.partition(":")[2]), iface=iface, action="pass",
                                  family="inet", proto=fl["proto"], src=_net(plan, src), dst=_net(plan, fl["dst"]),
                                  ports=fl["ports"], enabled=active, log=fl["log"]))
        rules.append(dict(id="deny-all@" + iface, iface=iface, action="block", family="inet", proto="any",
                          src="any", dst="any", ports=[], enabled=True, log=True))
    return rules


def _in(net, ip):
    return net == "any" or ipaddress.ip_address(ip) in ipaddress.ip_network(net)


def evaluate(plan, rules, probe):
    """First-match verdict for a probe as the firewall would see it (ingress on the source interface)."""
    zone = plan["hosts"][probe["src"]]["zone"]
    iface = plan["zones"][zone]["iface"]
    family = probe.get("family", "inet")
    dst = probe["dst"]
    for r in rules:
        if r["iface"] != iface or not r["enabled"] or r["family"] != family:
            continue
        if family == "inet":
            if r["proto"] not in ("any", probe["proto"]):
                continue
            if r["ports"] and probe["port"] not in r["ports"]:
                continue
            if not _in(r["src"], plan["hosts"][probe["src"]]["ip"]):
                continue
            if r["dst"] == SELF:
                if dst != "fw":
                    continue
            elif r["dst"] == UPDATE_ALIAS:
                if dst != "update_source":
                    continue
            elif r["dst"] != "any":
                if dst in ("fw", "update_source") or not _in(r["dst"], plan["hosts"][dst]["ip"]):
                    continue
        return "allow" if r["action"] == "pass" else "deny"
    return "deny"


def _dst_ip(plan, src, dst):
    if dst == "update_source":
        return "UPDATE_SOURCE"
    if dst != "fw":
        return plan["hosts"][dst]["ip"]
    zone = plan["hosts"][src]["zone"]
    if zone == "home":
        return plan["firewall"]["wan_ip"]
    return str(next(ipaddress.ip_network(plan["zones"][zone]["cidr"]).hosts()))


def _expected(p, mode, selected):
    """Literal verdict from the plan; probes tied to a selected target follow the selection in exercise mode."""
    if mode == "exercise" and "allowed_when_selected" in p:
        return "allow" if selected == p["allowed_when_selected"] else "deny"
    return p["modes"][mode]


def matrix(plan, mode, selected):
    rows = []
    for p in plan["probes"]:
        zone = plan["hosts"][p["src"]]["zone"]
        rows.append(dict(id=p["id"], src=p["src"], dst=p["dst"], proto=p["proto"], port=p["port"], mode=mode,
                         selected=selected or "none", expected=_expected(p, mode, selected), family="inet",
                         kind=p.get("kind", "tcp"), enforcement="firewall:" + plan["zones"][zone]["iface"],
                         src_ip=plan["hosts"][p["src"]]["ip"], dst_ip=_dst_ip(plan, p["src"], p["dst"])))
    for z in V6_ZONES:
        rows.append(dict(id="v6-" + z, src=z, dst="fw", proto="any", port=0, mode=mode, selected=selected or "none",
                         expected="deny", family="inet6", kind="no-ipv6",
                         enforcement="firewall:" + plan["zones"][plan["hosts"][z]["zone"]]["iface"],
                         src_ip=plan["hosts"][z]["ip"], dst_ip="-"))
    return rows


def lint(plan, mode, selected, rules=None):
    rules = render_rules(plan, mode, selected) if rules is None else rules
    bad = []
    for p in matrix(plan, mode, selected):
        got = evaluate(plan, rules, p)
        if got != p["expected"]:
            bad.append("%s %s->%s %s/%s %s: expected %s, rules give %s" %
                       (p["id"], p["src"], p["dst"], p["proto"], p["port"], mode, p["expected"], got))
    return bad


def plan_errors(plan):
    errs = []
    zones = plan["zones"]
    home = zones["home"]["bridge"]
    bridges = [(n, z["bridge"]) for n, z in zones.items() if z["bridge"]]
    seen = {}
    for n, b in bridges:
        if b in seen:
            errs.append("bridge %s used by %s and %s" % (b, seen[b], n))
        seen[b] = n
        if b == home and n != "home":
            errs.append("zone %s attached to the home bridge" % n)
    lab = [(n, ipaddress.ip_network(z["cidr"])) for n, z in zones.items() if n != "home"]
    for i, (n, a) in enumerate(lab):
        for m, b in lab[i + 1:]:
            if a.overlaps(b):
                errs.append("zones %s and %s overlap" % (n, m))
        for r in RESERVED:
            if a.overlaps(ipaddress.ip_network(r)):
                errs.append("zone %s overlaps reserved %s" % (n, r))
    for h, v in plan["hosts"].items():
        if v["zone"] != "home" and ipaddress.ip_address(v["ip"]) not in ipaddress.ip_network(zones[v["zone"]]["cidr"]):
            errs.append("host %s outside its zone" % h)
    for z in plan["nic_order"]:
        if not zones[z]["bridge"]:
            errs.append("nic_order zone %s has no bridge" % z)
    return errs


def bridge_stanzas(plan):
    out = ["# Managed by scripts/bootstrap-bridges.sh from network/plan.json. Lab bridges only; no host IP, no ports.\n"]
    for n, z in plan["zones"].items():
        if n == "home" or not z["bridge"]:
            continue
        out.append("auto {b}\niface {b} inet manual\n\tbridge-ports none\n\tbridge-stp off\n\tbridge-fd 0\n\tcomment lab zone {n}\n".format(b=z["bridge"], n=n))
    return "\n".join(out)


def main(argv):
    plan = load_plan(os.environ.get("LAB_PLAN", DEFAULT_PLAN))
    cmd = argv[1] if len(argv) > 1 else ""
    mode = argv[2] if len(argv) > 2 else "exercise"
    sel = argv[3] if len(argv) > 3 and argv[3] != "none" else None
    if cmd == "matrix":
        for r in matrix(plan, mode, sel):
            print("\t".join(str(r[k]) for k in ("id", "src", "dst", "proto", "port", "kind", "family", "mode", "expected", "enforcement", "src_ip", "dst_ip")))
    elif cmd == "rules":
        print(json.dumps(render_rules(plan, mode, sel), indent=1))
    elif cmd == "lint":
        bad = lint(plan, mode, sel)
        print("\n".join(bad) or "ok: rules match the probe matrix (%s)" % mode)
        return 1 if bad else 0
    elif cmd == "check":
        errs = plan_errors(plan)
        print("\n".join(errs) or "ok: plan sane")
        return 1 if errs else 0
    elif cmd == "bridges":
        print(bridge_stanzas(plan))
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
