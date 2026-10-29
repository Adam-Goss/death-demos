#!/usr/bin/env python3
"""OPNsense first-boot config.xml seed, generated from network/plan.json (issue #31).

  opnsense_seed.py template            print the secret-free seed (placeholders @@NAME@@)
  opnsense_seed.py check               offline guards: committed seed == generated, no secrets, no rules
  opnsense_seed.py render --out FILE   fill the seed with secrets from the environment (mode 0600)
  opnsense_seed.py iso --out FILE      render, then wrap as conf/config.xml in an ISO for the importer

Secrets come from the operator environment only (never the repo or Tofu state):
  OPNSENSE_ROOT_PASSWORD, OPNSENSE_API_KEY, OPNSENSE_API_SECRET,
  OPNSENSE_WG_PRIVATE_KEY, OPNSENSE_WG_PUBLIC_KEY (the firewall's), OPNSENSE_WG_PEER_PUBLIC_KEY (workstation's).
Passwords and the API secret are written as SHA-512 crypt hashes, as OPNsense stores them.

Filter rules: only a bootstrap set, so the API is reachable on a rebuilt firewall (default deny otherwise):
the workstation's WireGuard handshake and the VPN's TCP 443 to the firewall, plus the v6 block and deny-all on
those two interfaces. They are the exact payloads labmode.py would push (same descriptions), so its first sync
adopts them in place; labmode.py and netpolicy.py own everything else.

Compared with a real export from VM 2000 on 26.7 (2026-10-29): privilege names, the gateway (OPNsense/Gateways),
offload and IPv6 switches (OPNsense/Interfaces/settings), the "key|hash" apikeys text and the bootstrap rule
location (OPNsense/Firewall/Filter/rules) follow that export. Still unproven: that the nano image or importer
accepts this seed on first boot (cd9660 is the importer's documented fallback).
"""
import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import labmode  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLAN = os.path.join(ROOT, "network", "plan.json")
SEED = os.path.join(ROOT, "network", "opnsense-seed.xml")

SECRET_ENV = {
    "root_password": "OPNSENSE_ROOT_PASSWORD",
    "api_key": "OPNSENSE_API_KEY",
    "api_secret": "OPNSENSE_API_SECRET",
    "wg_private": "OPNSENSE_WG_PRIVATE_KEY",
    "wg_public": "OPNSENSE_WG_PUBLIC_KEY",
    "wg_peer_public": "OPNSENSE_WG_PEER_PUBLIC_KEY",
}
PLACEHOLDER = re.compile(r"@@[A-Z_]+@@")
WG_KEY = re.compile(r"^[A-Za-z0-9+/]{43}=$")

API_USER = "opaleye-api"
# Not an administrator: rules (filter API), aliases, firewall log, WireGuard status. Never page-all.
API_PRIVS = ["page-diagnostics-logs-firewall-dynamic", "page-diagnostics-logs-firewall-plain",
             "page-diagnostics-logs-firewall-summary", "page-firewall-alias-edit", "page-firewall-aliases",
             "page-filter-api", "page-firewall-rules-edit", "page-wireguard-diagnostics"]  # as exported from VM 2000
WG_IF = "wg0"
WG_PORT = 51820
PEER_NAME = "workstation"
BOOTSTRAP_FLOWS = ("vpn-handshake", "op-fw-admin")
BASELINE_FLOWS = ("v6-block", "deny-all")


def load_plan(path=PLAN):
    with open(path) as f:
        return json.load(f)


def placeholders():
    return {k: "@@%s@@" % v.replace("OPNSENSE_", "") for k, v in SECRET_ENV.items()}


def _uuid(name):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "opaleye/" + name))


def _sub(parent, tag, text=None, **attrs):
    e = ET.SubElement(parent, tag, attrs)
    if text is not None:
        e.text = str(text)
    return e


def _flow(desc):
    return desc[len(labmode.PREFIX):].split(":")[0].split("@")[0]


def bootstrap_rules(plan):
    """labmode's exercise-mode payloads for the bootstrap flows and the baseline on their interfaces."""
    want = labmode.desired(plan, "exercise", None)
    ifaces = {p["interface"] for d, p in want.items() if _flow(d) in BOOTSTRAP_FLOWS}
    keep = {d: p for d, p in want.items()
            if p["interface"] in ifaces and _flow(d) in BOOTSTRAP_FLOWS + BASELINE_FLOWS}
    return sorted(keep.items(), key=lambda kv: int(kv[1]["sequence"]))


def build(plan, vals):
    """Config tree. `vals` holds the six secret fields (hash or plaintext as stored, or placeholders)."""
    zones = plan["zones"]
    lab = [z for z in plan["nic_order"] if z != "home"]  # lab zones carry DNS/NTP
    lab_ifaces = [zones[z]["iface"] for z in lab]
    home = zones["home"]
    gw = plan["hosts"]["home_router"]["ip"]

    root = ET.Element("opnsense")
    _sub(root, "theme", "opnsense")
    opn = _sub(root, "OPNsense")

    system = _sub(root, "system")
    _sub(system, "hostname", "opaleye-firewall")
    _sub(system, "domain", "lab.internal")
    _sub(system, "timezone", "Etc/UTC")
    _sub(system, "dnsserver", gw)
    web = _sub(system, "webgui")
    _sub(web, "protocol", "https")
    _sub(web, "noantilockout", 1)                       # anti-lockout off: only 443 from the VPN reaches it
    # no <ipv6allow>: IPv6 stays off
    u = _sub(system, "user")
    _sub(u, "name", "root")
    _sub(u, "scope", "system")
    _sub(u, "uid", 0)
    _sub(u, "groupname", "admins")
    _sub(u, "password", vals["root_password"])
    a = _sub(system, "user")
    _sub(a, "name", API_USER)
    _sub(a, "scope", "user")
    _sub(a, "uid", 2000)
    _sub(a, "descr", "Opaleye labmode API user (rules, aliases, firewall log only)")
    _sub(a, "password", "*")                            # API only; no console or GUI login
    for p in API_PRIVS:
        _sub(a, "priv", p)
    _sub(a, "apikeys", "%s|%s" % (vals["api_key"], vals["api_secret"]))  # 26.7 stores "key|crypt-hash"

    ifs = _sub(root, "interfaces")
    for z in plan["nic_order"]:
        i = zones[z]
        e = _sub(ifs, i["iface"])
        _sub(e, "if", "vtnet%d" % plan["nic_order"].index(z))
        _sub(e, "descr", z)
        _sub(e, "enable", 1)
        if z == "home":
            _sub(e, "ipaddr", plan["firewall"]["wan_ip"])
            _sub(e, "subnet", ipaddress.ip_network(i["cidr"]).prefixlen)
            _sub(e, "gateway", "WAN_GW")
            # blockpriv / blockbogons omitted = "Block private networks" off (it drops the workstation)
        else:
            net = ipaddress.ip_network(i["cidr"])
            _sub(e, "ipaddr", str(net.network_address + 1))
            _sub(e, "subnet", net.prefixlen)
    vpn = zones["vpn"]
    e = _sub(ifs, vpn["iface"])
    _sub(e, "if", WG_IF)
    _sub(e, "descr", "vpn")
    _sub(e, "enable", 1)

    g = _sub(_sub(opn, "Gateways"), "gateway_item")
    _sub(g, "name", "WAN_GW")
    _sub(g, "interface", home["iface"])
    _sub(g, "gateway", gw)
    _sub(g, "defaultgw", 1)
    _sub(g, "ipprotocol", "inet")

    unbound = _sub(_sub(opn, "unboundplus"), "general")
    _sub(unbound, "enabled", 1)
    _sub(unbound, "active_interface", ",".join(lab_ifaces))
    iset = _sub(_sub(opn, "Interfaces"), "settings")
    for tag in ("disablechecksumoffloading", "disablesegmentationoffloading", "disablelargereceiveoffloading"):
        _sub(iset, tag, 1)                              # hardware offload off
    _sub(iset, "disableipv6", 1)
    ntp = _sub(root, "ntpd")
    _sub(ntp, "interface", ",".join(lab_ifaces))

    wg = _sub(opn, "wireguard")
    _sub(_sub(wg, "general"), "enabled", 1)
    peer_id = _uuid("wg-peer-" + PEER_NAME)
    server = _sub(_sub(wg, "server"), "servers")
    s = _sub(server, "server", uuid=_uuid("wg-instance-" + WG_IF))
    _sub(s, "enabled", 1)
    _sub(s, "name", "lab")
    _sub(s, "instance", 0)
    _sub(s, "pubkey", vals["wg_public"])
    _sub(s, "privkey", vals["wg_private"])
    _sub(s, "port", plan["services"]["wireguard"]["ports"][0])
    _sub(s, "tunneladdress", "%s/%d" % (ipaddress.ip_network(vpn["cidr"]).network_address + 1,
                                        ipaddress.ip_network(vpn["cidr"]).prefixlen))
    _sub(s, "peers", peer_id)
    c = _sub(_sub(_sub(wg, "client"), "clients"), "client", uuid=peer_id)
    _sub(c, "enabled", 1)
    _sub(c, "name", PEER_NAME)
    _sub(c, "pubkey", vals["wg_peer_public"])
    _sub(c, "tunneladdress", plan["hosts"]["operator"]["ip"] + "/32")  # IPv4 only (A2 wgv4only)

    # Bootstrap rules as the filter API stores them (MVC section); no legacy <filter> section.
    rules = _sub(_sub(_sub(opn, "Firewall"), "Filter"), "rules")
    for desc, payload in bootstrap_rules(plan):
        r = _sub(rules, "rule", uuid=_uuid("rule-" + desc))
        for k, v in payload.items():
            _sub(r, k, v)
    return root


def serialize(root):
    ET.indent(root)
    return '<?xml version="1.0"?>\n' + ET.tostring(root, encoding="unicode") + "\n"


def template(plan=None):
    return serialize(build(plan or load_plan(), placeholders()))


def sha512_crypt(secret):
    # Not the crypt module: macOS builds silently fall back to DES. Secret goes via stdin, not argv.
    if not shutil.which("openssl"):
        raise SystemExit("openssl is needed to hash the secrets")
    r = subprocess.run(["openssl", "passwd", "-6", "-stdin"], input=secret + "\n",
                       stdout=subprocess.PIPE, universal_newlines=True, check=True)
    h = r.stdout.strip()
    if not h.startswith("$6$"):
        raise SystemExit("openssl did not produce a SHA-512 crypt hash")
    return h


def secrets_from_env(env):
    missing = [n for n in SECRET_ENV.values() if not env.get(n)]
    if missing:
        raise SystemExit("set " + ", ".join(missing))
    v = {k: env[n] for k, n in SECRET_ENV.items()}
    for k in ("wg_private", "wg_public", "wg_peer_public"):
        if not WG_KEY.match(v[k]):
            raise SystemExit("%s is not a WireGuard key (44 chars base64)" % SECRET_ENV[k])
    if len(v["root_password"]) < 12:
        raise SystemExit("OPNSENSE_ROOT_PASSWORD must be at least 12 characters")
    if len(v["api_key"]) < 20 or len(v["api_secret"]) < 20:
        raise SystemExit("OPNSENSE_API_KEY/SECRET must be at least 20 characters")
    v["root_password"] = sha512_crypt(v["root_password"])
    v["api_secret"] = sha512_crypt(v["api_secret"])
    return v


def render(env=None, plan=None):
    xml = serialize(build(plan or load_plan(), secrets_from_env(os.environ if env is None else env)))
    if PLACEHOLDER.search(xml):
        raise SystemExit("unfilled placeholder in rendered config")
    return xml


def problems(xml):
    """Static invariants for a seed (template or render). Empty list = pass."""
    out = []
    root = ET.fromstring(xml)
    if root.find("filter") is not None:
        out.append("legacy <filter> section present")
    for r in root.iterfind("OPNsense/Firewall/Filter/rules/rule"):
        desc = r.findtext("description") or ""
        if not desc.startswith(labmode.PREFIX) or _flow(desc) not in BOOTSTRAP_FLOWS + BASELINE_FLOWS:
            out.append("non-bootstrap filter rule: " + desc)
    if root.find("system/webgui/noantilockout") is None:
        out.append("anti-lockout not disabled")
    if root.find("system/ipv6allow") is not None:
        out.append("IPv6 allowed")
    for tag in ("blockpriv", "blockbogons"):
        if list(root.iter(tag)):
            out.append("%s set on an interface" % tag)
    for tag in ("disablechecksumoffloading", "disablesegmentationoffloading", "disablelargereceiveoffloading"):
        if root.findtext("OPNsense/Interfaces/settings/" + tag) != "1":
            out.append("hardware offload not disabled (%s)" % tag)
    for p in root.iter("priv"):
        if p.text in ("page-all", "user-shell-access"):
            out.append("API user has admin privilege " + p.text)
    for t in root.iter("tunneladdress"):
        if ":" in (t.text or ""):
            out.append("IPv6 tunnel address")
    return out


def looks_secret(xml):
    """True if the document holds real secret material rather than placeholders or `*`."""
    root = ET.fromstring(xml)
    fields = ["system/user/password", "system/user/apikeys", "OPNsense/wireguard/server/servers/server/privkey"]
    for path in fields:
        for e in root.findall(path):
            left = PLACEHOLDER.sub("", e.text or "").replace("|", "")
            if left and left != "*":
                return True
    return False


def make_iso(src_dir, out):
    for tool, args in (("xorriso", ["-as", "mkisofs", "-V", "OPALEYE_SEED", "-r", "-o", out, src_dir]),
                       ("genisoimage", ["-V", "OPALEYE_SEED", "-r", "-o", out, src_dir]),
                       ("mkisofs", ["-V", "OPALEYE_SEED", "-r", "-o", out, src_dir]),
                       ("hdiutil", ["makehybrid", "-iso", "-joliet", "-default-volume-name", "OPALEYE_SEED",
                                    "-o", out, src_dir])):
        if shutil.which(tool):
            subprocess.run([tool] + args, check=True, stdout=subprocess.DEVNULL)
            return
    try:
        import pycdlib  # pure-Python fallback, e.g. on Windows
    except ImportError:
        raise SystemExit("need xorriso, genisoimage, mkisofs, hdiutil or the pycdlib module to build the seed ISO")
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3, rock_ridge="1.09", vol_ident="OPALEYE_SEED")
    iso.add_directory("/CONF", rr_name="conf", joliet_path="/conf")
    iso.add_file(os.path.join(src_dir, "conf", "config.xml"), "/CONF/CONFIG.XML;1",
                 rr_name="config.xml", joliet_path="/conf/config.xml")
    iso.write(out)
    iso.close()


def write_private(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("cmd", choices=["template", "check", "scan", "render", "iso"])
    ap.add_argument("--out")
    ap.add_argument("files", nargs="*", help="scan: XML files to search for real secret material")
    args = ap.parse_args(argv)
    if args.cmd == "template":
        sys.stdout.write(template())
        return 0
    if args.cmd == "check":
        bad = []
        want = template()
        try:
            have = open(SEED).read()
        except OSError:
            have = ""
        if have != want:
            bad.append("network/opnsense-seed.xml is stale: python3 scripts/opnsense_seed.py template > network/opnsense-seed.xml")
        bad += problems(have or want)
        if looks_secret(have or want):
            bad.append("seed holds real secret material")
        for b in bad:
            print("FAIL " + b, file=sys.stderr)
        return 1 if bad else 0
    if args.cmd == "scan":
        leaks = []
        for f in args.files:
            with open(f) as fh:
                text = fh.read()
            try:
                if looks_secret(text):
                    leaks.append(f)
            except ET.ParseError:
                pass
        for f in leaks:
            print("FAIL secret material in " + f, file=sys.stderr)
        return 1 if leaks else 0
    if not args.out:
        ap.error("--out required")
    xml = render()
    bad = problems(xml)
    if bad:
        raise SystemExit("; ".join(bad))
    if args.cmd == "render":
        write_private(args.out, xml)
    else:
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "conf"))
            write_private(os.path.join(d, "conf", "config.xml"), xml)
            make_iso(d, args.out)
        os.chmod(args.out, 0o600)
    return 0


if __name__ == "__main__":
    sys.exit(main())
