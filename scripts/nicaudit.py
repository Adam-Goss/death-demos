#!/usr/bin/env python3
"""NIC audit for A2 (issue #21): no lab guest has an alternate path around the firewall VM.

Rules, from network/plan.json:
  - only the firewall VM may have a NIC on the home bridge;
  - every other guest sits on exactly one lab bridge (two would bridge zones around the firewall);
  - no NIC on a bridge the plan doesn't know (e.g. a Ludus bridge).

CLI: nicaudit.py [wanmac]   (wanmac prints the firewall WAN MAC for the home-side IPv6 probe; env: PROXMOX_VE_ENDPOINT, PVE_NODE, PROXMOX_VE_API_TOKEN_{FIREWALL,ELASTIC,TARGETS,ATTACKER,GATEWAY},
                    PROXMOX_VE_INSECURE=true). Read-only; uses each stack's own token over the API.
"""
import json
import os
import re
import ssl
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netpolicy  # noqa: E402

POOLS = {"firewall": "lab-firewall", "elastic": "lab-elastic", "targets": "lab-targets", "attacker": "lab-attacker", "gateway": "lab-gateway"}


def bridges_of(vm):
    """Bridge names of every netN line in a VM config, in NIC order."""
    out = []
    for key in sorted(vm["config"], key=lambda k: (len(k), k)):
        if re.fullmatch(r"net\d+", key):
            m = re.search(r"(?:^|,)bridge=([^,]+)", vm["config"][key])
            if m:
                out.append(m.group(1))
    return out


def audit(plan, vms, require_firewall=False):
    home = plan["zones"]["home"]["bridge"]
    lab = {z["bridge"] for n, z in plan["zones"].items() if n != "home" and z["bridge"]}
    fw = plan["firewall"]["vm_id"]
    bad = []
    for vm in vms:
        who = "VM %s (%s)" % (vm["vmid"], vm.get("name", "?"))
        br = bridges_of(vm)
        if vm["vmid"] == fw:
            if require_firewall:
                missing = [plan["zones"][z]["bridge"] for z in plan["nic_order"] if plan["zones"][z]["bridge"] not in br]
                if missing:
                    bad.append("%s missing NIC on %s" % (who, ", ".join(missing)))
            for b in br:
                if b != home and b not in lab:
                    bad.append("%s has a NIC on unknown bridge %s" % (who, b))
            continue
        if home in br:
            bad.append("%s has a NIC on the home bridge %s" % (who, home))
        for b in br:
            if b != home and b not in lab:
                bad.append("%s has a NIC on unknown bridge %s" % (who, b))
        if len({b for b in br if b in lab}) > 1:
            bad.append("%s is on more than one lab bridge (%s): zones joined around the firewall" % (who, ", ".join(br)))
    return bad


def wan_mac(plan, vms):
    """MAC of the firewall VM's first NIC (the WAN, on the home bridge)."""
    fw = next(v for v in vms if v["vmid"] == plan["firewall"]["vm_id"])
    m = re.search(r"(?:^|,)[a-z0-9]+=([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", fw["config"]["net0"])
    return m.group(1)


def _get(base, token, path, ctx):
    req = urllib.request.Request(base + "/api2/json" + path, headers={"Authorization": "PVEAPIToken=" + token})
    with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
        return json.load(r)["data"]


def collect(plan, stacks=None):
    base = os.environ["PROXMOX_VE_ENDPOINT"].rstrip("/")
    node = os.environ["PVE_NODE"]
    ctx = ssl._create_unverified_context() if os.environ.get("PROXMOX_VE_INSECURE") == "true" else None
    vms = []
    for stack, pool in POOLS.items():
        if stacks and stack not in stacks:
            continue
        token = os.environ["PROXMOX_VE_API_TOKEN_" + stack.upper()]
        for m in _get(base, token, "/pools/" + pool, ctx).get("members", []):
            if m.get("type") == "qemu":
                cfg = _get(base, token, "/nodes/%s/qemu/%s/config" % (node, m["vmid"]), ctx)
                vms.append({"vmid": m["vmid"], "name": cfg.get("name", ""), "config": cfg})
    return vms


def main():
    plan = netpolicy.load_plan(os.environ.get("LAB_PLAN", netpolicy.DEFAULT_PLAN))
    if sys.argv[1:] == ["wanmac"]:
        print(wan_mac(plan, collect(plan, ("firewall",))))
        return 0
    for k in ("PROXMOX_VE_ENDPOINT", "PVE_NODE"):
        if not os.environ.get(k):
            raise SystemExit("set " + k)
    vms = collect(plan)
    print("| guest | pool bridges |\n| --- | --- |")
    for v in vms:
        print("| VM %s (%s) | %s |" % (v["vmid"], v["name"], ", ".join(bridges_of(v)) or "none"))
    bad = audit(plan, vms, require_firewall=any(v["vmid"] == plan["firewall"]["vm_id"] for v in vms))
    print("\n" + ("\n".join(bad) if bad else "ok: only the firewall VM touches the home bridge; every other guest is on one lab bridge"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
