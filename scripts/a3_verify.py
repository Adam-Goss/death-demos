#!/usr/bin/env python3
"""A3 evidence (issue #22): Elastic health, TLS, lifecycle, snapshot restore, destroy guard.

Runs from the workstation with the VPN up. Prints one row per check:
source | destination/port | mode | expected | actual | enforcement point. Exit non-zero on any FAIL/ERROR.
Network-reachability rows come from `a2-verify.sh` (see scripts/a3-verify.sh).
Env: PROXMOX_VE_ENDPOINT, PROXMOX_VE_API_TOKEN_FIREWALL / _TARGETS, PVE_NODE, PROXMOX_VE_INSECURE for the
token-scope rows; without them those rows are SKIP and the run is PASS-WITH-SKIPS.
"""
import base64
import json
import os
import pathlib
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLAN = json.load(open(ROOT / "network/plan.json"))
EL = PLAN["elastic"]
IP = PLAN["hosts"]["elastic"]["ip"]
SECRETS = ROOT / "secrets/elastic"
CA = SECRETS / "ca/ca.crt"
# Operator->9200/8220 is denied by design: reach them through an SSH tunnel (scripts/elastic-tunnel.sh).
ES = os.environ.get("ELASTIC_ES_URL", "https://127.0.0.1:19200")
KB = f"https://{IP}:5601"
FLEET = os.environ.get("ELASTIC_FLEET_URL", "https://127.0.0.1:18220")

rows = []


def row(src, dst, expected, actual, enforcement):
    rows.append((src, dst, "exercise", expected, actual, enforcement))


def verdict(expected, actual):
    return "OK" if expected == actual else "FAIL"


def req(url, method="GET", body=None, ctx=None, auth=True):
    ctx = ctx or ssl.create_default_context(cafile=str(CA))
    headers = {"Content-Type": "application/json", "kbn-xsrf": "a3"}
    if auth:
        pw = (SECRETS / "elastic.password").read_text().strip()
        headers["Authorization"] = "Basic " + base64.b64encode(f"elastic:{pw}".encode()).decode()
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(r, context=ctx, timeout=30) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {}


def check_health():
    code, info = req(ES + "/")
    row("operator", f"elastic:9200 version", EL["version"], info.get("version", {}).get("number", f"http {code}"),
        "elasticsearch")
    code, h = req(ES + "/_cluster/health")
    row("operator", "elastic:9200 nodes", "1", str(h.get("number_of_nodes")), "elasticsearch")
    row("operator", "elastic:9200 unassigned shards", "0", str(h.get("unassigned_shards")), "elasticsearch")
    row("operator", "elastic:9200 status", "green", h.get("status", "?"), "elasticsearch")
    code, lic = req(ES + "/_license")
    lic = lic.get("license", {})
    row("operator", "elastic:9200 license", "basic/active", f"{lic.get('type')}/{lic.get('status')}", "elasticsearch")
    code, st = req(KB + "/api/status")
    row("operator", "elastic:5601 kibana", "available", st.get("status", {}).get("overall", {}).get("level", f"http {code}"),
        "kibana")
    code, st = req(KB + "/api/status")
    row("operator", "elastic:5601 version", EL["version"], st.get("version", {}).get("number", "?"), "kibana")
    code, f = req(FLEET + "/api/status", auth=False)
    row("operator", "elastic:8220 fleet server", "HEALTHY", f.get("status", f"http {code}"), "fleet-server")


def tls_ok(url):
    try:
        urllib.request.urlopen(url, context=ssl.create_default_context(cafile=str(CA)), timeout=10)
        return "verified"
    except urllib.error.HTTPError:
        return "verified"  # TLS handshake succeeded; an HTTP error is not a TLS failure
    except Exception as e:  # noqa: BLE001
        return "error: " + type(e).__name__


def tls_rejects_without_ca(url):
    try:
        urllib.request.urlopen(url, context=ssl.create_default_context(), timeout=10)
        return "accepted"
    except urllib.error.HTTPError:
        return "accepted"
    except urllib.error.URLError as e:
        return "rejected" if isinstance(e.reason, ssl.SSLCertVerificationError) else "error: " + str(e.reason)
    except Exception as e:  # noqa: BLE001
        return "error: " + type(e).__name__


def check_tls():
    for name, url in (("elastic:9200 (tunnel)", ES), ("elastic:5601", KB), ("elastic:8220 (tunnel)", FLEET)):
        row("operator", f"{name} TLS with lab CA", "verified", tls_ok(url), "server certificate chain")
        row("operator", f"{name} TLS without lab CA", "rejected", tls_rejects_without_ca(url), "client trust store")


def check_lifecycle():
    for cls, r in EL["retention"].items():
        code, p = req(f"{ES}/_ilm/policy/{r['policy']}")
        delete = p.get(r["policy"], {}).get("policy", {}).get("phases", {}).get("delete", {}).get("min_age", "missing")
        row("operator", f"ilm {r['policy']} delete", f"{r['days']}d", delete, "ilm policy")
    for cls, names in EL["datasets"].items():
        policy = EL["retention"][cls]["policy"]
        bad = []
        for n in names:
            code, t = req(f"{ES}/_component_template/{n}@custom")
            comps = t.get("component_templates", [])
            got = comps[0]["component_template"]["template"]["settings"]["index"]["lifecycle"]["name"] if comps else None
            if got != policy:
                bad.append(n)
        row("operator", f"@custom templates ({cls}, {len(names)})", f"all use {policy}",
            "all" if not bad else "missing/wrong: " + ",".join(bad), "component templates")
    # Every data stream that exists must carry a lab policy: no stream is left on a default.
    code, ds = req(ES + "/_data_stream/*?expand_wildcards=all")
    lab = {r["policy"] for r in EL["retention"].values()}
    bad = [d["name"] for d in ds.get("data_streams", [])
           if not d["name"].startswith(".") and d.get("ilm_policy") not in lab]
    row("operator", f"existing data streams ({len(ds.get('data_streams', []))})", "all on a lab policy",
        "all" if not bad else "unmanaged: " + ",".join(bad), "ilm per data stream")


def check_snapshots():
    s = EL["snapshots"]
    code, v = req(f"{ES}/_snapshot/{s['repository']}/_verify", "POST")
    row("operator", f"snapshot repository {s['repository']}", "verified", "verified" if code == 200 else f"http {code}",
        "elasticsearch snapshot repo")
    code, p = req(f"{ES}/_slm/policy/{s['policy']}")
    pol = p.get(s["policy"], {}).get("policy", {})
    row("operator", f"slm {s['policy']}", f"{s['schedule']} / {s['retain_days']}d",
        f"{pol.get('schedule')} / {pol.get('retention', {}).get('expire_after')}", "slm policy")
    # Restore test: index -> snapshot -> delete -> restore -> same documents.
    idx, snap = "a3-restore-test", f"a3-test-{int(time.time())}"
    req(f"{ES}/{idx}", "DELETE")
    for i in range(3):
        req(f"{ES}/{idx}/_doc/{i}?refresh=true", "PUT", {"n": i})
    c1, _ = req(f"{ES}/_snapshot/{s['repository']}/{snap}?wait_for_completion=true", "PUT",
                {"indices": idx, "include_global_state": False})
    req(f"{ES}/{idx}", "DELETE")
    c2, _ = req(f"{ES}/_snapshot/{s['repository']}/{snap}/_restore?wait_for_completion=true", "POST",
                {"indices": idx, "include_global_state": False})
    req(f"{ES}/{idx}/_refresh", "POST")
    c3, cnt = req(f"{ES}/{idx}/_count")
    row("operator", "snapshot restore test (3 docs)", "3", str(cnt.get("count", f"http {c1}/{c2}/{c3}")), "snapshot repo")
    req(f"{ES}/{idx}", "DELETE")
    req(f"{ES}/_snapshot/{s['repository']}/{snap}", "DELETE")


def check_guard():
    env = dict(os.environ, OPALEYE_STATE_PASSPHRASE="0123456789abcdefghij", PROXMOX_VE_ENDPOINT="https://invalid.example:8006/")
    r = subprocess.run(["bash", str(ROOT / "scripts/lab.sh"), "destroy", "elastic"], env=env, capture_output=True, text=True)
    row("operator", "lab.sh destroy elastic", "refused", "refused" if r.returncode != 0 and "refused" in r.stderr else "ran",
        "scripts/lab.sh guard")
    guard = "prevent_destroy = true" in (ROOT / "tofu/stacks/elastic/main.tf").read_text()
    row("operator", "elastic VM prevent_destroy", "set", "set" if guard else "missing", "tofu lifecycle")
    endpoint, node = os.environ.get("PROXMOX_VE_ENDPOINT"), os.environ.get("PVE_NODE")
    insecure = ssl._create_unverified_context() if os.environ.get("PROXMOX_VE_INSECURE") else None
    for stack in ("firewall", "targets"):
        token = os.environ.get(f"PROXMOX_VE_API_TOKEN_{stack.upper()}")
        dst = f"proxmox vm {EL['vm_id']} (elastic)"
        if not (endpoint and node and token):
            rows.append((f"{stack} token", dst, "exercise", "deny", "SKIP", "proxmox pool ACL"))
            continue
        url = f"{endpoint.rstrip('/')}/api2/json/nodes/{node}/qemu/{EL['vm_id']}/status/current"
        r = urllib.request.Request(url, headers={"Authorization": f"PVEAPIToken={token}"})
        try:
            urllib.request.urlopen(r, context=insecure, timeout=15)
            actual = "allow"
        except urllib.error.HTTPError as e:
            actual = "deny" if e.code in (401, 403, 500) else f"http {e.code}"  # PVE answers 403/500 for no access
        except Exception:  # noqa: BLE001
            actual = "ERROR"
        rows.append((f"{stack} token", dst, "exercise", "deny", actual, "proxmox pool ACL"))


def main():
    if not CA.exists():
        print("no lab CA at secrets/elastic/ca/ca.crt: run the elastic playbook first", file=sys.stderr)
        return 2
    for fn in (check_health, check_tls, check_lifecycle, check_snapshots, check_guard):
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            rows.append(("operator", fn.__name__, "exercise", "ok", f"ERROR {type(e).__name__}: {e}", "a3-verify"))
    print("| source | destination/port | mode | expected | actual | enforcement point |")
    print("| --- | --- | --- | --- | --- | --- |")
    fail = skipped = 0
    for src, dst, mode, exp, act, enf in rows:
        if act == "SKIP":
            skipped += 1
        elif exp != act:
            fail += 1
        print(f"| {src} | {dst} | {mode} | {exp} | {act} | {enf} |")
    status = "FAIL" if fail else ("PASS-WITH-SKIPS" if skipped else "PASS")
    print(f"\nphase=a3 rows={len(rows)} skipped={skipped} {status}")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
