#!/usr/bin/env python3
"""A4 evidence (issue #23): evidence from one target arrives in Elastic, tagged and with distinct times.

Run from the workstation with the VPN up and scripts/elastic-tunnel.sh running, after the target has produced
traffic (browse DVWA from the attacker, run the exercise). Usage: a4_verify.py <target> [generation] [--window MIN]
Prints one row per check: source | destination/port | mode | expected | actual | enforcement point. Exit non-zero on
any FAIL/ERROR. Rows that need a human or an unbuilt component are SKIP and listed, never silently passed.
Env: as scripts/fleetctl.py.
"""
import argparse
import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import fleetctl  # noqa: E402

SOURCES = [
    ("defend process", "logs-endpoint.events.process-*"),
    ("defend network", "logs-endpoint.events.network-*"),
    ("auditd", "logs-auditd_manager.auditd-*"),
    ("docker container logs", "logs-docker.container_logs-*"),
    ("apache access", "logs-apache.access-*"),
    ("apache error", "logs-apache.error-*"),
    ("firewall flow logs", "logs-lab_firewall.flow-*"),
]
MANUAL = [
    ("apache POST body / query visibility", "SKIP: manual, exercise from the attacker (runbook A4 procedure)"),
    ("filestream 1,024-byte fingerprint", "SKIP: manual, write a <1 KB request log line and look for it (runbook)"),
    ("defend + auditd coexistence", "SKIP: manual, both sources present AND exec rule events seen (runbook)"),
]


def get(d, dotted):
    for k in dotted.split("."):
        d = d.get(k) if isinstance(d, dict) else None
    return d


def tagged(target, gen):
    f = [{"term": {"lab.target_id": target}}]
    if gen:
        f.append({"term": {"lab.rebuild_generation": gen}})
    return f


def check(es, target, gen, window, lag_window=None):
    lag_window = window if lag_window is None else lag_window
    rows = []
    mode = "exercise"
    for name, index in SOURCES:
        flt = tagged(target, gen) + [{"range": {"@timestamp": {"gte": "now-%dm" % window}}}]
        _, c = es.call("POST", "/%s/_count?ignore_unavailable=true&allow_no_indices=true" % index, {"query": {"bool": {"filter": flt}}})
        n = c.get("count", 0)
        rows.append((target, name, mode, "> 0 tagged lab.target_id=%s gen=%s" % (target, gen or "any"),
                     "%d events" % n, "elastic " + index, n > 0))
        _, s = es.call("POST", "/%s/_search?ignore_unavailable=true&allow_no_indices=true" % index,
                       {"size": 1, "sort": [{"@timestamp": "desc"}], "query": {"bool": {"filter": flt}}})
        hits = s["hits"]["hits"]
        src = hits[0]["_source"] if hits else {}
        t = [get(src, "@timestamp"), get(src, "event.created"), get(src, "event.ingested")]
        # All three time fields must be present; collection and ingestion are separate stages.
        ok = bool(all(t) and t[0] != t[2] and t[1] != t[2])
        rows.append((target, name + " times", mode, "all three times present; ingestion distinct from source and collection",
                     "/".join(str(x) for x in t) if hits else "no sample", "elastic " + index, ok))
    limit = fleetctl.load_plan()["target_stack"]["ingest_lag_seconds"]
    _, lag = es.call("POST", "/logs-*,metrics-*/_search?ignore_unavailable=true&allow_no_indices=true", {
        "size": 0, "track_total_hits": True, "query": {"bool": {"filter": [
            {"range": {"event.ingested": {"gte": "now-%dm" % lag_window}}},
            {"script": {"script": {"lang": "painless", "source": fleetctl.LAG_SCRIPT, "params": {"ms": limit * 1000}}}}]}}})
    n = lag["hits"]["total"]["value"]
    rows.append((target, "ingest lag", mode, "0 events > %d s" % limit, "%d events" % n, "elastic search", n == 0))
    kb = fleetctl.kibana()
    code, rule = kb.call("GET", "/api/alerting/rule/" + fleetctl.RULE_ID, ok=(200, 404))
    state = "enabled" if code == 200 and rule.get("enabled", True) else ("disabled" if code == 200 else "missing")
    rows.append((target, "ingest-lag rule " + fleetctl.RULE_ID, mode, "enabled", state, "kibana alerting (Basic)", state == "enabled"))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("generation", nargs="?", type=int)
    ap.add_argument("--window", type=int, default=60)
    ap.add_argument("--lag-window", type=int, help="recent ingestion minutes for the steady-state lag check")
    a = ap.parse_args()
    gen = a.generation
    if gen is None:
        f = fleetctl.ROOT / ".state/targets" / (a.target + ".generation")
        gen = int(f.read_text()) if f.exists() else None
    fleetctl.policy_id(fleetctl.load_plan(), a.target)  # refuses unknown targets
    rows = check(fleetctl.elastic(), a.target, gen, a.window, a.lag_window)
    print("| source | destination/port | mode | expected | actual | enforcement point |")
    print("| --- | --- | --- | --- | --- | --- |")
    fail = 0
    for src, dst, mode, exp, act, enf, ok in rows:
        if not ok:
            fail = 1
        print("| %s | %s | %s | %s | %s | %s |" % (src, dst, mode, exp, act, enf))
    for name, why in MANUAL:
        print("| %s | %s | exercise | recorded by hand | %s | - |" % (a.target, name, why))
    print("\nphase=A4 target=%s generation=%s rows=%d manual=%d %s" % (a.target, gen, len(rows), len(MANUAL), "FAIL" if fail else "PASS-WITH-SKIPS"))
    return fail


if __name__ == "__main__":
    sys.exit(main())
