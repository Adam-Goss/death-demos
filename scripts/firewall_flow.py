#!/usr/bin/env python3
"""Collect parsed OPNsense flow logs over the admin API and index them over lab-CA TLS.

Poll every five seconds on the controller (install-flow-timer.sh). The API exposes a
bounded log window, not a durable queue: bursts beyond 100 rows between polls can be lost.
An independent controller checkpoint prevents replay after rollover or evidence deletion.
Generation boundaries come from Fleet enrolment,
so delayed firewall records never acquire the generation current at polling time.
"""
import datetime as dt
import argparse
import fcntl
import hashlib
import json
import os
import pathlib
import time

import fleetctl
import opnsense


def timestamp(value):
    # The seeded firewall uses Etc/UTC; its diagnostics timestamps omit the zone.
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.replace(tzinfo=dt.timezone.utc) if parsed.tzinfo is None else parsed


def events(rows, targets, created):
    for row in rows:
        when = timestamp(row["__timestamp__"])
        for target, config in targets.items():
            if config["ip"] not in (row.get("src"), row.get("dst")):
                continue
            generations = [g for g in config["generations"] if timestamp(g["since"]) <= when]
            if not generations:
                continue  # No verified generation for this historical record.
            gen = max(generations, key=lambda g: timestamp(g["since"]))["generation"]
            identity = "%s:%s:%s" % (row["__digest__"], target, gen)
            doc = {
                "@timestamp": when.isoformat(),
                "event": {"created": created, "dataset": "lab_firewall.flow", "kind": "event",
                          "category": ["network"], "action": row.get("action"), "original": json.dumps(row)},
                "data_stream": {"type": "logs", "dataset": "lab_firewall.flow", "namespace": "default"},
                "observer": {"name": row.get("__host__"), "type": "firewall", "vendor": "OPNsense"},
                "source": {"ip": row["src"]}, "destination": {"ip": row["dst"]},
                "network": {"transport": row.get("protoname")},
                "rule": {"name": row.get("label"), "id": row.get("rid")},
                "lab": {"target_id": target, "rebuild_generation": gen},
            }
            for field, key in (("source", "srcport"), ("destination", "dstport")):
                value = str(row.get(key, ""))
                if value.isdigit():
                    doc[field]["port"] = int(value)
            yield hashlib.sha256(identity.encode()).hexdigest(), doc


def index_events(es, records):
    checkpoint = pathlib.Path(os.environ.get("FIREWALL_FLOW_CHECKPOINT") or
                              fleetctl.ROOT / ".state/firewall-flow-checkpoint.json")
    checkpoint.parent.mkdir(parents=True, exist_ok=True)
    indexed = duplicates = 0
    # The cron worker and manual invocations must share collection progress.
    with checkpoint.with_suffix(".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        seen = dict.fromkeys(json.loads(checkpoint.read_text())["seen"] if checkpoint.exists() else [])
        for identity, doc in records:
            if identity in seen:
                duplicates += 1
                continue
            code, _ = es.call("PUT", "/logs-lab_firewall.flow-default/_create/" + identity, doc, ok=(201, 409))
            indexed += code == 201
            duplicates += code == 409
            seen[identity] = None
            # Ten API windows of history also cover minor response reordering.
            while len(seen) > 2000:
                del seen[next(iter(seen))]
            staging = checkpoint.with_suffix(".tmp")
            staging.write_text(json.dumps({"seen": list(seen)}) + "\n")
            staging.replace(checkpoint)
    return indexed, duplicates


def collect(ensured):
    es = fleetctl.elastic()
    plan = fleetctl.load_plan()
    _, pipeline = es.call("GET", "/_ingest/pipeline/" + plan["target_stack"]["stamp_pipeline"])
    params = pipeline[plan["target_stack"]["stamp_pipeline"]]["processors"][0]["script"]["params"]
    targets = params.get("firewall_targets", {})
    if not targets:
        fleetctl.die("no firewall generation boundaries; run register-agent after target enrolment", 1)
    if not ensured:
        es.call("PUT", "/_index_template/lab-firewall-flows", {
            "index_patterns": ["logs-lab_firewall.flow-*"], "priority": 300, "data_stream": {},
            "composed_of": ["logs-lab_firewall.flow@custom"],
            "template": {"mappings": {"properties": {
                "@timestamp": {"type": "date"},
                "event": {"properties": {"created": {"type": "date"}, "ingested": {"type": "date"}}},
                "source": {"properties": {"ip": {"type": "ip"}, "port": {"type": "long"}}},
                "destination": {"properties": {"ip": {"type": "ip"}, "port": {"type": "long"}}},
            }}},
        })
        ensured.append(True)
    fw = opnsense.Client(os.environ["OPNSENSE_URL"], os.environ["OPNSENSE_API_KEY"],
                         os.environ["OPNSENSE_API_SECRET"], os.environ.get("OPNSENSE_INSECURE") == "true")
    rows = fw.call("diagnostics/firewall/log?limit=100", method="GET")
    created = dt.datetime.now(dt.timezone.utc).isoformat()
    indexed, duplicates = index_events(es, events(rows, targets, created))
    print("firewall flows: indexed=%d duplicates=%d window_rows=%d" % (indexed, duplicates, len(rows)))
    if len(rows) >= 100 and duplicates == 0:
        print("WARNING: API log window is full; collection completeness is not guaranteed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--watch-seconds", type=int, default=0)
    args = parser.parse_args()
    ensured = []  # the index template is put once per run, not on every poll
    deadline = time.monotonic() + args.watch_seconds
    while True:
        collect(ensured)
        if time.monotonic() + 5 >= deadline:
            return
        time.sleep(5)


if __name__ == "__main__":
    main()
