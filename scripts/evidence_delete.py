#!/usr/bin/env python3
"""Evidence deletion (issue #24): removes ingested Elastic evidence. The only command that does.

  evidence-delete all                    every evidence data stream (plan.json elastic.datasets.evidence) and the markers
  evidence-delete exercise:ID            one exercise: its window on its target, plus its markers
  add --confirm "<phrase>"                  the phrase is printed by the dry run (scope and document count); without
                                            --confirm nothing is deleted and the exit status is 2

Drain-marker lines live in whatever stream the agent ships them to and are not deleted here.
Not imported by, and not callable from, reset, shutdown or lab.sh. Metrics are never touched. Refused while an exercise is
active. Take a snapshot first if the evidence might be wanted (Elasticsearch snapshot `lab-daily`, or run one by hand).
Env: ELASTIC_* as in scripts/elastic_api.py (SSH tunnel to 9200), LABMODE_STATE_DIR (default .state).
"""
import argparse
import getpass
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import elastic_api  # noqa: E402
from labcommon import active_exercise, die, load_plan, state_dir  # noqa: E402

FLOW = "logs-lab_firewall.flow"  # firewall flow rows carry no lab.target_id: matched by the window alone (one exercise at a time)


def main(argv):
    ap = argparse.ArgumentParser(prog="evidence_delete.py")
    ap.add_argument("scope", help="all | exercise:<id>")
    ap.add_argument("--confirm", default=None)
    a = ap.parse_args(argv[1:])
    plan = load_plan()
    state = state_dir()
    marker = plan["ops"]["marker_stream"]
    patterns = [n + "-*" for n in plan["elastic"]["datasets"]["evidence"]] + [marker]

    kind, _, ex = a.scope.partition(":")
    if kind not in ("all", "exercise") or (kind == "exercise") != bool(ex):
        die("scope is `all` or `exercise:<id>`")
    active = active_exercise(state)
    if active:
        die("exercise %s is active: end it first" % active["id"])

    es = elastic_api.es_client()
    # Local state can be lost or stale (another workstation): Elastic's own markers must agree no exercise is open.
    n = {act: es.call("/%s/_count" % marker, {"query": {"term": {"event.action": act}}})["count"]
         for act in ("exercise-start", "exercise-end")}
    if n["exercise-start"] != n["exercise-end"]:
        die("markers show an exercise without an end (%d starts, %d ends): end it first" % (n["exercise-start"], n["exercise-end"]))
    query = window = {"match_all": {}}
    if kind == "exercise":
        res = es.call("/%s/_search" % marker, {"query": {"bool": {"filter": [{"term": {"lab.exercise_id": ex}}]}}, "size": 10})
        docs = [h["_source"] for h in res["hits"]["hits"]]
        starts = [d["@timestamp"] for d in docs if d["event"]["action"] == "exercise-start"]
        ends = [d["@timestamp"] for d in docs if d["event"]["action"] == "exercise-end"]
        if not (starts and ends):
            die("exercise %s has no complete start/end markers: its window is unknown" % ex)
        target = docs[0]["lab"]["target_id"]
        window = {"range": {"@timestamp": {"gte": min(starts), "lte": max(ends)}}}
        query = {"bool": {"filter": [{"term": {"lab.target_id": target}}, window]}}

    def query_for(pattern):
        if kind == "exercise" and pattern == marker:  # the exercise's own markers go with it
            return {"term": {"lab.exercise_id": ex}}
        return window if pattern.startswith(FLOW) else query

    counts = {p: es.call("/%s/_count" % p, {"query": query_for(p)})["count"] for p in patterns}
    for p, n in counts.items():
        print("%8d  %s" % (n, p))
    # The phrase carries the previewed total, so a confirmation only matches what the operator was shown.
    phrase = "DELETE EVIDENCE %s (%d documents)" % (a.scope, sum(counts.values()))
    if a.confirm is None:
        print("nothing deleted. To delete, re-run with: --confirm \"%s\"" % phrase)
        return 2
    if a.confirm != phrase:
        die("confirmation must be exactly: %s" % phrase)

    for p in patterns:
        es.call("/%s/_delete_by_query" % p, {"query": query_for(p)})
    os.makedirs(state, exist_ok=True)
    with open(os.path.join(state, "evidence-delete.log"), "a") as f:
        f.write(json.dumps(dict(ts=time.time(), user=getpass.getuser(), scope=a.scope, counts=counts)) + "\n")
    print("deleted. Indices and data streams remain; only documents were removed.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
