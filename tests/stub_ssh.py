#!/usr/bin/env python3
"""Stand-in for ssh in labops tests: records the call; plays the Elastic Agent for drain-marker writes."""
import json
import os
import re
import sys
import urllib.request

cmd = sys.argv[-1]
with open(os.environ["STUB_LOG"], "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\n")
m = re.search(r'target_id=(\w+)&rebuild_generation=(\d+) HTTP/1.1" 200 0 "-" "opaleye-drain/(\w+)"', cmd)
if "drain.log" in cmd and m and not os.environ.get("STUB_DROP"):
    gen = int(os.environ.get("STUB_GENERATION") or m.group(2))
    body = json.dumps({"@timestamp": "2026-10-28T10:00:00Z", "user_agent": {"original": "opaleye-drain/" + m.group(3)},
                       "lab": {"target_id": m.group(1), "rebuild_generation": gen}}).encode()
    urllib.request.urlopen(urllib.request.Request(
        os.environ["FAKE_ES_URL"] + "/logs-lab_drain.marker-default/_doc", data=body, method="POST"))
m = re.search(r"opaleye-drain/(\w+) zone=analysis host=(\w+)", cmd)
if "drain.log" in cmd and m and not os.environ.get("STUB_DROP"):
    body = json.dumps({"@timestamp": "2026-10-30T10:00:00Z", "message": "opaleye-drain/%s zone=analysis" % m.group(1),
                       "lab": {"zone": "analysis"}}).encode()
    urllib.request.urlopen(urllib.request.Request(
        os.environ["FAKE_ES_URL"] + "/logs-lab_drain.marker-analysis/_doc", data=body, method="POST"))
if "--enrollment-token" in cmd:  # the token arrives on stdin, never in the argument list
    with open(os.environ["STUB_LOG"], "a") as f:
        f.write("stdin|" + sys.stdin.read().strip() + "\n")
sys.exit(int(os.environ.get("STUB_RC") or 0))
