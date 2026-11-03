#!/usr/bin/env python3
"""Stand-in for scripts/fleetctl.py in labops tests: issue-token prints a token (stdout only); calls are recorded."""
import os
import sys

with open(os.environ["STUB_LOG"], "a") as f:
    f.write("fleetctl|" + " ".join(sys.argv[1:]) + "\n")
if sys.argv[1] == "issue-token":
    if os.environ.get("STUB_FAIL") == "token":
        sys.exit(1)
    print("TOKEN-%s-%s" % (sys.argv[2], sys.argv[3]))
sys.exit(0)
