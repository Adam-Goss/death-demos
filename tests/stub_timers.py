#!/usr/bin/env python3
"""Stand-in for `scripts/ops-timers.sh status` in the labops doctor tests: STUB_TIMERS=bad reports a missing timer."""
import os
import sys

if os.environ.get("STUB_TIMERS") == "bad":
    print("ok opaleye-labmode-tick")
    print("STALE opaleye-firewall-flow: /old/checkout does not exist")
    print("MISSING opaleye-elastic-tunnel")
    sys.exit(1)
for tag in ("opaleye-labmode-tick", "opaleye-firewall-flow", "opaleye-elastic-tunnel"):
    print("ok " + tag)
