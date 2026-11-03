#!/usr/bin/env python3
"""Stand-in for scripts/labmode.py in labops tests: records the call; STUB_FAIL=labmode makes it fail."""
import json
import os
import sys

with open(os.environ["STUB_LOG"], "a") as f:
    f.write("labmode|" + " ".join(sys.argv[1:]) + "\n")
sys.exit(1 if os.environ.get("STUB_FAIL") == "labmode" else 0)
