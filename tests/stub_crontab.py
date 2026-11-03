#!/usr/bin/env python3
"""Stand-in for `crontab` in the ops-timers tests: the table lives in the file named by CRON_FILE."""
import os
import sys

path = os.environ["CRON_FILE"]
if sys.argv[1:] == ["-l"]:
    if not os.path.exists(path):
        sys.stderr.write("no crontab for user\n")
        sys.exit(1)
    sys.stdout.write(open(path).read())
elif sys.argv[1:] == ["-"]:
    with open(path, "w") as f:
        f.write(sys.stdin.read())
else:
    sys.exit(2)
