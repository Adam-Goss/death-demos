#!/usr/bin/env python3
"""A10 measurement (issue #25): indexed bytes per evidence class and CPU/RAM of the Elastic components.

  a10_measure.py snapshot LABEL      write .state/a10/LABEL.json (docs and store bytes per class, process CPU/RAM)
  a10_measure.py report A B [HOURS]  per-class delta between snapshots A and B (per hour when HOURS is given)

Needs the VPN and scripts/elastic-tunnel.sh (ES calls). CPU/RAM come from `ps` over ssh on the Elastic VM and the target
(opaleye user, the same admin path Ansible uses); they are point samples, not averages. Env as for scripts/elastic_api.py.
"""
import json
import os
import pathlib
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import elastic_api  # noqa: E402
from labcommon import ROOT, load_plan  # noqa: E402

OUT = pathlib.Path(ROOT) / ".state" / "a10"
CLASSES = {
    "defend process": "logs-endpoint.events.process-*",
    "defend network": "logs-endpoint.events.network-*",
    "defend file/other": "logs-endpoint.events.file-*,logs-endpoint.events.security-*,logs-endpoint.events.library-*",
    "auditd": "logs-auditd_manager.auditd-*",
    "docker container logs": "logs-docker.container_logs-*",
    "apache access": "logs-apache.access-*",
    "apache error": "logs-apache.error-*",
    "firewall flow": "logs-lab_firewall.flow-*",
    "metrics (all)": "metrics-*",
    "agent logs": "logs-elastic_agent*",
}
PROCESSES = {  # label -> (host key, pgrep -f pattern)
    "elasticsearch": ("elastic", "org.elasticsearch.server"),
    "kibana": ("elastic", "kbn/cli/kibana/dist"),
    "fleet-server component": ("elastic", "components/fleet-server --agent-mode"),
    "elastic-agent (supervisor)": ("elastic", "/opt/Elastic/Agent/elastic-agent$"),
    "elastic-agent otel collector": ("elastic", "components/elastic-otel-collector"),
    "defend (elastic-endpoint)": ("t1", "elastic-endpoint"),
}


def store(es, pattern):
    stats = es.call("/%s/_stats/store,docs?expand_wildcards=all&ignore_unavailable=true&allow_no_indices=true" % pattern)
    total = stats.get("_all", {}).get("primaries", {})  # empty when the pattern matches no index yet
    return {"docs": total.get("docs", {}).get("count", 0), "bytes": total.get("store", {}).get("size_in_bytes", 0)}


def ps_sample(plan, host_key, pattern):
    ip = plan["hosts"][host_key]["ip"]
    # [x]yz trick: the remote shell's own command line contains the pattern text and must not match itself.
    cmd = "pid=$(pgrep -of %r) && ps -o rss=,pcpu=,etimes= -p $pid" % ("[%s]%s" % (pattern[0], pattern[1:]))
    r = subprocess.run(["ssh", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new", "opaleye@" + ip, cmd],
                       capture_output=True, text=True)
    parts = r.stdout.split()
    if r.returncode != 0 or len(parts) != 3:
        return {"error": (r.stderr or r.stdout).strip()[:120]}
    return {"rss_mb": round(int(parts[0]) / 1024, 1), "cpu_pct_lifetime": float(parts[1]), "uptime_s": int(parts[2])}


def snapshot(label):
    plan, es = load_plan(), elastic_api.es_client()
    data = {"label": label, "taken": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "epoch": int(time.time()), "classes": {}, "processes": {}}
    for name, pattern in CLASSES.items():
        data["classes"][name] = store(es, pattern)
    for name, (host, pattern) in PROCESSES.items():
        data["processes"][name] = ps_sample(plan, host, pattern)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / (label + ".json")).write_text(json.dumps(data, indent=1))
    print("snapshot %s written (%s)" % (label, data["taken"]))


def report(a, b, hours=None):
    A, B = (json.loads((OUT / (x + ".json")).read_text()) for x in (a, b))
    if hours is not None and hours <= 0:
        raise SystemExit("HOURS must be greater than 0")
    scale = (1.0 / hours) if hours else 1.0
    unit = "/h" if hours else ""
    # Store-size deltas go negative when Lucene merges segments, so size is estimated as new docs times the class's
    # average bytes per document at the later snapshot; the raw store delta is shown for reference only.
    print("| evidence class | docs%s | est. indexed KB%s | avg bytes/doc | raw store delta KB%s |" % (unit, unit, unit))
    print("| --- | --- | --- | --- | --- |")
    for name in CLASSES:
        if name not in A["classes"] or name not in B["classes"]:
            print("| %s | n/a (not in both snapshots) | | | |" % name)
            continue
        d = B["classes"][name]["docs"] - A["classes"][name]["docs"]
        avg = B["classes"][name]["bytes"] / B["classes"][name]["docs"] if B["classes"][name]["docs"] else 0
        raw = (B["classes"][name]["bytes"] - A["classes"][name]["bytes"]) / 1024
        print("| %s | %.0f | %.1f | %.0f | %.1f |" % (name, d * scale, d * avg * scale / 1024, avg, raw * scale))
    print()
    print("| process (at %s) | RSS MB | CPU %% (lifetime avg) |" % B["label"])
    print("| --- | --- | --- |")
    for name, p in B["processes"].items():
        print("| %s | %s | %s |" % (name, p.get("rss_mb", p.get("error")), p.get("cpu_pct_lifetime", "")))


def main(argv):
    if len(argv) >= 3 and argv[1] == "snapshot":
        snapshot(argv[2])
    elif len(argv) >= 4 and argv[1] == "report":
        try:
            hours = float(argv[4]) if len(argv) > 4 else None
        except ValueError:
            raise SystemExit("HOURS must be a number")
        report(argv[2], argv[3], hours)
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
