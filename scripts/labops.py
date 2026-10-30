#!/usr/bin/env python3
"""Operator commands for the lab (issue #24). Run from the workstation, VPN up, Elastic tunnel open for 9200.

  labops.py exercise start ID --target T   set lab.exercise_id: writes the exercise-start marker event
  labops.py exercise end                   writes the exercise-end marker event, then stamps lab.exercise_id on that target's events in the window
  labops.py exercise tag ID                repeat the stamping (events still in transit at `end`); safe to re-run
  labops.py exercise show ID               time window and target of an exercise, from its markers
  labops.py generation T                   show the lab.rebuild_generation of target T (owned by scripts/target.sh)
  labops.py drain T                        emit a drain marker on target T and confirm it in Elasticsearch
  labops.py reset T [--acknowledge-loss REASON]
                                           drain check, then scripts/target.sh bump + provision for target T only (maintenance mode)
  labops.py attacker-clean                 clear attacker-side exercise state (separate from reset)
  labops.py shutdown [--include-elastic] [--acknowledge-loss REASON]
                                           drain running targets, then graceful power-off of lab guests; nothing is destroyed
  labops.py startup  [--include-elastic]   power the lab guests back on (firewall first)
  labops.py watermark                      high-watermark check for cron: exit 1 and ALERT at the plan limit (Basic-license fallback for the alert)
  labops.py analysis-online on|off|status [--minutes N]
                                           malware analysis zone (#52): Internet on (30 min default, auto-expires, `on` again extends) or off
  labops.py analysis-sample start ID | end set lab.sample_id on analysis-zone events (markers + stamping, like an exercise)
  labops.py analysis-reset [HOST ...] [--acknowledge-loss REASON]
                                           force analysis Internet off, drain check, revert flare/remnux to the clean snapshot, fresh enrolment
  labops.py status

Evidence deletion is deliberately NOT here: it is its own guarded, confirmed command and nothing in this file can reach it.
Reset can only name a target with a VM in network/plan.json `targets`; it runs scripts/target.sh (targets stack), never Elastic.
Shutdown leaves Elastic running unless --include-elastic is given, and then only asks it to shut down gracefully.

Env: LABMODE_STATE_DIR (default .state, shared with labmode.py), LAB_PLAN, the ELASTIC_* variables of
     scripts/elastic_api.py, PROXMOX_VE_ENDPOINT, PVE_NODE, PROXMOX_VE_INSECURE, PROXMOX_VE_API_TOKEN_<STACK>
     (shutdown/startup), LABOPS_SSH / LABOPS_TARGET_SH (command overrides, used by tests),
     LABOPS_LABMODE / LABOPS_FLEETCTL (command overrides, used by tests), PROXMOX_VE_API_TOKEN_ANALYSIS (analysis-reset: the token
     with snapshot rights on the analysis pool only),
     LABOPS_POLL (seconds, default plan ops.drain.poll_s), LABOPS_DRAIN_TIMEOUT, LABOPS_SHUTDOWN_WAIT.
"""
import argparse
import datetime
import getpass
import json
import os
import re
import secrets
import shlex
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import elastic_api  # noqa: E402
import labpower  # noqa: E402
import pve  # noqa: E402
from labcommon import ROOT, die, load_plan, state_dir  # noqa: E402

EXERCISE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
EXERCISE_DIR = "/srv/exercise"  # attacker-side working directory (ansible/roles/attacker)
MIN_REASON = 5


DRAIN_AGENT = "opaleye-drain/"


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def need_reason(reason):
    if reason is not None and len(reason.strip()) < MIN_REASON:
        die("--acknowledge-loss needs a reason of at least %d characters" % MIN_REASON)


class Ops:
    def __init__(self):
        self.plan = load_plan()
        d = state_dir()
        self.path, self.log = os.path.join(d, "labops.json"), os.path.join(d, "labops.log")
        self.labmode_path = os.path.join(d, "labmode.json")
        try:
            with open(self.path) as f:
                self.state = json.load(f)
        except FileNotFoundError:
            self.state = {"active": None}
        self.drain_cfg = self.plan["ops"]["drain"]
        self.poll = float(os.environ.get("LABOPS_POLL") or self.drain_cfg["poll_s"])

    def save(self, event, **detail):
        with open(self.path, "w") as f:
            json.dump(self.state, f)
        self.audit(event, **detail)

    def audit(self, event, **detail):
        """Audit line only. Commands that run from cron use this so they never rewrite the state file from a stale copy."""
        with open(self.log, "a") as f:
            f.write(json.dumps(dict(ts=stamp(), event=event, user=getpass.getuser(), **detail)) + "\n")

    def target(self, name):
        vms = [t for t, v in self.plan["targets"].items() if "vm_id" in v]
        if name not in vms:
            die("%r is not a target with a VM (%s); only targets can be reset or drained" % (name, ", ".join(vms)))
        return name

    def generation_of(self, target):
        """scripts/target.sh owns the counter (it also feeds Tofu and Ansible)."""
        r = subprocess.run([os.environ.get("LABOPS_TARGET_SH", os.path.join(ROOT, "scripts/target.sh")), "generation", target],
                           capture_output=True, text=True, cwd=ROOT)
        if r.returncode != 0 or not r.stdout.strip().isdigit():
            die("cannot read the rebuild generation of %s: %s" % (target, r.stderr.strip()))
        return int(r.stdout.strip())

    def need_elastic(self):
        es = elastic_api.es_client()
        try:
            es.call("/_cluster/health")
        except elastic_api.EsError as e:
            die("Elastic is not answering (%s); is the tunnel up (scripts/elastic-tunnel.sh)? No exercise start, reset or shutdown during an outage" % e)
        return es

    def ssh(self, host, command, stdin=None):
        """Analysis hosts are reachable only from the gateway VM: jump through it."""
        analysis = host in self.plan["analysis"]["hosts"]
        user = self.plan["analysis"]["ssh_user"] if analysis else self.plan["ops"]["ssh_user"]
        jump = ["-J", "%s@%s" % (self.plan["ops"]["ssh_user"], self.plan["hosts"]["gateway"]["ip"])] if analysis else []
        argv = shlex.split(os.environ.get("LABOPS_SSH", "ssh")) + [
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", *jump,
            "%s@%s" % (user, self.plan["hosts"][host]["ip"]), command]
        return subprocess.run(argv, input=stdin, text=True).returncode

    def marker(self, es, action, exercise_id, target, generation):
        when = stamp()
        es.call("/%s/_doc" % self.plan["ops"]["marker_stream"], {
            "@timestamp": when, "message": "%s %s %s" % (action, exercise_id, target),
            "event": {"action": action, "dataset": "lab_marker.events", "kind": "event"},
            "lab": {"exercise_id": exercise_id, "target_id": target, "rebuild_generation": generation}})
        return when

    def exercise_start(self, exercise_id, target):
        if not EXERCISE_ID.match(exercise_id):
            die("exercise id must match %s" % EXERCISE_ID.pattern)
        self.target(target)
        if self.state["active"]:
            die("exercise %s is still active (one at a time): run `exercise end`" % self.state["active"]["id"])
        try:
            with open(self.labmode_path) as f:
                firewall = json.load(f)
        except FileNotFoundError:
            firewall = {}
        if firewall.get("mode") != "exercise" or firewall.get("selected") != target:
            die("firewall is not in exercise mode with %s selected: run scripts/labmode.py select %s" % (target, target))
        es = self.need_elastic()
        limit = self.plan["ops"]["high_watermark_pct"]
        worst = self.disk_worst(es)
        if worst >= limit:
            die("Elasticsearch disk at %g%% (high watermark %d%%): new exercises are blocked; free space via evidence deletion" % (worst, limit))
        generation = self.generation_of(target)
        started = self.marker(es, "exercise-start", exercise_id, target, generation)
        self.state["active"] = {"id": exercise_id, "target": target, "generation": generation, "started": started}
        self.save("exercise-start", exercise_id=exercise_id, target=target)
        print("exercise %s started on %s (generation %d). On the attacker VM: exercise1 --exercise-id %s" % (exercise_id, target, generation, exercise_id))

    @staticmethod
    def disk_worst(es):
        # An unassigned shard adds an UNASSIGNED row with a null disk.percent: it has no disk, so it is not a reading.
        return max(float(r["disk.percent"]) for r in es.call("/_cat/allocation?format=json") if r.get("disk.percent") is not None)

    def watermark(self):
        """Scheduled check (cron, every few minutes): the high-watermark alert, as the Basic-license fallback from #9.
        Exit 1 and a line on stderr at or over the plan limit; an Elastic outage is an error, never an `ok`."""
        es = self.need_elastic()
        limit = self.plan["ops"]["high_watermark_pct"]
        worst = self.disk_worst(es)
        if worst >= limit:
            self.audit("watermark-alert", disk_percent=worst, limit=limit)
            print("ALERT: Elasticsearch disk at %g%% (high watermark %d%%): new exercises are blocked; free space via evidence deletion" % (worst, limit), file=sys.stderr)
            return 1
        print("ok: Elasticsearch disk at %g%% (high watermark %d%%)" % (worst, limit))
        return 0

    def exercise_end(self):
        active = self.state["active"]
        if not active:
            die("no active exercise")
        es = self.need_elastic()
        ended = self.marker(es, "exercise-end", active["id"], active["target"], active["generation"])
        self.state["active"] = None
        self.save("exercise-end", exercise_id=active["id"], target=active["target"])
        print("exercise %s ended. Next: drain %s, then reset %s" % (active["id"], active["target"], active["target"]))
        try:
            self.stamp_window(es, active["id"], active["target"], active["generation"], active["started"], ended)
        except elastic_api.EsError as e:
            print("warning: events not tagged (%s): re-run `exercise tag %s`" % (e, active["id"]), file=sys.stderr)

    def stamp_window(self, es, exercise_id, target, generation, started, ended):
        """Stamp lab.exercise_id on the target's events (this generation) between the markers; safe to repeat.

        The window is widened by plan ops.tag_slack_s each side: hosts' clocks differ by about a second and Apache
        logs whole seconds, so the first request of an exercise can carry a time just before the start marker."""
        slack = datetime.timedelta(seconds=self.plan["ops"]["tag_slack_s"])
        def widen(ts, sign):
            when = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00")) + sign * slack
            return when.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        started, ended = widen(started, -1), widen(ended, 1)
        res = es.call("/logs-*,metrics-*/_update_by_query?conflicts=proceed&refresh=true&ignore_unavailable=true", {
            "query": {"bool": {
                "filter": [{"term": {"lab.target_id": target}}, {"term": {"lab.rebuild_generation": generation}},
                           {"range": {"@timestamp": {"gte": started, "lte": ended}}}],
                "must_not": [{"exists": {"field": "lab.exercise_id"}}, {"term": {"event.dataset": "lab_marker.events"}}]}},
            "script": {"lang": "painless", "params": {"id": exercise_id},
                       "source": "if (ctx._source.lab == null) { ctx._source.lab = new HashMap(); } ctx._source.lab.exercise_id = params.id"}})
        print("tagged %d events with lab.exercise_id=%s (events still in transit: run `exercise tag %s` later)"
              % (res.get("updated", 0), exercise_id, exercise_id))

    def exercise_tag(self, exercise_id):
        es = self.need_elastic()
        res = es.call("/%s/_search" % self.plan["ops"]["marker_stream"], {
            "query": {"bool": {"filter": [{"term": {"lab.exercise_id": exercise_id}}]}}, "size": 10})
        docs = {h["_source"]["event"]["action"]: h["_source"] for h in res["hits"]["hits"]}
        if "exercise-start" not in docs or "exercise-end" not in docs:
            die("exercise %s needs both its start and end markers" % exercise_id)
        s, e = docs["exercise-start"], docs["exercise-end"]
        self.stamp_window(es, exercise_id, s["lab"]["target_id"], s["lab"]["rebuild_generation"], s["@timestamp"], e["@timestamp"])

    def exercise_show(self, exercise_id):
        res = elastic_api.es_client().call("/%s/_search" % self.plan["ops"]["marker_stream"], {
            "query": {"bool": {"filter": [{"term": {"lab.exercise_id": exercise_id}}]}}, "size": 10})
        docs = [h["_source"] for h in res["hits"]["hits"]]
        if not docs:
            die("no markers for exercise %s" % exercise_id)
        for d in docs:
            print("%s  %s  target=%s generation=%s" % (d["@timestamp"], d["event"]["action"], d["lab"]["target_id"],
                                                       d["lab"]["rebuild_generation"]))
        if not any(d["event"]["action"] == "exercise-end" for d in docs):
            print("(no end marker: exercise still running or never ended)")

    def generation(self, target):
        print(self.generation_of(self.target(target)))

    def drain(self, target, es=None):
        """Emit a drain marker on the target (it travels the same agent pipeline as evidence) and wait for it in ES."""
        self.target(target)
        es = es or elastic_api.es_client()
        generation = self.generation_of(target)
        token = secrets.token_hex(8)
        # A valid Apache combined-log line: the Apache access pipeline rejects anything else (no `message`, no lab-stamp),
        # and as a real record it is parsed and stamped like the evidence it vouches for. The token is the User-Agent.
        line = '127.0.0.1 - - [%s] "GET /opaleye-drain?target_id=%s&rebuild_generation=%d HTTP/1.1" 200 0 "-" "%s%s"' % (
            time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime()), target, generation, DRAIN_AGENT, token)
        cmd = "printf '%%s\\n' %s | sudo -n tee -a %s >/dev/null" % (shlex.quote(line), shlex.quote(self.drain_cfg["log"]))
        if self.ssh(target, cmd) != 0:
            print("drain marker could not be written on %s (ssh failed)" % target, file=sys.stderr)
            return False
        end = time.time() + float(os.environ.get("LABOPS_DRAIN_TIMEOUT") or self.drain_cfg["timeout_s"])
        query = {"query": {"bool": {"filter": [{"term": {"lab.rebuild_generation": generation}},
                                                {"term": {"user_agent.original": DRAIN_AGENT + token}}]}}, "size": 1}
        while True:
            try:
                if es.call("/logs-*/_search", query)["hits"]["hits"]:
                    print("drained: marker %s for %s generation %d arrived in Elasticsearch" % (token, target, generation))
                    return True
            except elastic_api.EsError:
                pass
            if time.time() >= end:
                print("not drained: marker %s (generation %d) did not arrive from %s in time" % (token, generation, target), file=sys.stderr)
                return False
            time.sleep(self.poll)

    def reset(self, target, ack):
        self.target(target)
        need_reason(ack)
        active = self.state["active"]
        if active and active["target"] == target:
            die("exercise %s is active on %s: run `exercise end` first" % (active["id"], target))
        # Provisioning pulls images and packages: only maintenance mode allows that, so find out before anything changes.
        self.need_maintenance()
        es = self.need_elastic()  # no reset during an Elastic outage, override or not
        drained = self.drain(target, es)
        if not drained and ack is None:
            die("drain check failed; fix forwarding or accept the loss with --acknowledge-loss REASON")
        target_sh = os.environ.get("LABOPS_TARGET_SH", os.path.join(ROOT, "scripts/target.sh"))
        if subprocess.run([target_sh, "bump", target, "--acknowledge-no-drain-check"], cwd=ROOT).returncode != 0:
            print("generation bump failed: nothing was rebuilt", file=sys.stderr)
            return 1
        generation = self.generation_of(target)
        self.save("reset-bumped", target=target, drained=drained, acknowledged_loss=ack, generation=generation)
        # target.sh provision replaces the VM (the generation is a replace trigger), then enrols a fresh agent:
        # fleetctl issue-token deletes the target's older tokens and revokes its older agents.
        if subprocess.run([target_sh, "provision", target], cwd=ROOT).returncode != 0:
            self.save("reset-failed", target=target, generation=generation)
            print("provisioning failed at generation %d: re-run `scripts/target.sh provision %s` (a failed target is rebuilt, never hand-repaired)" % (generation, target), file=sys.stderr)
            return 1
        self.save("reset", target=target, drained=drained, acknowledged_loss=ack, generation=generation)
        print("%s rebuilt: generation %d. Prior events stay searchable by exercise id. Return to exercise mode and re-verify denies (labmode.py)." % (target, generation))
        return 0

    def need_maintenance(self):
        try:
            with open(self.labmode_path) as f:
                mode = json.load(f).get("mode")
        except FileNotFoundError:
            mode = None
        if mode != "maintenance":
            die("provisioning needs maintenance mode: run scripts/labmode.py maintenance --minutes 60 --reason \"target reset\" first")

    # ---- malware analysis zone (#52) ------------------------------------------------------------------------------

    def analysis_host(self, name):
        if name not in self.plan["analysis"]["hosts"]:
            die("%r is not an analysis host (%s)" % (name, ", ".join(self.plan["analysis"]["hosts"])))
        return name

    def labmode(self, *args):
        argv = shlex.split(os.environ.get("LABOPS_LABMODE") or "") or [sys.executable, os.path.join(ROOT, "scripts/labmode.py")]
        return subprocess.run(argv + list(args), cwd=ROOT).returncode

    def analysis_online(self, action, minutes):
        args = ["analysis", action] + (["--minutes", str(minutes)] if minutes is not None else [])
        rc = self.labmode(*args)
        if rc == 0 and action != "status":
            self.audit("analysis-online-" + action, minutes=minutes)
            if action == "on":
                print("Go offline BEFORE detonating a sample (C2 and home-IP risk): labops.py analysis-online off")
        return rc

    def sample_marker(self, es, action, sample_id):
        when = stamp()
        es.call("/%s/_doc" % self.plan["ops"]["marker_stream"], {
            "@timestamp": when, "message": "%s %s analysis" % (action, sample_id),
            "event": {"action": action, "dataset": "lab_marker.events", "kind": "event"},
            "lab": {"sample_id": sample_id, "zone": "analysis"}})
        return when

    def analysis_sample_start(self, sample_id):
        if not EXERCISE_ID.match(sample_id):
            die("sample id must match %s" % EXERCISE_ID.pattern)
        if self.state.get("sample"):
            die("sample %s is still active (one at a time): run `analysis-sample end`" % self.state["sample"]["id"])
        es = self.need_elastic()
        started = self.sample_marker(es, "sample-start", sample_id)
        self.state["sample"] = {"id": sample_id, "started": started}
        self.save("sample-start", sample_id=sample_id)
        print("sample %s started: analysis-zone events get lab.sample_id when you run `analysis-sample end`" % sample_id)

    def analysis_sample_end(self):
        active = self.state.get("sample")
        if not active:
            die("no active sample")
        es = self.need_elastic()
        ended = self.sample_marker(es, "sample-end", active["id"])
        self.state["sample"] = None
        self.save("sample-end", sample_id=active["id"])
        slack = datetime.timedelta(seconds=self.plan["ops"]["tag_slack_s"])

        def widen(ts, sign):
            when = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00")) + sign * slack
            return when.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        try:
            res = es.call("/logs-*,metrics-*/_update_by_query?conflicts=proceed&refresh=true&ignore_unavailable=true", {
                "query": {"bool": {
                    "filter": [{"term": {"lab.zone": "analysis"}},
                               {"range": {"@timestamp": {"gte": widen(active["started"], -1), "lte": widen(ended, 1)}}}],
                    "must_not": [{"exists": {"field": "lab.sample_id"}}, {"term": {"event.dataset": "lab_marker.events"}}]}},
                "script": {"lang": "painless", "params": {"id": active["id"]},
                           "source": "if (ctx._source.lab == null) { ctx._source.lab = new HashMap(); } ctx._source.lab.sample_id = params.id"}})
            print("sample %s ended: tagged %d events with lab.sample_id" % (active["id"], res.get("updated", 0)))
        except elastic_api.EsError as e:
            print("warning: events not tagged (%s): see the analysis runbook to repeat the stamping" % e, file=sys.stderr)

    def analysis_generation(self, host):
        return self.state.get("analysis_generation", {}).get(host, 1)

    def analysis_drain(self, host, es):
        """Write a drain marker into the host's drain log (shipped by its agent) and wait for it in Elasticsearch."""
        cfg = self.plan["analysis"]
        token = secrets.token_hex(8)
        line = "opaleye-drain/%s zone=analysis host=%s generation=%d" % (token, host, self.analysis_generation(host))
        if cfg["hosts"][host]["os"] == "windows":
            cmd = 'powershell -NoProfile -Command "Add-Content -Path \'%s\' -Value \'%s\'"' % (cfg["drain"]["log_windows"], line)
        else:
            cmd = "printf '%%s\\n' %s | sudo -n tee -a %s >/dev/null" % (shlex.quote(line), shlex.quote(cfg["drain"]["log_linux"]))
        if self.ssh(host, cmd) != 0:
            print("drain marker could not be written on %s (ssh failed)" % host, file=sys.stderr)
            return False
        end = time.time() + float(os.environ.get("LABOPS_DRAIN_TIMEOUT") or self.drain_cfg["timeout_s"])
        query = {"query": {"bool": {"filter": [{"term": {"lab.zone": "analysis"}},
                                                {"match_phrase": {"message": "opaleye-drain/" + token}}]}}, "size": 1}
        while True:
            try:
                if es.call("/logs-*/_search", query)["hits"]["hits"]:
                    print("drained: marker %s from %s arrived in Elasticsearch" % (token, host))
                    return True
            except elastic_api.EsError:
                pass
            if time.time() >= end:
                print("not drained: marker %s did not arrive from %s in time" % (token, host), file=sys.stderr)
                return False
            time.sleep(self.poll)

    def analysis_reset(self, hosts, ack):
        """Revert to the clean Proxmox snapshot (no rebuild). Internet goes off first, whatever happens next."""
        need_reason(ack)
        hosts = [self.analysis_host(h) for h in hosts] or list(self.plan["analysis"]["hosts"])
        if self.state.get("sample"):
            die("sample %s is active: run `analysis-sample end` first" % self.state["sample"]["id"])
        if self.labmode("analysis", "off") != 0:
            die("could not switch analysis Internet off; nothing was reverted")
        client = pve.from_env("analysis")
        es = self.need_elastic()
        cfg = self.plan["analysis"]
        running = [h for h in hosts if client.status(cfg["hosts"][h]["vm_id"]) == "running"]
        undrained = [h for h in running if not self.analysis_drain(h, es)]
        if undrained and ack is None:
            die("drain check failed for %s; fix forwarding or accept the loss with --acknowledge-loss REASON" % ", ".join(undrained))
        wait = float(os.environ.get("LABOPS_SHUTDOWN_WAIT") or 120)
        fleetctl = shlex.split(os.environ.get("LABOPS_FLEETCTL") or "") or [sys.executable, os.path.join(ROOT, "scripts/fleetctl.py")]
        for h in hosts:
            vmid = cfg["hosts"][h]["vm_id"]
            was_running = h in running
            client.rollback(vmid, cfg["snapshot"])
            client.wait(vmid, "stopped", wait, min(self.poll, 2))  # a rollback leaves the guest stopped
            if not was_running:
                print("%s reverted; it was off, so it stays off (generation not enrolled until it runs: re-run analysis-reset %s after starting it)" % (h, h))
                continue
            if not self.start_after_rollback(client, vmid, wait):
                print("%s did not start after the revert" % h, file=sys.stderr)
                return 1
            generation = self.analysis_generation(h) + 1
            self.state.setdefault("analysis_generation", {})[h] = generation
            self.save("analysis-reverted", host=h, generation=generation, drained=h not in undrained, acknowledged_loss=ack)
            if self.enrol(h, generation, fleetctl) != 0:
                print("%s reverted (generation %d) but enrolment failed: re-run `analysis-reset %s`" % (h, generation, h), file=sys.stderr)
                return 1
            print("%s reverted to snapshot %r: generation %d, fresh enrolment" % (h, cfg["snapshot"], generation))
        self.save("analysis-reset", hosts=hosts, acknowledged_loss=ack)
        print("Analysis Internet is off. Tool updates: go online, update, then take a new snapshot (runbook).")
        return 0

    def start_after_rollback(self, client, vmid, wait):
        """The rollback task may still hold the VM lock when the API has already returned: retry the start until it takes."""
        end = time.time() + wait
        while True:
            try:
                if client.status(vmid) != "running":
                    client.start(vmid)
                return client.wait(vmid, "running", max(end - time.time(), 0), min(self.poll, 2))
            except pve.PveError:
                if time.time() >= end:
                    return False
                time.sleep(self.poll)

    def enrol(self, host, generation, fleetctl):
        """Fresh token (retires the old agent), enrol the snapshot's unenrolled agent over SSH, register for lab fields."""
        r = subprocess.run(fleetctl + ["issue-token", host, str(generation)], capture_output=True, text=True, cwd=ROOT)
        token = r.stdout.strip()
        if r.returncode != 0 or not token:
            print("cannot issue an enrolment token for %s: %s" % (host, r.stderr.strip()), file=sys.stderr)
            return 1
        url = "https://%s:8220" % self.plan["hosts"]["elastic"]["ip"]
        if self.plan["analysis"]["hosts"][host]["os"] == "windows":
            cmd = ('powershell -NoProfile -Command "& \'C:\\Program Files\\Elastic\\Agent\\elastic-agent.exe\' enroll --force --non-interactive '
                   '--url=%s --certificate-authorities=C:\\ProgramData\\opaleye\\ca.crt --enrollment-token ([Console]::In.ReadLine())"' % url)
        else:
            cmd = ('sudo -n elastic-agent enroll --force --non-interactive --url=%s '
                   '--certificate-authorities=/etc/lab-ca/ca.crt --enrollment-token="$(cat)"' % url)
        if self.ssh(host, cmd, stdin=token + "\n") != 0:  # the token travels on stdin, never in an argument list
            return 1
        return subprocess.run(fleetctl + ["register-agent", host, str(generation)], cwd=ROOT).returncode

    def attacker_clean(self):
        if self.ssh("attacker", "find %s -mindepth 1 -delete" % shlex.quote(EXERCISE_DIR)) != 0:
            return 1
        self.save("attacker-clean")
        print("attacker %s cleared" % EXERCISE_DIR)
        return 0

    def power(self, action, include_elastic, ack=None):
        need_reason(ack)
        if self.state["active"]:
            die("exercise %s is active: run `exercise end` first" % self.state["active"]["id"])
        if action == "shutdown":
            self.drain_before_shutdown(ack)
        wait = float(os.environ.get("LABOPS_SHUTDOWN_WAIT") or 120)
        failed = labpower.run(self.plan, action, include_elastic, wait, self.poll, print)
        self.save(action, include_elastic=include_elastic, failed=failed, acknowledged_loss=ack)
        if not include_elastic:
            print("Elastic left running (use --include-elastic to %s it; graceful only, nothing is destroyed)" % ("power it off" if action == "shutdown" else "start it"))
        if failed:
            print("not %s: %s (nothing was forced; retry or use the Proxmox console)" % ("stopped" if action == "shutdown" else "started", ", ".join(map(str, failed))), file=sys.stderr)
            return 1
        return 0

    def drain_before_shutdown(self, ack):
        """Powering a target off with events unshipped loses them: check first, all targets, before anything is stopped."""
        running = labpower.running_targets(self.plan)
        if not running:
            return
        es = self.need_elastic() if ack is None else elastic_api.es_client()
        undrained = [t for t in running if not self.drain(t, es)]
        if undrained and ack is None:
            die("drain check failed for %s; fix forwarding or accept the loss with --acknowledge-loss REASON" % ", ".join(undrained))


def main(argv):
    ap = argparse.ArgumentParser(prog="labops.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    exercise = sub.add_parser("exercise").add_subparsers(dest="sub", required=True)
    start = exercise.add_parser("start")
    start.add_argument("id"), start.add_argument("--target", required=True)
    exercise.add_parser("end")
    exercise.add_parser("show").add_argument("id")
    exercise.add_parser("tag").add_argument("id")
    sub.add_parser("generation").add_argument("target")
    sub.add_parser("drain").add_argument("target")
    reset = sub.add_parser("reset")
    reset.add_argument("target"), reset.add_argument("--acknowledge-loss", metavar="REASON", default=None)
    for name in ("shutdown", "startup"):
        power = sub.add_parser(name)
        power.add_argument("--include-elastic", action="store_true")
        if name == "shutdown":
            power.add_argument("--acknowledge-loss", metavar="REASON", default=None)
    online = sub.add_parser("analysis-online")
    online.add_argument("action", choices=("on", "off", "status")), online.add_argument("--minutes", type=int, default=None)
    sample = sub.add_parser("analysis-sample").add_subparsers(dest="sub", required=True)
    sample.add_parser("start").add_argument("id")
    sample.add_parser("end")
    ar = sub.add_parser("analysis-reset")
    ar.add_argument("hosts", nargs="*"), ar.add_argument("--acknowledge-loss", metavar="REASON", default=None)
    for name in ("attacker-clean", "status", "watermark"):
        sub.add_parser(name)
    a = ap.parse_args(argv[1:])

    ops = Ops()
    try:
        if a.cmd == "exercise" and a.sub == "start":
            ops.exercise_start(a.id, a.target)
        elif a.cmd == "exercise" and a.sub == "end":
            ops.exercise_end()
        elif a.cmd == "exercise" and a.sub == "tag":
            ops.exercise_tag(a.id)
        elif a.cmd == "exercise":
            ops.exercise_show(a.id)
        elif a.cmd == "generation":
            ops.generation(a.target)
        elif a.cmd == "drain":
            return 0 if ops.drain(a.target) else 1
        elif a.cmd == "reset":
            return ops.reset(a.target, a.acknowledge_loss)
        elif a.cmd in ("shutdown", "startup"):
            return ops.power(a.cmd, a.include_elastic, getattr(a, "acknowledge_loss", None))
        elif a.cmd == "analysis-online":
            return ops.analysis_online(a.action, a.minutes)
        elif a.cmd == "analysis-sample" and a.sub == "start":
            ops.analysis_sample_start(a.id)
        elif a.cmd == "analysis-sample":
            ops.analysis_sample_end()
        elif a.cmd == "analysis-reset":
            return ops.analysis_reset(a.hosts, a.acknowledge_loss)
        elif a.cmd == "attacker-clean":
            return ops.attacker_clean()
        elif a.cmd == "watermark":
            return ops.watermark()
        elif a.cmd == "status":
            print(json.dumps(ops.state))
    except (elastic_api.EsError, pve.PveError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
