#!/usr/bin/env python3
"""Operator commands for the lab (issue #24). Run from the workstation, VPN up, Elastic tunnel open for 9200.

  labops.py exercise start ID --target T   set lab.exercise_id: writes the exercise-start marker event
  labops.py exercise end                   writes the exercise-end marker event
  labops.py exercise show ID               time window and target of an exercise, from its markers
  labops.py generation T [N]               show (or align) the tracked lab.rebuild_generation of target T
  labops.py drain T                        emit a drain marker on target T and confirm it in Elasticsearch
  labops.py reset T [--acknowledge-loss REASON]
                                           drain check, retire the agent, rebuild target T only, bump its generation
  labops.py attacker-clean                 clear attacker-side exercise state (separate from reset)
  labops.py shutdown [--include-elastic] [--acknowledge-loss REASON]
                                           drain running targets, then graceful power-off of lab guests; nothing is destroyed
  labops.py startup  [--include-elastic]   power the lab guests back on (firewall first)
  labops.py status

Evidence deletion is deliberately NOT here: it is its own guarded, confirmed command and nothing in this file can reach it.
Reset can only name a target in network/plan.json `targets`; it runs lab.sh against the targets stack, never Elastic.
Shutdown leaves Elastic running unless --include-elastic is given, and then only asks it to shut down gracefully.

Env: LABMODE_STATE_DIR (default .state, shared with labmode.py), LAB_PLAN, the ELASTIC_* variables of
     scripts/elastic_api.py, PROXMOX_VE_ENDPOINT, PVE_NODE, PROXMOX_VE_INSECURE, PROXMOX_VE_API_TOKEN_<STACK>
     (shutdown/startup), LABOPS_SSH / LABOPS_LAB_SH / LABOPS_ANSIBLE (command overrides, used by tests),
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
            self.state = {"active": None, "generations": {t: 1 for t in self.plan["targets"]}}
        self.drain_cfg = self.plan["ops"]["drain"]
        self.poll = float(os.environ.get("LABOPS_POLL") or self.drain_cfg["poll_s"])

    def save(self, event, **detail):
        with open(self.path, "w") as f:
            json.dump(self.state, f)
        with open(self.log, "a") as f:
            f.write(json.dumps(dict(ts=stamp(), event=event, user=getpass.getuser(), **detail)) + "\n")

    def target(self, name):
        if name not in self.plan["targets"]:
            die("%r is not a target (%s); only targets can be reset or drained" % (name, ", ".join(self.plan["targets"])))
        return name

    def need_elastic(self):
        es = elastic_api.es_client()
        try:
            es.call("/_cluster/health")
        except elastic_api.EsError as e:
            die("Elastic is not answering (%s); is the tunnel up (scripts/elastic-tunnel.sh)? No exercise start, reset or shutdown during an outage" % e)
        return es

    def ssh(self, host, command):
        argv = shlex.split(os.environ.get("LABOPS_SSH", "ssh")) + [
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
            "%s@%s" % (self.plan["ops"]["ssh_user"], self.plan["hosts"][host]["ip"]), command]
        return subprocess.run(argv).returncode

    def marker(self, es, action, exercise_id, target, generation):
        es.call("/%s/_doc" % self.plan["ops"]["marker_stream"], {
            "@timestamp": stamp(), "message": "%s %s %s" % (action, exercise_id, target),
            "event": {"action": action, "dataset": "lab_marker.events", "kind": "event"},
            "lab": {"exercise_id": exercise_id, "target_id": target, "rebuild_generation": generation}})

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
        worst = max(float(r["disk.percent"]) for r in es.call("/_cat/allocation?format=json"))
        if worst >= limit:
            die("Elasticsearch disk at %g%% (high watermark %d%%): new exercises are blocked; free space via evidence deletion" % (worst, limit))
        generation = self.state["generations"][target]
        self.marker(es, "exercise-start", exercise_id, target, generation)
        self.state["active"] = {"id": exercise_id, "target": target, "generation": generation, "started": stamp()}
        self.save("exercise-start", exercise_id=exercise_id, target=target)
        print("exercise %s started on %s (generation %d). On the attacker VM: exercise1 --exercise-id %s" % (exercise_id, target, generation, exercise_id))

    def exercise_end(self):
        active = self.state["active"]
        if not active:
            die("no active exercise")
        self.marker(self.need_elastic(), "exercise-end", active["id"], active["target"], active["generation"])
        self.state["active"] = None
        self.save("exercise-end", exercise_id=active["id"], target=active["target"])
        print("exercise %s ended. Next: drain %s, then reset %s" % (active["id"], active["target"], active["target"]))

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

    def generation(self, target, value):
        self.target(target)
        if value is not None:
            self.state["generations"][target] = value
            self.save("generation", target=target, generation=value)
        print(self.state["generations"][target])

    def drain(self, target, es=None):
        """Emit a drain marker on the target (it travels the same agent pipeline as evidence) and wait for it in ES."""
        self.target(target)
        es = es or elastic_api.es_client()
        generation = self.state["generations"][target]
        token = secrets.token_hex(8)
        line = "OPALEYE_DRAIN_MARKER token=%s target_id=%s rebuild_generation=%d" % (token, target, generation)
        cmd = "printf '%%s\\n' %s | sudo -n tee -a %s >/dev/null" % (shlex.quote(line), shlex.quote(self.drain_cfg["log"]))
        if self.ssh(target, cmd) != 0:
            print("drain marker could not be written on %s (ssh failed)" % target, file=sys.stderr)
            return False
        end = time.time() + float(os.environ.get("LABOPS_DRAIN_TIMEOUT") or self.drain_cfg["timeout_s"])
        query = {"query": {"bool": {"filter": [{"term": {"lab.rebuild_generation": generation}},
                                                {"match_phrase": {"message": "token=" + token}}]}}, "size": 1}
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
        es = self.need_elastic()  # no reset during an Elastic outage, override or not
        drained = self.drain(target, es)
        if not drained and ack is None:
            die("drain check failed; fix forwarding or accept the loss with --acknowledge-loss REASON")
        # Fail closed: a rebuilt VM must not enrol next to a live record of its predecessor.
        self.retire_agent(target)
        generations = dict(self.state["generations"])
        generations[target] += 1
        env = dict(os.environ, TF_VAR_rebuild_generations=json.dumps(generations))
        lab_sh = os.environ.get("LABOPS_LAB_SH", os.path.join(ROOT, "scripts/lab.sh"))
        if subprocess.run([lab_sh, "replace", "targets", self.plan["targets"][target]["tofu_address"]], env=env, cwd=ROOT).returncode != 0:
            self.save("reset-failed", target=target, drained=drained)
            print("rebuild failed: re-run `reset %s` (a failed target is rebuilt, never hand-repaired)" % target, file=sys.stderr)
            return 1
        self.state["generations"] = generations  # the rebuilt VM carries the new generation from here on
        self.save("reset", target=target, drained=drained, acknowledged_loss=ack, agent_retired=True,
                  generation=generations[target])
        ansible = os.environ.get("LABOPS_ANSIBLE", "ansible-playbook")
        if subprocess.run([ansible, "playbooks/targets.yml", "--limit", target, "-e", "rebuild_generation=%d" % generations[target]],
                          cwd=os.path.join(ROOT, "ansible")).returncode != 0:
            print("target rebuilt (generation %d) but provisioning failed: re-run `reset %s`" % (generations[target], target), file=sys.stderr)
            return 1
        print("%s rebuilt: generation %d. Prior events stay searchable by exercise id." % (target, generations[target]))
        return 0

    def retire_agent(self, target):
        """Revoke the old agent (its API key) before the rebuilt VM enrols afresh; refuse the rebuild if that fails."""
        try:
            elastic_api.kibana_client(self.plan).call("/api/fleet/agents/bulk_unenroll", {
                "agents": 'local_metadata.host.name : "opaleye-%s"' % target, "revoke": True})
        except elastic_api.EsError as e:
            die("old agent for %s not retired (%s); nothing was rebuilt. Fix Fleet access and re-run" % (target, e))

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
    gen = sub.add_parser("generation")
    gen.add_argument("target"), gen.add_argument("value", nargs="?", type=int)
    sub.add_parser("drain").add_argument("target")
    reset = sub.add_parser("reset")
    reset.add_argument("target"), reset.add_argument("--acknowledge-loss", metavar="REASON", default=None)
    for name in ("shutdown", "startup"):
        power = sub.add_parser(name)
        power.add_argument("--include-elastic", action="store_true")
        if name == "shutdown":
            power.add_argument("--acknowledge-loss", metavar="REASON", default=None)
    for name in ("attacker-clean", "status"):
        sub.add_parser(name)
    a = ap.parse_args(argv[1:])

    ops = Ops()
    try:
        if a.cmd == "exercise" and a.sub == "start":
            ops.exercise_start(a.id, a.target)
        elif a.cmd == "exercise" and a.sub == "end":
            ops.exercise_end()
        elif a.cmd == "exercise":
            ops.exercise_show(a.id)
        elif a.cmd == "generation":
            ops.generation(a.target, a.value)
        elif a.cmd == "drain":
            return 0 if ops.drain(a.target) else 1
        elif a.cmd == "reset":
            return ops.reset(a.target, a.acknowledge_loss)
        elif a.cmd in ("shutdown", "startup"):
            return ops.power(a.cmd, a.include_elastic, getattr(a, "acknowledge_loss", None))
        elif a.cmd == "attacker-clean":
            return ops.attacker_clean()
        elif a.cmd == "status":
            print(json.dumps(ops.state))
    except (elastic_api.EsError, pve.PveError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
