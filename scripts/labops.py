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
  labops.py shutdown [--include-elastic]   graceful power-off of lab guests; nothing is destroyed
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
import pve  # noqa: E402

ROOT = elastic_api.ROOT
EXERCISE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
EXERCISE_DIR = "/srv/exercise"  # attacker-side working directory (ansible/roles/attacker)


def die(msg):
    raise SystemExit("refused: " + msg)


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class Ops:
    def __init__(self):
        with open(os.environ.get("LAB_PLAN", os.path.join(ROOT, "network/plan.json"))) as f:
            self.plan = json.load(f)
        self.dir = os.environ.get("LABMODE_STATE_DIR", ".state")
        os.makedirs(self.dir, exist_ok=True)
        self.path, self.log = os.path.join(self.dir, "labops.json"), os.path.join(self.dir, "labops.log")
        try:
            with open(self.path) as f:
                self.st = json.load(f)
        except FileNotFoundError:
            self.st = {"active": None, "generations": {t: 1 for t in self.plan["targets"]}}
        self.drain_cfg = self.plan["ops"]["drain"]
        self.poll = float(os.environ.get("LABOPS_POLL") or self.drain_cfg["poll_s"])

    # --- state -------------------------------------------------------------------------------
    def save(self, event, **detail):
        with open(self.path, "w") as f:
            json.dump(self.st, f)
        with open(self.log, "a") as f:
            f.write(json.dumps(dict(ts=stamp(), event=event, user=getpass.getuser(), **detail)) + "\n")

    def target(self, name):
        if name not in self.plan["targets"]:
            die("%r is not a target (%s); only targets can be reset or drained" % (name, ", ".join(self.plan["targets"])))
        return name

    def ip(self, host):
        return self.plan["hosts"][host]["ip"]

    def need_elastic(self):
        es = elastic_api.es_client()
        try:
            es.call("/_cluster/health")
        except elastic_api.EsError as e:
            die("Elastic is not answering (%s); is the tunnel up (scripts/elastic-tunnel.sh)? No exercise start or reset during an outage" % e)
        return es

    def run(self, argv, **kw):
        return subprocess.run(argv, **kw).returncode

    def ssh(self, host, command):
        argv = shlex.split(os.environ.get("LABOPS_SSH", "ssh")) + [
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
            "%s@%s" % (self.plan["ops"]["ssh_user"], self.ip(host)), command]
        return self.run(argv)

    # --- exercise markers --------------------------------------------------------------------
    def marker(self, es, action, ex, target, generation):
        es.call("/%s/_doc" % self.plan["ops"]["marker_stream"], {
            "@timestamp": stamp(), "message": "%s %s %s" % (action, ex, target),
            "event": {"action": action, "dataset": "lab_marker.events", "kind": "event"},
            "lab": {"exercise_id": ex, "target_id": target, "rebuild_generation": generation}})

    def exercise_start(self, ex, target):
        if not EXERCISE_ID.match(ex):
            die("exercise id must match %s" % EXERCISE_ID.pattern)
        self.target(target)
        if self.st["active"]:
            die("exercise %s is still active (one at a time): run `exercise end`" % self.st["active"]["id"])
        try:
            with open(os.path.join(self.dir, "labmode.json")) as f:
                lm = json.load(f)
        except FileNotFoundError:
            lm = {}
        if lm.get("mode") != "exercise" or lm.get("selected") != target:
            die("firewall is not in exercise mode with %s selected: run scripts/labmode.py select %s" % (target, target))
        es = self.need_elastic()
        limit = self.plan["ops"]["high_watermark_pct"]
        worst = max(float(r["disk.percent"]) for r in es.call("/_cat/allocation?format=json"))
        if worst >= limit:
            die("Elasticsearch disk at %g%% (high watermark %d%%): new exercises are blocked; free space via evidence deletion" % (worst, limit))
        gen = self.st["generations"][target]
        self.marker(es, "exercise-start", ex, target, gen)
        self.st["active"] = {"id": ex, "target": target, "generation": gen, "started": stamp()}
        self.save("exercise-start", exercise_id=ex, target=target)
        print("exercise %s started on %s (generation %d). On the attacker VM: exercise1 --exercise-id %s" % (ex, target, gen, ex))

    def exercise_end(self):
        act = self.st["active"]
        if not act:
            die("no active exercise")
        self.marker(self.need_elastic(), "exercise-end", act["id"], act["target"], act["generation"])
        self.st["active"] = None
        self.save("exercise-end", exercise_id=act["id"], target=act["target"])
        print("exercise %s ended. Next: drain %s, then reset %s" % (act["id"], act["target"], act["target"]))

    def exercise_show(self, ex):
        res = elastic_api.es_client().call("/%s/_search" % self.plan["ops"]["marker_stream"], {
            "query": {"bool": {"filter": [{"term": {"lab.exercise_id": ex}}]}}, "size": 10})
        docs = [h["_source"] for h in res["hits"]["hits"]]
        if not docs:
            die("no markers for exercise %s" % ex)
        for d in docs:
            print("%s  %s  target=%s generation=%s" % (d["@timestamp"], d["event"]["action"], d["lab"]["target_id"],
                                                       d["lab"]["rebuild_generation"]))
        if not any(d["event"]["action"] == "exercise-end" for d in docs):
            print("(no end marker: exercise still running or never ended)")

    def generation(self, target, value):
        self.target(target)
        if value is not None:
            self.st["generations"][target] = value
            self.save("generation", target=target, generation=value)
        print(self.st["generations"][target])

    # --- drain ---------------------------------------------------------------------------------
    def drain(self, target, es=None):
        """Emit a drain marker on the target (it travels the same agent pipeline as evidence) and wait for it in ES."""
        self.target(target)
        es = es or elastic_api.es_client()
        gen = self.st["generations"][target]
        token = secrets.token_hex(8)
        line = "OPALEYE_DRAIN_MARKER token=%s target_id=%s rebuild_generation=%d" % (token, target, gen)
        cmd = "printf '%%s\\n' %s | sudo -n tee -a %s >/dev/null" % (shlex.quote(line), shlex.quote(self.drain_cfg["log"]))
        if self.ssh(target, cmd) != 0:
            print("drain marker could not be written on %s (ssh failed)" % target, file=sys.stderr)
            return False
        end = time.time() + float(os.environ.get("LABOPS_DRAIN_TIMEOUT") or self.drain_cfg["timeout_s"])
        query = {"query": {"bool": {"filter": [{"term": {"lab.rebuild_generation": gen}},
                                                {"match_phrase": {"message": "token=" + token}}]}}, "size": 1}
        while True:
            try:
                if es.call("/logs-*/_search", query)["hits"]["hits"]:
                    print("drained: marker %s for %s generation %d arrived in Elasticsearch" % (token, target, gen))
                    return True
            except elastic_api.EsError:
                pass
            if time.time() >= end:
                print("not drained: marker %s (generation %d) did not arrive from %s in time" % (token, gen, target), file=sys.stderr)
                return False
            time.sleep(self.poll)

    # --- reset -----------------------------------------------------------------------------------
    def reset(self, target, ack):
        self.target(target)
        act = self.st["active"]
        if act and act["target"] == target:
            die("exercise %s is active on %s: run `exercise end` first" % (act["id"], target))
        es = self.need_elastic()  # no reset during an Elastic outage, override or not
        drained = self.drain(target, es)
        if not drained and not ack:
            die("drain check failed; fix forwarding or accept the loss with --acknowledge-loss REASON")
        retired = self.retire_agent(target)
        gens = dict(self.st["generations"])
        gens[target] += 1
        env = dict(os.environ, TF_VAR_rebuild_generations=json.dumps(gens))
        lab_sh = os.environ.get("LABOPS_LAB_SH", os.path.join(ROOT, "scripts/lab.sh"))
        if self.run([lab_sh, "replace", "targets", self.plan["targets"][target]["tofu_address"]], env=env, cwd=ROOT) != 0:
            self.save("reset-failed", target=target, drained=drained)
            print("rebuild failed: re-run `reset %s` (a failed target is rebuilt, never hand-repaired)" % target, file=sys.stderr)
            return 1
        self.st["generations"] = gens  # the rebuilt VM carries the new generation from here on
        self.save("reset", target=target, drained=drained, acknowledged_loss=ack, agent_retired=retired,
                  generation=gens[target])
        ansible = os.environ.get("LABOPS_ANSIBLE", "ansible-playbook")
        if self.run([ansible, "playbooks/targets.yml", "--limit", target, "-e", "rebuild_generation=%d" % gens[target]],
                    cwd=os.path.join(ROOT, "ansible")) != 0:
            print("target rebuilt (generation %d) but provisioning failed: re-run `reset %s`" % (gens[target], target), file=sys.stderr)
            return 1
        print("%s rebuilt: generation %d. Prior events stay searchable by exercise id." % (target, gens[target]))
        return 0

    def retire_agent(self, target):
        """Revoke the old agent record (and with it its enrolment) before the rebuilt VM enrols afresh."""
        try:
            elastic_api.kibana_client(self.plan).call("/api/fleet/agents/bulk_unenroll", {
                "agents": 'local_metadata.host.name : "opaleye-%s"' % target, "revoke": True})
            return True
        except elastic_api.EsError as e:
            print("WARNING: old agent for %s not retired (%s); retire it in Fleet before enrolment" % (target, e), file=sys.stderr)
            return False

    def attacker_clean(self):
        cmd = "find %s -mindepth 1 -delete" % shlex.quote(EXERCISE_DIR)
        if self.ssh("attacker", cmd) != 0:
            return 1
        self.save("attacker-clean")
        print("attacker %s cleared" % EXERCISE_DIR)
        return 0

    # --- shutdown / startup ------------------------------------------------------------------------
    def guests(self, include_elastic):
        """(label, stack, vmid) in shutdown order: attacker, targets, [elastic], firewall."""
        g = [("attacker", "attacker", self.plan["attacker"]["vm_id"])]
        g += [(t, "targets", v["vm_id"]) for t, v in self.plan["targets"].items()]
        if include_elastic:
            g.append(("elastic", "elastic", self.plan["elastic"]["vm_id"]))
        g.append(("firewall", "firewall", self.plan["firewall"]["vm_id"]))
        return g

    def power(self, action, include_elastic):
        if self.st["active"]:
            die("exercise %s is active: run `exercise end` first" % self.st["active"]["id"])
        endpoint, node = os.environ.get("PROXMOX_VE_ENDPOINT"), os.environ.get("PVE_NODE")
        if not (endpoint and node):
            raise SystemExit("set PROXMOX_VE_ENDPOINT and PVE_NODE")
        order = self.guests(include_elastic)
        if action == "start":
            order = order[::-1]  # firewall first, then Elastic, targets, attacker
        wait = float(os.environ.get("LABOPS_SHUTDOWN_WAIT") or 120)
        failed, clients = [], {}
        for label, stack, vmid in order:
            var = "PROXMOX_VE_API_TOKEN_" + stack.upper()
            if not os.environ.get(var):
                raise SystemExit("set " + var)
            c = clients.setdefault(stack, pve.Client(endpoint, node, os.environ[var], os.environ.get("PROXMOX_VE_INSECURE") == "true"))
            want = "stopped" if action == "shutdown" else "running"
            if c.status(vmid) == want:
                print("%s (%d): already %s" % (label, vmid, want))
                continue
            c.shutdown(vmid, int(wait)) if action == "shutdown" else c.start(vmid)
            ok = c.wait(vmid, want, wait, min(self.poll, 2))
            print("%s (%d): %s" % (label, vmid, want if ok else "NOT %s" % want))
            if not ok:
                failed.append(vmid)
        self.save(action, include_elastic=include_elastic, failed=failed)
        if not include_elastic:
            print("Elastic left running (use --include-elastic to %s it; graceful only, nothing is destroyed)" % ("power it off" if action == "shutdown" else "start it"))
        if failed:
            print("not %s: %s (nothing was forced; retry or use the Proxmox console)" % ("stopped" if action == "shutdown" else "started", ", ".join(map(str, failed))), file=sys.stderr)
            return 1
        return 0


def main(argv):
    ap = argparse.ArgumentParser(prog="labops.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ex = sub.add_parser("exercise").add_subparsers(dest="sub", required=True)
    s = ex.add_parser("start")
    s.add_argument("id"), s.add_argument("--target", required=True)
    ex.add_parser("end")
    ex.add_parser("show").add_argument("id")
    g = sub.add_parser("generation")
    g.add_argument("target"), g.add_argument("value", nargs="?", type=int)
    sub.add_parser("drain").add_argument("target")
    r = sub.add_parser("reset")
    r.add_argument("target"), r.add_argument("--acknowledge-loss", metavar="REASON", default=None)
    for c in ("shutdown", "startup"):
        sub.add_parser(c).add_argument("--include-elastic", action="store_true")
    for c in ("attacker-clean", "status"):
        sub.add_parser(c)
    a = ap.parse_args(argv[1:])

    ops = Ops()
    try:
        if a.cmd == "exercise":
            {"start": lambda: ops.exercise_start(a.id, a.target), "end": ops.exercise_end,
             "show": lambda: ops.exercise_show(a.id)}[a.sub]()
        elif a.cmd == "generation":
            ops.generation(a.target, a.value)
        elif a.cmd == "drain":
            return 0 if ops.drain(a.target) else 1
        elif a.cmd == "reset":
            if a.acknowledge_loss is not None and not a.acknowledge_loss.strip():
                die("--acknowledge-loss needs a reason")
            return ops.reset(a.target, a.acknowledge_loss)
        elif a.cmd in ("shutdown", "startup"):
            return ops.power("shutdown" if a.cmd == "shutdown" else "start", a.include_elastic)
        elif a.cmd == "attacker-clean":
            return ops.attacker_clean()
        elif a.cmd == "status":
            print(json.dumps(ops.st))
    except (elastic_api.EsError, pve.PveError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
