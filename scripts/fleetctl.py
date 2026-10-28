#!/usr/bin/env python3
"""Fleet and evidence-pipeline control for the target VM (issue #23, M4). Stdlib only.

  upload-packages            verify the staged integration zips against plan.json and upload them to Kibana
  fetch-packages             download the zips on the workstation (Elastic has no Internet; this host does)
  ensure-policy <target>     agent policy and package policies for one target (idempotent)
  issue-token <target> <n>   retire the target's old tokens and agents, print a fresh enrolment token (stdout only)
  ensure-pipeline            create the lab-stamp pipeline if absent (never touches an existing registry)
  register-agent <target> <n>  record the enrolled agent id -> target_id / rebuild_generation in lab-stamp
  ingest-lag                 fail if events were indexed more than ingest_lag_seconds after their @timestamp
  lag-rule                   create/update the Kibana rule that raises the same alert

Kibana (5601) is reached directly; Elasticsearch (9200) only through scripts/elastic-tunnel.sh, because the
firewall gives the operator 5601 and 22 only. Env: FLEET_KIBANA_URL, FLEET_ES_URL, FLEET_CA, FLEET_PACKAGE_DIR,
FLEET_PLAN, ELASTIC_PASSWORD (default: secrets/elastic/elastic.password). The token is printed once and never stored.
"""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import ssl
import sys
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
PIPELINE_FILE = ROOT / "ansible/roles/elastic/files/lab-stamp-pipeline.json"
RULE_ID = "lab-ingest-lag"


def load_plan():
    return json.loads(pathlib.Path(os.environ.get("FLEET_PLAN") or ROOT / "network/plan.json").read_text())


def die(msg, code=2):
    print("fleetctl: " + msg, file=sys.stderr)
    sys.exit(code)


class Client:
    def __init__(self, base):
        self.base = base.rstrip("/")
        pw = os.environ.get("ELASTIC_PASSWORD")
        if not pw:
            f = ROOT / "secrets/elastic/elastic.password"
            if not f.exists():
                die("no ELASTIC_PASSWORD and no %s (run playbooks/elastic.yml first)" % f)
            pw = f.read_text().strip()
        self.auth = "Basic " + base64.b64encode(("elastic:" + pw).encode()).decode()
        self.ctx = None
        if self.base.startswith("https"):
            ca = os.environ.get("FLEET_CA") or str(ROOT / "secrets/elastic/ca/ca.crt")
            self.ctx = ssl.create_default_context(cafile=ca)

    def call(self, method, path, body=None, raw=None, ctype="application/json", ok=(200,)):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={
            "Authorization": self.auth, "Content-Type": ctype, "kbn-xsrf": "fleetctl", "elastic-api-version": "2023-10-31"})
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=60) as r:
                code, text = r.status, r.read()
        except urllib.error.HTTPError as e:
            code, text = e.code, e.read()
        except urllib.error.URLError as e:
            die("cannot reach %s: %s" % (self.base, e.reason))
        try:
            out = json.loads(text) if text else {}
        except ValueError:
            out = {}
        if code not in ok:
            die("%s %s -> http %s %s" % (method, path, code, str(out)[:300]))
        return code, out


def kibana():
    return Client(os.environ.get("FLEET_KIBANA_URL") or "https://%s:5601" % load_plan()["hosts"]["elastic"]["ip"])


def elastic():
    return Client(os.environ.get("FLEET_ES_URL") or "https://127.0.0.1:19200")


def policy_id(plan, target):
    if target not in plan["targets"] or "vm_id" not in plan["targets"][target]:
        die("unknown target %r (no VM in plan.json targets)" % target)
    return plan["target_stack"]["agent_policy_prefix"] + target


def generation(text):
    try:
        n = int(text)
    except ValueError:
        n = 0
    if n < 1:
        die("generation must be a positive integer, got %r" % text)
    return n


# ---- packages -----------------------------------------------------------------------------------------------------

def package_dir():
    return pathlib.Path(os.environ.get("FLEET_PACKAGE_DIR") or ROOT / "secrets/elastic/packages")


def cmd_fetch(_args):
    d = package_dir()
    d.mkdir(parents=True, exist_ok=True)
    for name, p in load_plan()["target_stack"]["integrations"].items():
        f = d / p["file"]
        if not f.exists():
            urllib.request.urlretrieve(p["url"], f)  # pinned https URL from plan.json; checked below
        if hashlib.sha256(f.read_bytes()).hexdigest() != p["sha256"]:
            f.unlink()
            die("%s: sha256 does not match the pin in plan.json; file removed" % name)
        print("ok " + name)


def cmd_upload(_args):
    integrations = load_plan()["target_stack"]["integrations"]
    d = package_dir()
    for name, p in integrations.items():  # verify everything before sending anything
        f = d / p["file"]
        if not f.exists():
            die("missing %s (run fetch-packages)" % f)
        if hashlib.sha256(f.read_bytes()).hexdigest() != p["sha256"]:
            die("%s: sha256 does not match the pin in plan.json" % f)
    kb = kibana()
    for name, p in integrations.items():
        code, _ = kb.call("GET", "/api/fleet/epm/packages/%s/%s" % (name, p["version"]), ok=(200, 404))
        if code == 200:
            print("installed already: %s %s" % (name, p["version"]))
            continue
        kb.call("POST", "/api/fleet/epm/packages?ignoreMappingUpdateErrors=false", raw=(d / p["file"]).read_bytes(),
                ctype="application/zip")
        print("uploaded: %s %s" % (name, p["version"]))


# ---- policies -----------------------------------------------------------------------------------------------------
# Input keys and var names below follow the package manifests; they are unverified on 9.5.5 until A4 and are fixed
# by editing this file and re-running, never by hand in Kibana.

AUDIT_RULES = "\n".join([
    "-a always,exit -F arch=b64 -S execve,execveat -k lab_exec",
    "-a always,exit -F arch=b64 -S connect -k lab_connect",
])
# Filestream waits for 1,024 bytes before it fingerprints a file; tiny exercise logs would look missing.
FINGERPRINT = "prospector.scanner.fingerprint.offset: 0\nprospector.scanner.fingerprint.length: 64\n"


def package_policy(target, pkg, plan, version=None):
    version = version or plan["target_stack"]["integrations"].get(pkg, {}).get("version")
    base = {"name": "%s-%s" % (target, pkg), "namespace": "default", "policy_id": policy_id(plan, target),
            "package": {"name": pkg, "version": version}}
    if pkg == "endpoint":
        # DataCollection = events only, no protections: the exercise must be able to run and be observed.
        base["inputs"] = [{"type": "endpoint", "enabled": True, "streams": [], "config": {"integration_config": {
            "value": {"type": "endpoint", "endpointConfig": {"preset": "DataCollection"}}}}}]
    elif pkg == "auditd_manager":
        base["inputs"] = {"auditd-auditd": {"enabled": True, "streams": {"auditd_manager.auditd": {
            "enabled": True, "vars": {"audit_rules": AUDIT_RULES, "resolve_ids": True, "failure_mode": "log"}}}}}
    elif pkg == "docker":
        base["inputs"] = {
            "docker-filestream": {"enabled": True, "streams": {"docker.container_logs": {
                "enabled": True, "vars": {"containers.ids": ["*"]}}}},
            "docker-docker/metrics": {"enabled": False},
        }
    elif pkg == "apache":
        base["inputs"] = {
            "apache-filestream": {"enabled": True, "streams": {
                "apache.access": {"enabled": True, "vars": {"paths": [plan["target_stack"]["apache_log_dir"] + "/access.log*"], "custom": FINGERPRINT}},
                "apache.error": {"enabled": True, "vars": {"paths": [plan["target_stack"]["apache_log_dir"] + "/error.log*"], "custom": FINGERPRINT}}}},
            "apache-apache/metrics": {"enabled": False},
        }
    elif pkg != "system":
        die("no policy definition for package %r" % pkg)
    return base


def cmd_policy(args):
    plan = load_plan()
    pid = policy_id(plan, args.target)
    kb = kibana()
    code, _ = kb.call("GET", "/api/fleet/agent_policies/" + pid, ok=(200, 404))
    if code == 404:
        kb.call("POST", "/api/fleet/agent_policies?sys_monitoring=false", {
            "id": pid, "name": pid, "namespace": "default", "monitoring_enabled": ["logs", "metrics"],
            "description": "Opaleye %s evidence sources; managed by scripts/fleetctl.py" % args.target})
        print("created policy " + pid)
    _, existing = kb.call("GET", "/api/fleet/package_policies?perPage=500")
    have = {p["name"] for p in existing.get("items", []) if p.get("policy_id") == pid}
    for pkg in plan["target_stack"]["bundled_integrations"] + list(plan["target_stack"]["integrations"]):
        name = "%s-%s" % (args.target, pkg)
        if name in have:
            continue
        code, info = kb.call("GET", "/api/fleet/epm/packages/" + pkg, ok=(200, 404))
        if code == 404 or info.get("item", {}).get("status") != "installed":
            die("package %s is not installed in Kibana (run upload-packages; Elastic has no Internet)" % pkg)
        kb.call("POST", "/api/fleet/package_policies", package_policy(args.target, pkg, plan, info["item"]["version"]))
        print("added " + name)


# ---- enrolment ----------------------------------------------------------------------------------------------------

def policy_agents(kb, pid):
    _, out = kb.call("GET", "/api/fleet/agents?perPage=500&showInactive=false")
    return [a for a in out.get("items", []) if a.get("policy_id") == pid]


def cmd_token(args):
    plan = load_plan()
    pid, gen = policy_id(plan, args.target), generation(args.generation)
    kb = kibana()
    _, keys = kb.call("GET", "/api/fleet/enrollment_api_keys?perPage=500")
    for k in keys.get("items", []):
        if k.get("policy_id") == pid:
            kb.call("DELETE", "/api/fleet/enrollment_api_keys/" + k["id"])
    for a in policy_agents(kb, pid):
        kb.call("POST", "/api/fleet/agents/%s/unenroll" % a["id"], {"revoke": True, "force": True})
    _, made = kb.call("POST", "/api/fleet/enrollment_api_keys", {"policy_id": pid, "name": "%s-gen%d" % (args.target, gen)})
    print(made["item"]["api_key"])


def load_pipeline():
    return json.loads(PIPELINE_FILE.read_text())


def cmd_ensure_pipeline(_args):
    name = load_plan()["target_stack"]["stamp_pipeline"]
    es = elastic()
    code, _ = es.call("GET", "/_ingest/pipeline/" + name, ok=(200, 404))
    if code == 404:
        es.call("PUT", "/_ingest/pipeline/" + name, load_pipeline())
        print("created pipeline " + name)


def cmd_register(args):
    plan = load_plan()
    pid, gen = policy_id(plan, args.target), generation(args.generation)
    host = "opaleye-" + args.target
    kb, es = kibana(), elastic()
    deadline = time.time() + args.wait
    while True:
        found = [a for a in policy_agents(kb, pid) if a.get("local_metadata", {}).get("host", {}).get("name") == host]
        if found or time.time() >= deadline:
            break
        time.sleep(5)
    if not found:
        die("no enrolled agent for %s on policy %s" % (host, pid), 1)
    name = plan["target_stack"]["stamp_pipeline"]
    _, cur = es.call("GET", "/_ingest/pipeline/" + name)
    body = cur[name]
    agents = body["processors"][0]["script"]["params"]["agents"]
    for a in found:
        agents[a["id"]] = {"target_id": args.target, "rebuild_generation": gen}
    es.call("PUT", "/_ingest/pipeline/" + name, body)
    print("registered %s as %s gen %d" % (", ".join(a["id"] for a in found), args.target, gen))


# ---- ingest lag ---------------------------------------------------------------------------------------------------

LAG_SCRIPT = ("doc['event.ingested'].size() > 0 && doc['@timestamp'].size() > 0 && "
              "doc['event.ingested'].value.toInstant().toEpochMilli() - doc['@timestamp'].value.toInstant().toEpochMilli() > params.ms")


def cmd_lag(args):
    limit = load_plan()["target_stack"]["ingest_lag_seconds"]
    body = {"size": 3, "_source": ["data_stream.dataset", "lab.target_id", "@timestamp", "event.ingested"],
            "query": {"bool": {"filter": [
                {"range": {"event.ingested": {"gte": "now-%dm" % args.window}}},
                {"script": {"script": {"lang": "painless", "source": LAG_SCRIPT, "params": {"ms": limit * 1000}}}}]}}}
    _, out = elastic().call("POST", "/logs-*,metrics-*/_search?ignore_unavailable=true&allow_no_indices=true", body)
    n = out["hits"]["total"]["value"]
    print("lagging events in the last %d min (> %d s): %d" % (args.window, limit, n))
    for h in out["hits"]["hits"]:
        s = h["_source"]
        print("  %s target=%s" % (s.get("data_stream", {}).get("dataset"), s.get("lab", {}).get("target_id")))
    sys.exit(1 if n else 0)


def cmd_rule(_args):
    limit = load_plan()["target_stack"]["ingest_lag_seconds"]
    esql = ('FROM logs-*,metrics-* | WHERE event.ingested IS NOT NULL | '
            'EVAL lag_s = DATE_DIFF("seconds", @timestamp, event.ingested) | WHERE lag_s > %d | '
            'KEEP @timestamp, event.ingested, lag_s, data_stream.dataset, lab.target_id | LIMIT 100' % limit)
    rule = {"name": "Opaleye ingest lag > %ds" % limit, "tags": ["opaleye"], "schedule": {"interval": "1m"}, "actions": [],
            "params": {"searchType": "esqlQuery", "esqlQuery": {"esql": esql}, "timeField": "event.ingested", "size": 100,
                       "threshold": [0], "thresholdComparator": ">", "timeWindowSize": 5, "timeWindowUnit": "m",
                       "excludeHitsFromPreviousRun": True}}
    kb = kibana()
    code, _ = kb.call("GET", "/api/alerting/rule/" + RULE_ID, ok=(200, 404))
    if code == 404:  # rule_type_id and consumer cannot change after creation
        kb.call("POST", "/api/alerting/rule/" + RULE_ID, dict(rule, rule_type_id=".es-query", consumer="stackAlerts"))
        print("created rule " + RULE_ID)
    else:
        kb.call("PUT", "/api/alerting/rule/" + RULE_ID, rule)
        print("updated rule " + RULE_ID)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("fetch-packages").set_defaults(fn=cmd_fetch)
    sub.add_parser("upload-packages").set_defaults(fn=cmd_upload)
    p = sub.add_parser("ensure-policy")
    p.add_argument("target")
    p.set_defaults(fn=cmd_policy)
    p = sub.add_parser("issue-token")
    p.add_argument("target")
    p.add_argument("generation")
    p.set_defaults(fn=cmd_token)
    sub.add_parser("ensure-pipeline").set_defaults(fn=cmd_ensure_pipeline)
    p = sub.add_parser("register-agent")
    p.add_argument("target")
    p.add_argument("generation")
    p.add_argument("--wait", type=int, default=180, help="seconds to wait for the agent to appear in Fleet")
    p.set_defaults(fn=cmd_register)
    p = sub.add_parser("ingest-lag")
    p.add_argument("--window", type=int, default=15, help="minutes of recent indexing to inspect")
    p.set_defaults(fn=cmd_lag)
    sub.add_parser("lag-rule").set_defaults(fn=cmd_rule)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
