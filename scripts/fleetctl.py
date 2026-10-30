#!/usr/bin/env python3
"""Fleet and evidence-pipeline control for the target VM (issue #23, M4). Stdlib only.

  upload-packages            verify the staged integration zips against plan.json and upload them to Kibana
  fetch-packages             download the zips on the workstation (Elastic has no Internet; this host does)
  ensure-policy <target>     agent policy and package policies for one target (idempotent); for flare/remnux (#52) the
                             `analysis` namespace policy: Windows + Sysmon / auditd + system, tagged lab.zone=analysis
  issue-token <target> <n>   retire the target's old tokens and agents, print a fresh enrolment token (stdout only);
                             also for the analysis hosts flare and remnux
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
import datetime as dt
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


def analysis_hosts(plan):
    return plan.get("analysis", {}).get("hosts", {})


def policy_id(plan, target):
    if target in analysis_hosts(plan):
        return plan["analysis"]["agent_policy_prefix"] + target
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
        code, info = kb.call("GET", "/api/fleet/epm/packages/%s/%s" % (name, p["version"]), ok=(200, 404))
        if code == 200 and info.get("item", {}).get("status") == "installed":
            print("installed already: %s %s" % (name, p["version"]), flush=True)
            continue
        if name == "endpoint":
            # Kibana bundles Defend's special assets; direct ZIP uploads reject them.
            kb.call("POST", "/api/fleet/epm/packages/endpoint/" + p["version"], {})
        else:
            for attempt in range(4):
                code, out = kb.call("POST", "/api/fleet/epm/packages?ignoreMappingUpdateErrors=false",
                                    raw=(d / p["file"]).read_bytes(), ctype="application/zip", ok=(200, 429))
                if code != 429:
                    break
                if attempt == 3:
                    die("package upload rate limit persisted after retries: " + name)
                print("upload rate limited; retrying in 12 seconds: " + name, flush=True)
                time.sleep(12)
        print("uploaded: %s %s" % (name, p["version"]), flush=True)


# ---- policies -----------------------------------------------------------------------------------------------------
# Input keys and var names below follow the package manifests; they are unverified on 9.5.5 until A4 and are fixed
# by editing this file and re-running, never by hand in Kibana.

AUDIT_RULES = "\n".join([
    "-a always,exit -F arch=b64 -S execve,execveat -k lab_exec",
    "-a always,exit -F arch=b64 -S connect -k lab_connect",
])
# Filestream waits for 1,024 bytes before it fingerprints a file; tiny exercise logs would look missing.
FINGERPRINT = "prospector.scanner.fingerprint.offset: 0\nprospector.scanner.fingerprint.length: 64\n"
CREATED_PROCESSOR = """- script:
    lang: javascript
    id: lab_event_created
    source: >
      function process(event) {
        if (event.Get('event.created') === null) {
          event.Put('event.created', new Date().toISOString());
        }
      }
"""


def package_policy(target, pkg, plan, version=None, log_kind="access"):
    version = version or plan["target_stack"]["integrations"].get(pkg, {}).get("version")
    base = {"name": "%s-%s" % (target, pkg), "namespace": "default", "policy_id": policy_id(plan, target),
            "package": {"name": pkg, "version": version}}
    if pkg == "endpoint":
        # DataCollection = events only, no protections: the exercise must be able to run and be observed.
        base["inputs"] = [{"type": "endpoint", "enabled": True, "streams": [], "config": {"integration_config": {
            "value": {"type": "endpoint", "endpointConfig": {"preset": "DataCollection"}}}}}]
    elif pkg == "system":
        base["inputs"] = {"system-system/metrics": {"enabled": True, "streams": {
            dataset: {"enabled": True} for dataset in ["system.cpu", "system.memory", "system.network", "system.filesystem"]}}}
    elif pkg == "auditd_manager":
        base["inputs"] = {"auditd-audit/auditd": {"enabled": True, "streams": {"auditd_manager.auditd": {
            "enabled": True, "vars": {"audit_rules": AUDIT_RULES, "socket_type": "unicast", "resolve_ids": True, "failure_mode": "log", "processors": CREATED_PROCESSOR}}}}}
    elif pkg == "docker":
        base["inputs"] = {
            "docker-filestream": {"enabled": True, "streams": {"docker.container_logs": {
                "enabled": True, "vars": {"paths": ["/var/lib/docker/containers/${docker.container.id}/*-json.log"], "custom": FINGERPRINT, "processors": CREATED_PROCESSOR}}}},
            "docker-docker/metrics": {"enabled": False},
        }
    elif pkg == "apache":
        base["inputs"] = {"apache-logfile": {"enabled": False}, "apache-apache/metrics": {"enabled": False}}
    elif pkg == "filestream":
        paths = [plan["target_stack"]["apache_log_dir"] + "/" + log_kind + ".log*"]
        if log_kind == "access":
            paths.append(plan["ops"]["drain"]["log"])
        else:
            base["name"] += "-" + log_kind
        apache_version = plan["target_stack"]["integrations"]["apache"]["version"]
        base["create_dataset_templates"] = False  # Apache owns the parsed dataset templates.
        values = {"paths": paths, "data_stream.dataset": "apache." + log_kind,
                  "pipeline": "logs-apache." + log_kind + "-" + apache_version,
                  "fingerprint": True, "fingerprint_length": 64, "processors": CREATED_PROCESSOR}
        base["inputs"] = {"filestream-filestream": {"enabled": True,
            "streams": {"filestream.filestream": {"enabled": True, "vars": values}}}}
    else:
        die("no policy definition for package %r" % pkg)
    return base


# Best effort by design (#52): a sample can tamper with the agent. Every event carries the zone; lab.sample_id is stamped later.
ANALYSIS_PROCESSOR = "- add_fields:\n    target: lab\n    fields:\n      zone: analysis\n"
# Sysmon operational, Security and PowerShell channels on FLARE; no Elastic Defend (it conflicts with the tools and may kill samples).
def drain_input(log):
    """The drain log is shipped like the target's, so a drain marker proves forwarding works (labops.py analysis-reset)."""
    return ("filestream", {"filestream-filestream": {"enabled": True, "streams": {"filestream.filestream": {"enabled": True, "vars": {
        "paths": [log], "data_stream.dataset": "lab_drain.marker", "fingerprint": True, "fingerprint_length": 64,
        "processors": ANALYSIS_PROCESSOR}}}}})


ANALYSIS_INPUTS = {
    "flare": [("windows", {"windows-winlog": {"enabled": True, "streams": {
                  "windows.sysmon_operational": {"enabled": True, "vars": {"processors": ANALYSIS_PROCESSOR}},
                  "windows.powershell_operational": {"enabled": True, "vars": {"processors": ANALYSIS_PROCESSOR}}}}}),
              ("system", {"system-winlog": {"enabled": True, "streams": {
                  "system.security": {"enabled": True, "vars": {"processors": ANALYSIS_PROCESSOR}}}}})],
    "remnux": [("auditd_manager", {"auditd-audit/auditd": {"enabled": True, "streams": {"auditd_manager.auditd": {
                  "enabled": True, "vars": {"audit_rules": AUDIT_RULES, "socket_type": "unicast", "resolve_ids": True,
                                            "failure_mode": "log", "processors": ANALYSIS_PROCESSOR}}}}}),
               ("system", {"system-logfile": {"enabled": True, "streams": {
                  "system.syslog": {"enabled": True, "vars": {"processors": ANALYSIS_PROCESSOR}},
                  "system.auth": {"enabled": True, "vars": {"processors": ANALYSIS_PROCESSOR}}}}})],
}


def analysis_inputs(plan, host):
    log = plan["analysis"]["drain"]["log_windows" if plan["analysis"]["hosts"][host]["os"] == "windows" else "log_linux"]
    return ANALYSIS_INPUTS[host] + [drain_input(log)]


def cmd_analysis_policy(args, plan):
    pid, host = policy_id(plan, args.target), args.target
    kb = kibana()
    code, _ = kb.call("GET", "/api/fleet/agent_policies/" + pid, ok=(200, 404))
    if code == 404:
        kb.call("POST", "/api/fleet/agent_policies?sys_monitoring=false", {
            "id": pid, "name": pid, "namespace": plan["analysis"]["namespace"], "monitoring_enabled": ["logs", "metrics"],
            "description": "Opaleye analysis zone %s; managed by scripts/fleetctl.py" % host})
        print("created policy " + pid)
    _, existing = kb.call("GET", "/api/fleet/package_policies?perPage=500")
    have = {p["name"]: p for p in existing.get("items", []) if p.get("policy_id") == pid}
    for pkg, inputs in analysis_inputs(plan, host):
        name = "%s-%s" % (host, pkg)
        code, info = kb.call("GET", "/api/fleet/epm/packages/" + pkg, ok=(200, 404))
        if code == 404 or info.get("item", {}).get("status") != "installed":
            die("package %s is not installed in Kibana (run upload-packages or install it from the registry mirror)" % pkg)
        body = {"name": name, "namespace": plan["analysis"]["namespace"], "policy_id": pid,
                "package": {"name": pkg, "version": info["item"]["version"]}, "inputs": inputs}
        digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        body["description"] = "Managed by scripts/fleetctl.py; config-sha256=" + digest
        if name in have:
            if have[name].get("description") != body["description"]:
                kb.call("PUT", "/api/fleet/package_policies/" + have[name]["id"], body)
                print("updated " + name)
        else:
            kb.call("POST", "/api/fleet/package_policies", body)
            print("added " + name)


def cmd_policy(args):
    plan = load_plan()
    if args.target in analysis_hosts(plan):
        return cmd_analysis_policy(args, plan)
    pid = policy_id(plan, args.target)
    kb = kibana()
    code, _ = kb.call("GET", "/api/fleet/agent_policies/" + pid, ok=(200, 404))
    if code == 404:
        kb.call("POST", "/api/fleet/agent_policies?sys_monitoring=false", {
            "id": pid, "name": pid, "namespace": "default", "monitoring_enabled": ["logs", "metrics"],
            "description": "Opaleye %s evidence sources; managed by scripts/fleetctl.py" % args.target})
        print("created policy " + pid)
    _, existing = kb.call("GET", "/api/fleet/package_policies?perPage=500")
    have = {p["name"]: p for p in existing.get("items", []) if p.get("policy_id") == pid}
    packages = plan["target_stack"]["bundled_integrations"] + list(plan["target_stack"]["integrations"])
    specs = [(pkg, "access") for pkg in packages] + [("filestream", "error")]
    for pkg, log_kind in specs:
        name = "%s-%s" % (args.target, pkg) + ("-error" if log_kind == "error" else "")
        version = plan["target_stack"]["integrations"].get(pkg, {}).get("version")
        package_path = pkg + ("/" + version if version else "")
        code, info = kb.call("GET", "/api/fleet/epm/packages/" + package_path, ok=(200, 404))
        if code == 404 or info.get("item", {}).get("status") != "installed":
            die("package %s is not installed in Kibana (run upload-packages; Elastic has no Internet)" % pkg)
        body = package_policy(args.target, pkg, plan, info["item"]["version"], log_kind)
        digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        body["description"] = "Managed by scripts/fleetctl.py; config-sha256=" + digest
        if pkg == "endpoint":
            body["description"] += "; session-data=enabled"
        if name in have:
            if have[name].get("description") == body["description"]:
                continue
            if pkg == "endpoint":
                # Defend requires its generated policy and artifact manifest on update.
                body["inputs"][0]["config"].update(have[name]["inputs"][0].get("config", {}))
                body["inputs"][0]["config"]["policy"]["value"]["linux"]["events"]["session_data"] = True
            kb.call("PUT", "/api/fleet/package_policies/" + have[name]["id"], body)
            print("updated " + name)
        else:
            _, created = kb.call("POST", "/api/fleet/package_policies", body)
            if pkg == "endpoint":
                body["inputs"][0]["config"].update(created["item"]["inputs"][0].get("config", {}))
                policy = body["inputs"][0]["config"].get("policy", {}).get("value")
                if policy is not None:
                    policy["linux"]["events"]["session_data"] = True
                    kb.call("PUT", "/api/fleet/package_policies/" + created["item"]["id"], body)
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
    # Elasticsearch 9 returns system-managed creation/modification dates that PUT rejects.
    body = {k: v for k, v in cur[name].items()
            if k in ("description", "processors", "on_failure", "version", "_meta", "deprecated")}
    agents = body["processors"][0]["script"]["params"]["agents"]
    for a in found:
        agents[a["id"]] = {"target_id": args.target, "rebuild_generation": gen}
    params = body["processors"][0]["script"]["params"]
    config = params.setdefault("firewall_targets", {}).setdefault(args.target, {
        "ip": plan["hosts"][args.target]["ip"], "generations": []})
    if not any(g["generation"] == gen for g in config["generations"]):
        # Fleet writes `Z`; compare as datetimes, not strings, and keep the earliest original value.
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        since = min((a.get("enrolled_at") or now for a in found),
                    key=lambda v: dt.datetime.fromisoformat(v.replace("Z", "+00:00")))
        config["generations"].append({"generation": gen, "since": since})
    es.call("PUT", "/_ingest/pipeline/" + name, body)
    print("registered %s as %s gen %d" % (", ".join(a["id"] for a in found), args.target, gen))


# ---- ingest lag ---------------------------------------------------------------------------------------------------

LAG_SCRIPT = ("doc.containsKey('event.ingested') && doc.containsKey('@timestamp') && "
              "doc['event.ingested'].size() > 0 && doc['@timestamp'].size() > 0 && "
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
