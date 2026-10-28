"""In-memory stand-in for the Kibana Fleet/alerting and Elasticsearch ingest/search calls scripts/fleetctl.py makes."""
import io
import json
import threading
import uuid
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse


def package_zip(name, version):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("%s-%s/manifest.yml" % (name, version), "name: %s\nversion: %s\n" % (name, version))
    return buf.getvalue()


class Fake:
    def __init__(self):
        self.installed = {"endpoint": "9.5.0", "system": "2.0.0"}
        self.policies, self.package_policies, self.keys, self.agents = {}, [], {}, {}
        self.pipelines, self.rules, self.calls = {}, {}, []
        self.lag_hits = 0
        self.counts = {}  # index pattern -> document count for _count (default 5)
        self.sample = {"@timestamp": "2026-10-28T10:00:00Z", "event": {"created": "2026-10-28T10:00:01Z", "ingested": "2026-10-28T10:00:02Z"},
                       "data_stream": {"dataset": "docker.container_logs"}, "lab": {"target_id": "t1"}}
        self.last_search = None
        self.srv = HTTPServer(("127.0.0.1", 0), self._handler())
        self.url = "http://127.0.0.1:%d" % self.srv.server_port
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()

    def enrol(self, policy_id, host, agent_id=None):
        agent_id = agent_id or str(uuid.uuid4())
        self.agents[agent_id] = {"id": agent_id, "policy_id": policy_id, "status": "online",
                                 "local_metadata": {"host": {"name": host}}}
        return agent_id

    def names(self):
        return [c[0] for c in self.calls]

    def _route(self, method, path, query, raw, ctype):
        body = json.loads(raw) if raw and "json" in (ctype or "") else None
        seg = path.strip("/").split("/")
        self.calls.append((method + " " + path, body))
        if path == "/api/fleet/epm/packages" and method == "POST":
            with zipfile.ZipFile(io.BytesIO(raw)) as z:
                top = z.namelist()[0].split("/")[0]
            name, _, version = top.rpartition("-")
            self.installed[name] = version
            return 200, {"items": []}
        if seg[:4] == ["api", "fleet", "epm", "packages"] and len(seg) == 5 and method == "GET":
            have = self.installed.get(seg[4])
            if have:
                return 200, {"item": {"name": seg[4], "version": have, "status": "installed"}}
            return 404, {"message": "not found"}
        if seg[:4] == ["api", "fleet", "epm", "packages"] and len(seg) == 6 and method == "GET":
            have = self.installed.get(seg[4])
            if have == seg[5]:
                return 200, {"item": {"name": seg[4], "version": have, "status": "installed"}}
            return 404, {"message": "not found"}
        if seg[:3] == ["api", "fleet", "agent_policies"]:
            if method == "GET" and len(seg) == 4:
                return (200, {"item": self.policies[seg[3]]}) if seg[3] in self.policies else (404, {})
            if method == "POST":
                self.policies[body["id"]] = dict(body)
                return 200, {"item": body}
        if path == "/api/fleet/package_policies":
            if method == "GET":
                return 200, {"items": self.package_policies}
            if method == "POST":
                if body["package"]["name"] not in self.installed:
                    return 400, {"message": "package not installed"}
                self.package_policies.append(dict(body, id=str(uuid.uuid4())))
                return 200, {"item": body}
        if path == "/api/fleet/enrollment_api_keys":
            if method == "GET":
                return 200, {"items": list(self.keys.values())}
            if method == "POST":
                k = {"id": str(uuid.uuid4()), "name": body["name"], "policy_id": body["policy_id"],
                     "api_key": "SECRET-" + uuid.uuid4().hex, "active": True}
                self.keys[k["id"]] = k
                return 200, {"item": k}
        if seg[:3] == ["api", "fleet", "enrollment_api_keys"] and method == "DELETE":
            self.keys.pop(seg[3], None)
            return 200, {"action": "deleted"}
        if path == "/api/fleet/agents" and method == "GET":
            return 200, {"items": list(self.agents.values())}
        if seg[:3] == ["api", "fleet", "agents"] and seg[-1] == "unenroll" and method == "POST":
            self.agents.pop(seg[3], None)
            return 200, {}
        if seg[:3] == ["api", "alerting", "rule"]:
            rid = seg[3]
            if method == "GET":
                return (200, self.rules[rid]) if rid in self.rules else (404, {})
            if method in ("POST", "PUT"):
                if method == "POST" and rid in self.rules:
                    return 409, {}
                self.rules[rid] = body
                return 200, body
        if seg[:2] == ["_ingest", "pipeline"]:
            if method == "GET":
                return (200, {seg[2]: self.pipelines[seg[2]]}) if seg[2] in self.pipelines else (404, {})
            if method == "PUT":
                self.pipelines[seg[2]] = body
                return 200, {"acknowledged": True}
        if path.endswith("/_search") and method == "POST":
            self.last_search = (path, body)
            n = self.lag_hits if body and "script" in json.dumps(body) else 1
            return 200, {"hits": {"total": {"value": n}, "hits": [{"_source": self.sample}] * min(n, 3)}}
        if path.endswith("/_count") and method == "POST":
            self.last_count = (path, body)
            return 200, {"count": self.counts.get(seg[0], 5)}

        return 404, {"error": "unhandled " + method + " " + path}

    def _handler(self):
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _do(self):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                u = urlparse(self.path)
                code, out = fake._route(self.command, u.path, u.query, raw, self.headers.get("Content-Type"))
                data = json.dumps(out).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_DELETE = _do

        return H
