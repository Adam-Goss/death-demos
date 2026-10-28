"""In-memory stand-in for the OPNsense filter/alias/log API (the subset scripts/opnsense.py uses)."""
import base64
import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer


class Fake:
    def __init__(self, key="k", secret="s"):
        self.auth = "Basic " + base64.b64encode(("%s:%s" % (key, secret)).encode()).decode()
        self.rules, self.aliases, self.calls, self.log, self.wg_rows = {}, {}, [], [], []
        self.fail_apply = False
        self.reject_rules = False  # OPNsense answers 200 with result=failed for a rejected rule
        self.cut_off = False  # after apply the controller can no longer reach the API (a push that cut it off)
        self.applied = False
        self.srv = HTTPServer(("127.0.0.1", 0), self._handler())
        self.url = "http://127.0.0.1:%d" % self.srv.server_port
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def arm(self, token="t0"):
        for n in ("opaleye_pending", "opaleye_confirmed"):
            self.aliases[str(uuid.uuid4())] = {"name": n, "description": token, "content": "127.0.0.1"}

    def marker(self, name):
        return next((a["description"] for a in self.aliases.values() if a["name"] == name), None)

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()

    def names(self):
        return [c[0] for c in self.calls]

    def mutations(self):
        return [n for n in self.names() if n in ("addRule", "setRule", "delRule")]

    def _route(self, path, body):
        path = path.split("?")[0]
        tail = path.split("/")[-1]
        if self.cut_off and self.applied:
            return None, None
        if path.endswith("/filter/apply"):
            self.applied = True
            return "apply", ({"status": "error"} if self.fail_apply else {"status": "OK "})
        if path.endswith("/filter/searchRule"):
            return "searchRule", {"rows": [dict(r, uuid=u) for u, r in self.rules.items()], "rowCount": len(self.rules)}
        if path.endswith("/filter/addRule"):
            if self.reject_rules:
                return "addRule", {"result": "failed", "validations": {"rule.interface": "not a valid interface"}}
            u = str(uuid.uuid4())
            self.rules[u] = body["rule"]
            return "addRule", {"result": "saved", "uuid": u}
        if "/filter/setRule/" in path:
            self.rules[tail] = body["rule"]
            return "setRule", {"result": "saved"}
        if "/filter/delRule/" in path:
            self.rules.pop(tail, None)
            return "delRule", {"result": "deleted"}
        if path.endswith("/alias/searchItem"):
            return "searchAlias", {"rows": [dict(a, uuid=u) for u, a in self.aliases.items()]}
        if path.endswith("/alias/addItem"):
            u = str(uuid.uuid4())
            self.aliases[u] = body["alias"]
            return "addAlias", {"result": "saved", "uuid": u}
        if "/alias/setItem/" in path:
            self.aliases[tail] = body["alias"]
            return "setAlias", {"result": "saved"}
        if path.endswith("/alias/reconfigure"):
            return "reconfigureAlias", {"status": "ok"}
        if path.endswith("/diagnostics/firewall/log"):
            return "log", list(self.log)
        if path.endswith("/wireguard/service/show"):
            return "wgshow", {"total": len(self.wg_rows), "rows": list(self.wg_rows)}
        return "unknown", {"status": "error"}

    def _handler(self):
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _do(self):
                n = int(self.headers.get("Content-Length") or 0)
                json_ct = "json" in (self.headers.get("Content-Type") or "")
                if self.command == "GET" and (n or json_ct):  # real OPNsense answers 400 to a GET with a body or JSON content type
                    self.send_response(400)
                    self.end_headers()
                    return
                body = json.loads(self.rfile.read(n) or b"{}")
                if self.headers.get("Authorization") != fake.auth:
                    self.send_response(401)
                    self.end_headers()
                    return
                name, out = fake._route(self.path, body)
                if name is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                fake.calls.append((name, body))
                data = json.dumps(out).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = _do
            do_POST = _do

        return H
