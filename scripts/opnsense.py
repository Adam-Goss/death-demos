"""Minimal OPNsense API client for the lab filter rules (issue #21).

Endpoints follow the OPNsense core firewall API (filter savepoint/apply/cancelRollback,
rule CRUD, alias CRUD). Untested against a live OPNsense yet: A2 on the real VM is the proof.
Auth: HTTP basic with the API key and secret from the OPNsense user (env, never the repo).
"""
import base64
import json
import ssl
import urllib.request


class ApiError(RuntimeError):
    pass


class Client:
    def __init__(self, url, key, secret, insecure=False):
        self.url = url.rstrip("/")
        self.auth = "Basic " + base64.b64encode(("%s:%s" % (key, secret)).encode()).decode()
        self.ctx = ssl._create_unverified_context() if insecure else None

    def call(self, path, body=None, method="POST"):
        req = urllib.request.Request(self.url + "/api/" + path, method=method,
                                     data=json.dumps(body if body is not None else {}).encode(),
                                     headers={"Authorization": self.auth, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=20, context=self.ctx) as r:
                return json.load(r)
        except Exception as e:
            raise ApiError("%s: %s" % (path, e))

    # filter rules
    def rules(self, prefix):
        rows = self.call("firewall/filter/searchRule", {"rowCount": -1}).get("rows", [])
        return {r["description"]: r for r in rows if r.get("description", "").startswith(prefix)}

    def add_rule(self, rule):
        self.call("firewall/filter/addRule", {"rule": rule})

    def set_rule(self, uuid, rule):
        self.call("firewall/filter/setRule/" + uuid, {"rule": rule})

    def del_rule(self, uuid):
        self.call("firewall/filter/delRule/" + uuid)

    # transaction: apply auto-reverts unless cancel_rollback is called for the same revision
    def savepoint(self):
        return self.call("firewall/filter/savepoint")["revision"]

    def apply(self, revision):
        out = self.call("firewall/filter/apply/" + revision)
        if str(out.get("status", "")).strip().upper() != "OK":
            raise ApiError("apply failed: %s" % out)

    def cancel_rollback(self, revision):
        self.call("firewall/filter/cancelRollback/" + revision)

    # aliases
    def ensure_alias(self, name, content, comment):
        """Create or update a host alias; returns True if it changed."""
        want = {"enabled": "1", "name": name, "type": "host", "content": "\n".join(content), "description": comment}
        rows = self.call("firewall/alias/searchItem", {"rowCount": -1}).get("rows", [])
        cur = next((r for r in rows if r.get("name") == name), None)
        if cur and cur.get("content") == want["content"]:
            return False
        if cur:
            self.call("firewall/alias/setItem/" + cur["uuid"], {"alias": want})
        else:
            self.call("firewall/alias/addItem", {"alias": want})
        self.call("firewall/alias/reconfigure")
        return True

    def firewall_log(self):
        return self.call("diagnostics/firewall/log", method="GET")
