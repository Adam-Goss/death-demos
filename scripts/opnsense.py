"""Minimal OPNsense API client for the lab filter rules (issue #21).

Endpoints follow the OPNsense core firewall API (filter savepoint/apply/cancelRollback,
rule CRUD, alias CRUD). Exercised live against OPNsense CE 26.7 by A2 (docs/runbooks/m2-firewall-and-networks.md).
Core 26.7 has no savepoint: see allow_no_savepoint.
Auth: HTTP basic with the API key and secret from the OPNsense user (env, never the repo).
"""
import base64
import json
import ssl
import sys
import urllib.request


class ApiError(RuntimeError):
    pass


class Client:
    def __init__(self, url, key, secret, insecure=False, allow_no_savepoint=False):
        self.allow_no_savepoint = allow_no_savepoint
        self.url = url.rstrip("/")
        self.auth = "Basic " + base64.b64encode(("%s:%s" % (key, secret)).encode()).decode()
        self.ctx = ssl._create_unverified_context() if insecure else None

    def call(self, path, body=None, method="POST"):
        headers = {"Authorization": self.auth}
        data = None
        if method != "GET":  # a GET with a body or JSON content type is a 400 on OPNsense
            data = json.dumps(body if body is not None else {}).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.url + "/api/" + path, method=method, data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=20, context=self.ctx) as r:
                return json.load(r)
        except Exception as e:
            raise ApiError("%s: %s" % (path, e))

    # filter rules
    def rules(self, prefix):
        rows = self.call("firewall/filter/searchRule", {"rowCount": -1}).get("rows", [])
        return {r["description"]: r for r in rows if r.get("description", "").startswith(prefix)}

    def _changed(self, path, body=None):
        """A rejected change is HTTP 200 with result=failed (and validations): it must not read as success."""
        out = self.call(path, body)
        if out.get("result") == "failed" or out.get("validations"):
            raise ApiError("%s rejected: %s" % (path, out))
        return out

    def add_rule(self, rule):
        self._changed("firewall/filter/addRule", {"rule": rule})

    def set_rule(self, uuid, rule):
        self._changed("firewall/filter/setRule/" + uuid, {"rule": rule})

    def del_rule(self, uuid):
        self._changed("firewall/filter/delRule/" + uuid)

    # transaction: apply auto-reverts unless cancel_rollback is called for the same revision
    # OPNsense core has no savepoint (that is the os-firewall plugin): apply takes no revision and
    # nothing reverts a bad change. Only usable when the operator opts in; returns None then.
    def savepoint(self):
        try:
            return self.call("firewall/filter/savepoint")["revision"]
        except ApiError as e:
            if self.allow_no_savepoint and "404" in str(e):
                print("warning: no savepoint on this firewall; changes apply without auto-revert", file=sys.stderr)
                return None
            raise

    def apply(self, revision):
        out = self.call("firewall/filter/apply" + ("/" + revision if revision else ""))
        if str(out.get("status", "")).strip().upper() != "OK":
            raise ApiError("apply failed: %s" % out)

    def cancel_rollback(self, revision):
        if revision is None:
            return
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
            self._changed("firewall/alias/setItem/" + cur["uuid"], {"alias": want})
        else:
            self._changed("firewall/alias/addItem", {"alias": want})
        self.call("firewall/alias/reconfigure")
        return True

    def wireguard_peers(self):
        rows = self.call("wireguard/service/show", method="GET").get("rows", [])
        return [r for r in rows if r.get("type") == "peer"]

    def firewall_log(self):
        return self.call("diagnostics/firewall/log?limit=100", method="GET")
