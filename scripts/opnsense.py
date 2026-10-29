"""Minimal OPNsense API client for the lab filter rules (issue #21).

Endpoints follow the OPNsense core firewall API (filter apply, rule CRUD, alias CRUD). Exercised live against OPNsense CE 26.7 by A2 (docs/runbooks/m2-firewall-and-networks.md).
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

    # OPNsense core 26.7 has no savepoint (that is the os-firewall plugin) and apply takes no revision.
    # The revert is the dead-man switch on the firewall (scripts/firewall/opaleye_deadman.py): push_marker
    # before the change, confirm_marker only once the controller can still reach the API afterwards.
    def apply(self):
        out = self.call("firewall/filter/apply")
        if str(out.get("status", "")).strip().upper() != "OK":
            raise ApiError("apply failed: %s" % out)

    def marker(self, name):
        """Token in the description of a dead-man marker alias, or None if the alias does not exist."""
        rows = self.call("firewall/alias/searchItem", {"rowCount": -1}).get("rows", [])
        cur = next((r for r in rows if r.get("name") == name), None)
        return None if cur is None else cur.get("description", "")

    def set_marker(self, name, token):
        want = {"enabled": "1", "name": name, "type": "host", "content": "127.0.0.1", "description": token}
        rows = self.call("firewall/alias/searchItem", {"rowCount": -1}).get("rows", [])
        cur = next((r for r in rows if r.get("name") == name), None)
        if cur:
            self._changed("firewall/alias/setItem/" + cur["uuid"], {"alias": want})
        else:
            self._changed("firewall/alias/addItem", {"alias": want})

    # aliases
    def ensure_alias(self, name, content, comment, check_only=False):
        """Return whether a host alias differs; update it unless check_only is set."""
        want = {"enabled": "1", "name": name, "type": "host", "content": "\n".join(content), "description": comment}
        rows = self.call("firewall/alias/searchItem", {"rowCount": -1}).get("rows", [])
        cur = next((r for r in rows if r.get("name") == name), None)
        if cur and cur.get("content") == want["content"]:
            return False
        if check_only:
            return True
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
