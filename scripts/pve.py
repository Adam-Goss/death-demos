"""Minimal Proxmox API client for lab shutdown/startup (issue #24). API token only, power operations only.

Deliberately has no stop, delete or config call: a lab shutdown is a graceful guest shutdown and nothing else.
Env: PROXMOX_VE_ENDPOINT, PROXMOX_VE_INSECURE=true (self-signed).
"""
import json
import ssl
import time
import urllib.request


class PveError(RuntimeError):
    pass


class Client:
    def __init__(self, endpoint, node, token, insecure=False):
        self.base = "%s/api2/json/nodes/%s/qemu" % (endpoint.rstrip("/"), node)
        self.token = token
        self.ctx = ssl._create_unverified_context() if insecure else None

    def _call(self, path, method="GET", body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={
            "Authorization": "PVEAPIToken=" + self.token, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30, context=self.ctx) as r:
                return json.load(r).get("data")
        except Exception as e:  # noqa: BLE001
            raise PveError("%s %s: %s" % (method, path, e))

    def status(self, vmid):
        return self._call("/%d/status/current" % vmid)["status"]

    def shutdown(self, vmid, timeout):
        self._call("/%d/status/shutdown" % vmid, "POST", {"timeout": timeout})

    def start(self, vmid):
        self._call("/%d/status/start" % vmid, "POST", {})

    def wait(self, vmid, want, timeout, poll):
        end = time.time() + timeout
        while time.time() < end:
            if self.status(vmid) == want:
                return True
            time.sleep(poll)
        return self.status(vmid) == want
