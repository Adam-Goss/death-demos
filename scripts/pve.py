"""Minimal Proxmox API client for lab shutdown/startup (issue #24). API token only, power operations only.

Deliberately has no stop, delete or config call: a lab shutdown is a graceful guest shutdown and nothing else.
Env: PROXMOX_VE_ENDPOINT, PROXMOX_VE_INSECURE=true (self-signed).
"""
import os
import ssl
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from labcommon import fetch_json  # noqa: E402


class PveError(RuntimeError):
    pass


class Client:
    def __init__(self, endpoint, node, token, insecure=False):
        self.base = "%s/api2/json/nodes/%s/qemu" % (endpoint.rstrip("/"), node)
        self.token = token
        self.ctx = ssl._create_unverified_context() if insecure else None

    def _call(self, path, method="GET", body=None):
        headers = {"Authorization": "PVEAPIToken=" + self.token, "Content-Type": "application/json"}
        try:
            return fetch_json(self.base + path, method, headers, body, self.ctx).get("data")
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


def from_env(stack):
    """Client for one stack's token. Shutdown/startup read their settings only here."""
    endpoint, node = os.environ.get("PROXMOX_VE_ENDPOINT"), os.environ.get("PVE_NODE")
    if not (endpoint and node):
        raise SystemExit("set PROXMOX_VE_ENDPOINT and PVE_NODE")
    var = "PROXMOX_VE_API_TOKEN_" + stack.upper()
    if not os.environ.get(var):
        raise SystemExit("set " + var)
    return Client(endpoint, node, os.environ[var], os.environ.get("PROXMOX_VE_INSECURE") == "true")
