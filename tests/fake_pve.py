"""In-memory stand-in for the Proxmox qemu status API (the subset scripts/pve.py uses)."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class FakePve:
    def __init__(self, vms, node="n1"):
        self.vms = dict(vms)  # vmid -> "running"/"stopped"
        self.node = node
        self.calls = []       # (method, path, token)
        self.rollbacks = []   # (vmid, snapshot)
        self.stuck = set()    # guests that ignore the shutdown request
        self.srv = HTTPServer(("127.0.0.1", 0), self._handler())
        self.url = "http://127.0.0.1:%d" % self.srv.server_port
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()

    def paths(self):
        return [(m, p) for m, p, _ in self.calls]

    def _handler(self):
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _do(self):
                n = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(n)
                fake.calls.append((self.command, self.path, self.headers.get("Authorization")))
                parts = self.path.strip("/").split("/")  # api2 json nodes N qemu ID status ACTION
                code, out = 404, {}
                if len(parts) == 9 and parts[3] == fake.node and int(parts[5]) in fake.vms and parts[6] == "snapshot" and parts[8] == "rollback":
                    fake.rollbacks.append((int(parts[5]), parts[7]))
                    fake.vms[int(parts[5])] = "stopped"  # a Proxmox rollback leaves the guest stopped (no vmstate in the snapshot)
                    code, out = 200, {"data": "UPID"}
                if len(parts) == 8 and parts[3] == fake.node and int(parts[5]) in fake.vms:
                    vmid, action = int(parts[5]), parts[7]
                    if action == "current":
                        code, out = 200, {"data": {"status": fake.vms[vmid]}}
                    elif action == "shutdown":
                        if vmid not in fake.stuck:
                            fake.vms[vmid] = "stopped"
                        code, out = 200, {"data": "UPID"}
                    elif action == "start":
                        fake.vms[vmid] = "running"
                        code, out = 200, {"data": "UPID"}
                data = json.dumps(out).encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_DELETE = _do

        return H
