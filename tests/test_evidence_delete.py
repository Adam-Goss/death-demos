"""Evidence deletion (issue #24): only via its guarded, confirmed command; unreachable from reset/shutdown."""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))
from fake_es_ops import FakeEs  # noqa: E402

PLAN = json.load(open(os.path.join(ROOT, "network/plan.json")))
MARK = PLAN["ops"]["marker_stream"]


class EvidenceDelete(unittest.TestCase):
    def setUp(self):
        self.es = FakeEs()
        self.dir = tempfile.mkdtemp()
        pw = os.path.join(self.dir, "pw")
        with open(pw, "w") as f:
            f.write("pw\n")
        self.env = dict(os.environ, LABMODE_STATE_DIR=self.dir, ELASTIC_ES_URL=self.es.url, ELASTIC_PASSWORD_FILE=pw)
        for i in range(3):
            self.es.add("logs-endpoint.events.process-default", {"@timestamp": "2026-10-28T10:0%d:00Z" % i, "lab": {"target_id": "t1"}})
        self.es.add("logs-endpoint.events.process-default", {"@timestamp": "2026-10-28T12:00:00Z", "lab": {"target_id": "t1"}})
        self.es.add("logs-apache.access-default", {"@timestamp": "2026-10-28T10:01:30Z", "lab": {"target_id": "t1"}})
        self.es.add("metrics-system.cpu-default", {"@timestamp": "2026-10-28T10:01:00Z"})
        self.es.add(MARK, {"@timestamp": "2026-10-28T10:00:00Z", "event": {"action": "exercise-start"}, "lab": {"exercise_id": "ex-1", "target_id": "t1"}})
        self.es.add(MARK, {"@timestamp": "2026-10-28T11:00:00Z", "event": {"action": "exercise-end"}, "lab": {"exercise_id": "ex-1", "target_id": "t1"}})

    def tearDown(self):
        self.es.close()

    def run_cli(self, *args):
        return subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "evidence_delete.py"), *args],
                              env=self.env, capture_output=True, text=True)

    def phrase(self, scope):
        out = self.run_cli(scope).stdout
        return re.search(r'--confirm "(.*)"', out).group(1)

    def count(self, prefix):
        return len(self.es.select(prefix))

    def test_without_confirmation_it_only_reports_what_it_would_delete(self):
        r = self.run_cli("all")
        self.assertEqual(r.returncode, 2)
        self.assertIn("DELETE EVIDENCE all (7 documents)", r.stdout)
        self.assertEqual(self.es.deletes(), [])

    def test_a_wrong_phrase_deletes_nothing(self):
        r = self.run_cli("all", "--confirm", "yes")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.es.deletes(), [])
        self.assertEqual(self.count("logs-"), 7)

    def test_all_removes_evidence_and_markers_but_not_metrics(self):
        r = self.run_cli("all", "--confirm", self.phrase("all"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.count("logs-"), 0)
        self.assertEqual(self.count("metrics-"), 1)

    def test_one_exercise_removes_only_its_window_on_its_target(self):
        r = self.run_cli("exercise:ex-1", "--confirm", self.phrase("exercise:ex-1"))
        self.assertEqual(r.returncode, 0, r.stderr)
        left = self.es.select("logs-endpoint.events.process")
        self.assertEqual([d["@timestamp"] for d in left], ["2026-10-28T12:00:00Z"])
        self.assertEqual(self.count("logs-apache.access"), 0)
        self.assertEqual(self.count(MARK), 0)
        self.assertEqual(self.count("metrics-"), 1)

    def test_a_phrase_for_a_different_scope_or_count_is_refused(self):
        self.assertNotEqual(self.run_cli("all", "--confirm", "DELETE EVIDENCE all").returncode, 0)
        self.assertNotEqual(self.run_cli("all", "--confirm", "DELETE EVIDENCE all (9 documents)").returncode, 0)
        self.assertEqual(self.es.deletes(), [])

    def test_firewall_flow_rows_in_the_window_go_with_the_exercise(self):
        self.es.add("logs-lab_firewall.flow-default", {"@timestamp": "2026-10-28T10:30:00Z"})
        self.es.add("logs-lab_firewall.flow-default", {"@timestamp": "2026-10-28T14:00:00Z"})
        self.assertEqual(self.run_cli("exercise:ex-1", "--confirm", self.phrase("exercise:ex-1")).returncode, 0)
        self.assertEqual([d["@timestamp"] for d in self.es.select("logs-lab_firewall.flow")], ["2026-10-28T14:00:00Z"])

    def test_an_unknown_exercise_is_refused(self):
        self.assertNotEqual(self.run_cli("exercise:nope", "--confirm", "DELETE EVIDENCE exercise:nope").returncode, 0)
        self.assertEqual(self.es.deletes(), [])

    def test_refused_while_an_exercise_is_active(self):
        with open(os.path.join(self.dir, "labops.json"), "w") as f:
            json.dump({"active": {"id": "ex-9", "target": "t1"}, "generations": {}}, f)
        r = self.run_cli("all", "--confirm", "DELETE EVIDENCE all (7 documents)")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.es.deletes(), [])

    def test_refused_when_the_markers_show_an_open_exercise_even_without_local_state(self):
        self.es.add(MARK, {"@timestamp": "2026-10-28T13:00:00Z", "event": {"action": "exercise-start"}, "lab": {"exercise_id": "ex-2", "target_id": "t1"}})
        r = self.run_cli("all", "--confirm", "DELETE EVIDENCE all (9 documents)")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.es.deletes(), [])

    def test_a_confirmed_deletion_is_audited(self):
        self.run_cli("all", "--confirm", self.phrase("all"))
        with open(os.path.join(self.dir, "evidence-delete.log")) as f:
            self.assertEqual(json.loads(f.readline())["scope"], "all")


class Unreachable(unittest.TestCase):
    """Evidence deletion is its own entry point; reset, shutdown and the stack runner cannot reach it."""

    def read(self, rel):
        with open(os.path.join(ROOT, rel)) as f:
            return f.read()

    def test_labops_has_no_delete_path_to_elasticsearch(self):
        text = self.read("scripts/labops.py") + self.read("scripts/pve.py")
        self.assertNotRegex(text, r"evidence_delete|_delete_by_query|_data_stream|\"DELETE\"|method=.DELETE")
        self.assertNotRegex(text, r"import evidence")

    def test_nothing_imports_evidence_delete(self):
        for rel in os.listdir(os.path.join(ROOT, "scripts")):
            if rel.endswith((".py", ".sh")) and rel != "evidence_delete.py":
                self.assertNotIn("evidence_delete", self.read("scripts/" + rel), rel)

    def test_pve_client_has_no_stop_delete_or_config_call(self):
        self.assertNotRegex(self.read("scripts/pve.py"), r"status/stop|DELETE|status/reset|/config")

    def test_lab_sh_still_refuses_to_destroy_elastic(self):
        env = dict(os.environ, OPALEYE_STATE_PASSPHRASE="0123456789abcdefghij", PROXMOX_VE_ENDPOINT="https://x/")
        r = subprocess.run(["bash", os.path.join(ROOT, "scripts/lab.sh"), "destroy", "elastic"], env=env, capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("refused", r.stderr)


if __name__ == "__main__":
    unittest.main()
