"""Offline tests for scripts/fleetctl.py (issue #23) against tests/fake_elastic.py."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "scripts"))
from fake_elastic import Fake, package_zip  # noqa: E402
import fleetctl  # noqa: E402

PLAN = json.load(open(ROOT / "network/plan.json"))
TS = PLAN["target_stack"]
POLICY = "lab-target-t1"


class Base(unittest.TestCase):
    def setUp(self):
        self.fake = Fake()
        self.pkgs = tempfile.mkdtemp()
        self.addCleanup(self.fake.close)

    def run_cli(self, *args, **extra):
        env = dict(os.environ, FLEET_KIBANA_URL=self.fake.url, FLEET_ES_URL=self.fake.url, FLEET_PACKAGE_DIR=self.pkgs,
                   ELASTIC_PASSWORD="pw", **extra)
        return subprocess.run([sys.executable, str(ROOT / "scripts/fleetctl.py"), *args], env=env, capture_output=True, text=True)

    def stage_packages(self, only=None):
        for name, p in TS["integrations"].items():
            if only is None or name in only:
                pathlib.Path(self.pkgs, p["file"]).write_bytes(package_zip(name, p["version"]))

    def unpinned_plan(self):
        """The staged zips are fakes, so their sha256 cannot match the plan: tests use a plan copy with their hashes."""
        import hashlib
        plan = json.loads(json.dumps(PLAN))
        for name, p in plan["target_stack"]["integrations"].items():
            p["sha256"] = hashlib.sha256(package_zip(name, p["version"])).hexdigest()
        f = pathlib.Path(tempfile.mkdtemp(), "plan.json")
        f.write_text(json.dumps(plan))
        return str(f)


class Packages(Base):
    def test_uploads_missing_integration_zips_and_skips_installed(self):
        self.stage_packages()
        plan = self.unpinned_plan()
        self.fake.installed["docker"] = TS["integrations"]["docker"]["version"]
        r = self.run_cli("upload-packages", FLEET_PLAN=plan)
        self.assertEqual(r.returncode, 0, r.stderr)
        posts = [c for c in self.fake.names() if c == "POST /api/fleet/epm/packages"]
        self.assertEqual(len(posts), 4)  # auditd, Apache, System and Filestream; Docker and Endpoint already installed
        self.assertEqual(self.fake.installed["apache"], TS["integrations"]["apache"]["version"])

    def test_refuses_a_zip_that_does_not_match_the_pinned_sha256(self):
        self.stage_packages()
        r = self.run_cli("upload-packages")  # fake zips do not match the real pins
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("sha256", r.stderr)
        self.assertNotIn("POST /api/fleet/epm/packages", self.fake.names())

    def test_missing_zip_is_an_error_not_a_silent_skip(self):
        r = self.run_cli("upload-packages")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("missing", r.stderr.lower())


class Policy(Base):
    def setUp(self):
        super().setUp()
        for n, p in TS["integrations"].items():
            self.fake.installed[n] = p["version"]

    def test_creates_the_target_policy_with_every_evidence_source(self):
        r = self.run_cli("ensure-policy", "t1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(POLICY, self.fake.policies)
        pkgs = sorted(p["package"]["name"] for p in self.fake.package_policies)
        self.assertEqual(pkgs, ["apache", "auditd_manager", "docker", "endpoint", "filestream", "filestream", "system"])
        self.assertTrue(all(p["policy_id"] == POLICY for p in self.fake.package_policies))

    def test_second_run_creates_nothing(self):
        self.run_cli("ensure-policy", "t1")
        before = list(self.fake.calls)
        r = self.run_cli("ensure-policy", "t1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual([c for c in self.fake.calls[len(before):] if c[0].startswith("POST")], [])

    def test_uninstalled_package_fails_with_the_upload_hint(self):
        del self.fake.installed["apache"]
        r = self.run_cli("ensure-policy", "t1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("upload-packages", r.stderr)

    def test_defend_collects_events_and_does_not_block_the_exercise(self):
        pp = fleetctl.package_policy("t1", "endpoint", PLAN)
        value = pp["inputs"][0]["config"]["integration_config"]["value"]
        self.assertEqual(value["endpointConfig"]["preset"], "DataCollection")

    def test_auditd_has_explicit_exec_rules(self):
        pp = fleetctl.package_policy("t1", "auditd_manager", PLAN)
        rules = json.dumps(pp)
        self.assertIn("execve", rules)

    def test_apache_filestream_does_not_wait_for_1024_bytes(self):
        pp = fleetctl.package_policy("t1", "filestream", PLAN)
        self.assertIn("fingerprint", json.dumps(pp))
        self.assertIn("/var/log/dvwa/apache2/access.log", json.dumps(pp))

    def test_no_secret_or_token_in_any_payload(self):
        for n in ("endpoint", "system", "auditd_manager", "docker", "apache"):
            self.assertNotRegex(json.dumps(fleetctl.package_policy("t1", n, PLAN)).lower(), r"token|password")


class Enrolment(Base):
    def setUp(self):
        super().setUp()
        self.fake.policies[POLICY] = {"id": POLICY}

    def test_prints_only_the_token_and_names_it_by_generation(self):
        r = self.run_cli("issue-token", "t1", "2")
        self.assertEqual(r.returncode, 0, r.stderr)
        key = next(iter(self.fake.keys.values()))
        self.assertEqual(key["name"], "t1-gen2")
        self.assertEqual(r.stdout.strip(), key["api_key"])
        self.assertNotIn(key["api_key"], r.stderr)

    def test_retires_the_previous_token_and_agent(self):
        self.run_cli("issue-token", "t1", "1")
        old = self.fake.enrol(POLICY, "opaleye-t1")
        other = self.fake.enrol("some-other-policy", "elastic")
        r = self.run_cli("issue-token", "t1", "2")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual([k["name"] for k in self.fake.keys.values()], ["t1-gen2"])
        self.assertNotIn(old, self.fake.agents)
        self.assertIn(other, self.fake.agents)

    def test_unknown_target_is_refused(self):
        r = self.run_cli("issue-token", "t9", "1")
        self.assertNotEqual(r.returncode, 0)

    def test_generation_must_be_a_positive_integer(self):
        for bad in ("0", "-1", "x"):
            self.assertNotEqual(self.run_cli("issue-token", "t1", bad).returncode, 0, bad)


class Stamp(Base):
    def test_ensure_pipeline_creates_it_once_and_never_clobbers_the_registry(self):
        self.assertEqual(self.run_cli("ensure-pipeline").returncode, 0)
        name = TS["stamp_pipeline"]
        self.assertIn(name, self.fake.pipelines)
        self.fake.pipelines[name]["processors"][0]["script"]["params"]["agents"]["a1"] = {"target_id": "t1", "rebuild_generation": 1}
        self.assertEqual(self.run_cli("ensure-pipeline").returncode, 0)
        self.assertIn("a1", self.fake.pipelines[name]["processors"][0]["script"]["params"]["agents"])

    def test_register_agent_keeps_earlier_generations(self):
        self.run_cli("ensure-pipeline")
        self.fake.policies[POLICY] = {"id": POLICY}
        self.fake.enrol(POLICY, "opaleye-t1", agent_id="gen1-agent")
        self.assertEqual(self.run_cli("register-agent", "t1", "1").returncode, 0)
        self.fake.agents.clear()
        self.fake.enrol(POLICY, "opaleye-t1", agent_id="gen2-agent")
        self.assertEqual(self.run_cli("register-agent", "t1", "2").returncode, 0)
        agents = self.fake.pipelines[TS["stamp_pipeline"]]["processors"][0]["script"]["params"]["agents"]
        self.assertEqual(agents["gen1-agent"], {"target_id": "t1", "rebuild_generation": 1})
        self.assertEqual(agents["gen2-agent"], {"target_id": "t1", "rebuild_generation": 2})

    def test_register_agent_fails_when_nothing_enrolled(self):
        self.run_cli("ensure-pipeline")
        r = self.run_cli("register-agent", "t1", "1", "--wait", "0")
        self.assertNotEqual(r.returncode, 0)

    def test_pipeline_keeps_event_ingested_distinct_from_timestamp(self):
        p = fleetctl.load_pipeline()
        text = json.dumps(p)
        self.assertIn("event.ingested", text)
        self.assertIn("_ingest.timestamp", text)
        self.assertNotIn("ctx['@timestamp'] =", text)  # never overwrite the source time


class IngestLag(Base):
    def test_no_lagging_events_passes(self):
        r = self.run_cli("ingest-lag")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_lagging_events_fail_and_name_the_dataset(self):
        self.fake.lag_hits = 4
        r = self.run_cli("ingest-lag")
        self.assertEqual(r.returncode, 1)
        self.assertIn("docker.container_logs", r.stdout)

    def test_threshold_is_two_minutes_from_the_plan(self):
        self.run_cli("ingest-lag")
        body = json.dumps(self.fake.last_search[1])
        self.assertIn("120000", body)
        self.assertIn("event.ingested", body)

    def test_kibana_rule_is_created_then_updated_not_duplicated(self):
        self.assertEqual(self.run_cli("lag-rule").returncode, 0)
        self.assertEqual(self.run_cli("lag-rule").returncode, 0)
        self.assertEqual(list(self.fake.rules), ["lab-ingest-lag"])
        rule = self.fake.rules["lab-ingest-lag"]
        self.assertIn("120", rule["params"]["esqlQuery"]["esql"])
        self.assertEqual(rule["schedule"]["interval"], "1m")


if __name__ == "__main__":
    unittest.main()
