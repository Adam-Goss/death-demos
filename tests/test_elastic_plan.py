"""Offline guards for M3 (issue #22): the Elastic pin, retention and destroy guard."""
import json
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLAN = json.load(open(ROOT / "network/plan.json"))
EL = PLAN["elastic"]


class ElasticPlan(unittest.TestCase):
    def test_packages_are_pinned_by_version_and_sha512(self):
        for name, p in EL["packages"].items():
            self.assertRegex(p["sha512"], r"^[0-9a-f]{128}$", name)
            self.assertIn(EL["version"], p["file"], name)
            self.assertTrue(p["url"].startswith("https://artifacts.elastic.co/downloads/"), name)
            self.assertTrue(p["url"].endswith(p["file"]), name)

    def test_retention_matches_the_telemetry_contract(self):
        self.assertEqual(EL["retention"]["evidence"]["days"], 90)
        self.assertEqual(EL["retention"]["metrics"]["days"], 14)
        self.assertEqual(EL["snapshots"]["retain_days"], 14)

    def test_datasets_are_unique_and_classified(self):
        names = EL["datasets"]["evidence"] + EL["datasets"]["metrics"]
        self.assertEqual(len(names), len(set(names)))
        for n in names:
            self.assertRegex(n, r"^(logs|metrics)-[a-z0-9_.]+$")

    def test_endpoint_evidence_is_never_on_the_short_policy(self):
        self.assertTrue(all(not n.startswith("metrics-") for n in EL["datasets"]["evidence"]))

    def test_vm_id_does_not_collide_with_other_lab_ids(self):
        ids = {PLAN["firewall"]["vm_id"], EL["vm_id"], EL["template_vm_id"], 2100}
        self.assertEqual(len(ids), 4)

    def test_placeholders_from_the_budget(self):
        self.assertEqual((EL["vcpu"], EL["memory_mb"], EL["heap_gb"], EL["data_disk_gb"]), (4, 8192, 4, 100))


class DestroyGuard(unittest.TestCase):
    def test_lab_sh_refuses_elastic_destroy(self):
        env = dict(os.environ, OPALEYE_STATE_PASSPHRASE="0123456789abcdefghij", PROXMOX_VE_ENDPOINT="https://x/")
        r = subprocess.run(["bash", str(ROOT / "scripts/lab.sh"), "destroy", "elastic"], env=env, capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("refused", r.stderr)

    def test_broad_destroy_skips_elastic(self):
        text = (ROOT / "scripts/lab.sh").read_text()
        self.assertIn("grep -v '^elastic$'", text)

    def test_vm_has_prevent_destroy(self):
        text = (ROOT / "tofu/stacks/elastic/main.tf").read_text()
        self.assertRegex(text, r"prevent_destroy\s*=\s*true")

    def test_elastic_stack_cannot_reach_the_home_bridge_or_ssh(self):
        text = (ROOT / "tofu/stacks/elastic/main.tf").read_text()
        self.assertNotRegex(text, r"zones\.home|zones\[\"home\"\]")
        self.assertNotRegex(text, r"(?m)^\s*ssh\s*\{")


class ConfigBackup(unittest.TestCase):
    """A3 proves the config/secrets backup is restorable: keystores, certificates and configs are in it."""

    def make(self, members):
        d = tempfile.mkdtemp()
        path = pathlib.Path(d) / "config-backup.tgz"
        with tarfile.open(path, "w:gz") as t:
            for m in members:
                f = pathlib.Path(d) / "f"
                f.write_text("x")
                t.add(f, arcname=m)
        return path

    def setUp(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import a3_verify
        self.a3 = a3_verify

    def test_complete_backup_has_nothing_missing(self):
        path = self.make(self.a3.BACKUP_MEMBERS)
        self.assertEqual(self.a3.missing_backup_members(path), [])

    def test_missing_keystore_and_key_are_reported(self):
        path = self.make([m for m in self.a3.BACKUP_MEMBERS if "keystore" not in m and not m.endswith("server.key")])
        gone = self.a3.missing_backup_members(path)
        self.assertTrue(any("elasticsearch.keystore" in m for m in gone))
        self.assertTrue(any("server.key" in m for m in gone))

    def test_absent_archive_reports_everything_missing(self):
        self.assertEqual(self.a3.missing_backup_members(pathlib.Path("/nonexistent/x.tgz")), ["archive"])


class Probes(unittest.TestCase):
    def test_every_ingest_and_kibana_source_is_probed(self):
        seen = {(p["src"], p["port"]): p["modes"]["exercise"] for p in PLAN["probes"] if p["dst"] == "elastic"}
        for src in ("t1", "t2"):
            self.assertEqual(seen[(src, 9200)], "allow")
            self.assertEqual(seen[(src, 8220)], "allow")
        # The attacker is the adversary: no write path to the evidence store (#9, A3).
        for port in (9200, 8220):
            self.assertEqual(seen[("attacker", port)], "deny")
        self.assertEqual(seen[("operator", 5601)], "allow")
        for port in (9200, 8220):
            self.assertEqual(seen[("operator", port)], "deny")
        for src in ("attacker", "t1", "workstation"):
            self.assertEqual(seen[(src, 5601)], "deny")


if __name__ == "__main__":
    unittest.main()
