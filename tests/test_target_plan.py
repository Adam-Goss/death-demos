"""Offline guards for M4 (issue #23): pins, no baked-in token, target stack shape, Ansible/Compose wiring."""
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "scripts"))
from fake_elastic import Fake  # noqa: E402
from labcommon import BASH  # noqa: E402
import a4_verify  # noqa: E402
import fleetctl  # noqa: E402

PLAN = json.loads((ROOT / "network/plan.json").read_text())
TS = PLAN["target_stack"]
T1 = PLAN["targets"]["t1"]


def text(rel):
    return (ROOT / rel).read_text()


class Pins(unittest.TestCase):
    def test_images_are_pinned_by_digest_and_compose_uses_only_those(self):
        for name, i in TS["dvwa"]["images"].items():
            self.assertRegex(i["digest"], r"^sha256:[0-9a-f]{64}$", name)
        compose = text("ansible/roles/target/templates/compose.yml.j2")
        images = re.findall(r"(?m)^\s+image:\s*(\S.*)$", compose)
        self.assertEqual(len(images), 2)
        for img in images:
            self.assertIn("@{{ ts.dvwa.images.", img)
        self.assertNotRegex(compose, r"(?m):latest|build:|pull_policy:\s*always")

    def test_integration_zips_are_pinned_by_sha256_and_version(self):
        for name, p in TS["integrations"].items():
            self.assertRegex(p["sha256"], r"^[0-9a-f]{64}$", name)
            self.assertEqual(p["file"], "%s-%s.zip" % (name, p["version"]))
            self.assertTrue(p["url"].endswith("/" + p["file"]) and p["url"].startswith("https://epr.elastic.co/"), name)

    def test_every_integration_is_uploaded_not_pulled_and_covers_a_listed_dataset(self):
        datasets = PLAN["elastic"]["datasets"]["evidence"]
        for name in ("auditd_manager", "docker", "apache"):
            self.assertIn(name, TS["integrations"])
            self.assertTrue(any(d.startswith("logs-" + name) for d in datasets), name)
        self.assertEqual(set(TS["bundled_integrations"]), set())

    def test_ghcr_is_a_maintenance_update_source_for_the_dvwa_image(self):
        self.assertIn("ghcr.io", PLAN["update_sources"])
        self.assertNotIn("ghcr.io", json.dumps(PLAN["elastic"]))

    def test_target_vm_ids_do_not_collide(self):
        ids = [PLAN["firewall"]["vm_id"], PLAN["elastic"]["vm_id"], PLAN["elastic"]["template_vm_id"], 2100,
               T1["vm_id"], T1["template_vm_id"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_inventory_address_matches_the_plan(self):
        inv = text("ansible/inventory/hosts.yml")
        self.assertIn("ansible_host: " + PLAN["hosts"]["t1"]["ip"], inv)


class NoBakedInSecrets(unittest.TestCase):
    def test_the_template_image_and_role_carry_no_enrolment_token(self):
        self.assertNotIn("enroll", text("scripts/make-target-template.sh").lower())
        role = ROOT / "ansible/roles/target"
        for f in list(role.rglob("templates/*")) + list(role.rglob("files/*")) + list(role.rglob("defaults/*")):
            self.assertNotRegex(f.read_text().lower(), r"enrol+ment[-_ ]?(token|key)|api_key", str(f))

    def test_token_is_only_ever_passed_on_a_no_log_task(self):
        tasks = text("ansible/roles/target/tasks/agent.yml")
        for block in re.split(r"(?m)^- name:", tasks)[1:]:
            if "token.stdout" in block or "issue-token" in block:
                self.assertIn("no_log: true", block, block.splitlines()[0])

    def test_token_is_issued_per_rebuild_generation(self):
        self.assertRegex(text("ansible/roles/target/tasks/agent.yml"), r"issue-token.*rebuild_generation")

    def test_agent_trusts_the_lab_ca(self):
        self.assertIn("--certificate-authorities=/etc/lab-ca/ca.crt", text("ansible/roles/target/tasks/agent.yml"))

    def test_agent_is_downloaded_with_the_pinned_checksum(self):
        self.assertIn("checksum: \"sha512:{{ agent_pkg.sha512 }}\"", text("ansible/roles/target/tasks/agent.yml"))

    def test_no_secrets_dir_content_is_committed(self):
        tracked = subprocess.run(["git", "ls-files", "secrets"], cwd=ROOT, capture_output=True, text=True).stdout
        self.assertEqual(tracked.strip(), "")


class TargetStack(unittest.TestCase):
    def test_vm_comes_from_the_plan_not_literals(self):
        t = text("tofu/stacks/targets/main.tf")
        self.assertNotRegex(t, r"vmbr\d+")
        self.assertIn("local.plan.targets", t)
        self.assertNotRegex(t, r"(?m)^\s*ssh\s*\{")
        self.assertNotRegex(t, r"zones\.home|zones\[\"home\"\]")

    def test_generation_change_replaces_the_vm_and_there_is_no_destroy_guard(self):
        t = text("tofu/stacks/targets/main.tf")
        self.assertIn("replace_triggered_by", t)
        self.assertNotIn("prevent_destroy", t)  # a used target is rebuilt, never kept

    def test_target_is_one_nic_on_its_own_bridge(self):
        t = text("tofu/stacks/targets/main.tf")
        self.assertEqual(t.count("network_device {"), 1)

    def test_targets_stack_is_applied_after_elastic(self):
        order = re.search(r'ORDER="([^"]+)"', text("scripts/lab.sh")).group(1).split()
        self.assertLess(order.index("elastic"), order.index("targets"))


class LabFields(unittest.TestCase):
    def test_every_evidence_stream_gets_the_stamp_pipeline_and_mappings_from_the_custom_template(self):
        lc = text("ansible/roles/elastic/tasks/lifecycle.yml")
        self.assertIn("index.final_pipeline", lc)
        for field in ("target_id", "rebuild_generation", "exercise_id"):
            self.assertIn(field, lc)

    def test_stamp_pipeline_is_created_only_when_absent(self):
        lc = text("ansible/roles/elastic/tasks/lifecycle.yml")
        self.assertIn("status_code: [200, 404]", lc)
        self.assertIn("when: stamp.status == 404", lc)

    def test_pipeline_file_is_valid_and_registry_starts_empty(self):
        p = fleetctl.load_pipeline()
        self.assertEqual(p["processors"][0]["script"]["params"]["agents"], {})


class A4Verifier(unittest.TestCase):
    def setUp(self):
        self.fake = Fake()
        self.addCleanup(self.fake.close)
        import os
        os.environ.update(FLEET_KIBANA_URL=self.fake.url, FLEET_ES_URL=self.fake.url, ELASTIC_PASSWORD="pw")
        self.fake.rules["lab-ingest-lag"] = {"enabled": True}

    def run_rows(self):
        return a4_verify.check(fleetctl.elastic(), "t1", 2, 60)

    def test_all_sources_present_with_distinct_times_and_no_lag_passes(self):
        rows = self.run_rows()
        self.assertTrue(all(r[-1] for r in rows), [r for r in rows if not r[-1]])
        self.assertEqual(len([r for r in rows if r[1] in dict(a4_verify.SOURCES)]), 7)

    def test_a_silent_source_fails(self):
        self.fake.counts["logs-auditd_manager.auditd-*"] = 0
        bad = [r for r in self.run_rows() if not r[-1]]
        self.assertEqual([r[1] for r in bad], ["auditd"])

    def test_equal_timestamps_fail_the_distinct_check(self):
        s = self.fake.sample
        s["event"]["ingested"] = s["@timestamp"]
        self.assertTrue(any("times" in r[1] and not r[-1] for r in self.run_rows()))

    def test_lag_over_two_minutes_fails(self):
        self.fake.lag_hits = 2
        self.assertTrue(any(r[1] == "ingest lag" and not r[-1] for r in self.run_rows()))

    def test_missing_lag_rule_fails(self):
        self.fake.rules.clear()
        self.assertTrue(any("rule" in r[1] and not r[-1] for r in self.run_rows()))

    def test_query_filters_on_target_and_generation(self):
        self.run_rows()
        body = json.dumps(self.fake.last_count[1])
        self.assertIn('"lab.target_id": "t1"', body)
        self.assertIn('"lab.rebuild_generation": 2', body)

    def test_manual_rows_are_listed_as_skips_not_passes(self):
        self.assertTrue(all(why.startswith("SKIP") for _, why in a4_verify.MANUAL))
        self.assertEqual(len(a4_verify.MANUAL), 3)


class TargetShell(unittest.TestCase):
    def run_sh(self, *args):
        return subprocess.run([BASH, str(ROOT / "scripts/target.sh"), *args], capture_output=True, text=True, cwd=ROOT)

    def test_unknown_target_is_refused(self):
        r = self.run_sh("provision", "t9")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("unknown target", r.stderr)

    def test_t2_has_no_vm_yet(self):
        self.assertNotEqual(self.run_sh("generation", "t2").returncode, 0)

    def test_bump_needs_the_acknowledgement_while_no_drain_check_exists(self):
        r = self.run_sh("bump", "t1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("drain check", r.stderr)


class RebuildGenerationReachesTheStack(unittest.TestCase):
    """#71: with TF_VAR_rebuild_generation unset the stack resolved the generation to `lookup(..., 1)`, which
    disagrees with the state and trips the VM's `replace_triggered_by` — `plan targets` reported a bland
    `1 to add, 1 to change, 1 to destroy` and an apply destroyed a healthy target with no drain check and no
    maintenance window, enrolling the replacement back at generation 1. lab.sh now reads the counters
    scripts/target.sh owns. Behavioural: a stub tofu records the variable each stack was called with.
    """

    def setUp(self):
        d = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.repo = d / "checkout"
        (self.repo / "scripts").mkdir(parents=True)
        shutil.copy(ROOT / "scripts/lab.sh", self.repo / "scripts/lab.sh")
        for s in ("firewall", "elastic", "targets", "attacker", "gateway"):
            (self.repo / "tofu/stacks" / s).mkdir(parents=True)
        self.log = d / "calls"
        stub = d / "tofu"
        stub.write_text('#!/bin/sh\nprintf "%%s %%s\\n" "$(basename "$PWD")" "${TF_VAR_rebuild_generation-unset}" >> "%s"\n'
                        % self.log)
        stub.chmod(0o755)
        self.env = dict(os.environ, PATH=str(d) + os.pathsep + os.environ["PATH"],
                        OPALEYE_STATE_PASSPHRASE="0123456789abcdefghij", PROXMOX_VE_ENDPOINT="https://x/")
        for s in ("FIREWALL", "ELASTIC", "TARGETS", "ATTACKER", "GATEWAY"):
            self.env["PROXMOX_VE_API_TOKEN_" + s] = "t"
        self.env.pop("TF_VAR_rebuild_generation", None)

    def counter(self, target, value):
        p = self.repo / ".state/targets" / (target + ".generation")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(value + "\n")

    def run_lab(self, *args):
        return subprocess.run([BASH, "scripts/lab.sh", *args], cwd=self.repo, env=self.env,
                              capture_output=True, text=True)

    def calls(self):
        """(stack, rebuild_generation as the stack saw it) per tofu invocation, in order."""
        lines = self.log.read_text().splitlines() if self.log.exists() else []
        return [tuple(line.split(" ", 1)) for line in lines]

    def test_plan_targets_passes_the_recorded_generation_not_the_fallback(self):
        self.counter("t1", "7")
        r = self.run_lab("plan", "targets")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.calls(), [("targets", '{"t1": 7}')])

    def test_apply_all_cannot_rebuild_a_target_as_a_side_effect(self):
        """`scripts/a1-verify.sh` runs `lab.sh apply all`, and `/lab-deploy` offers it: the README's
        "re-running an apply is always safe" has to hold for the targets stack too."""
        self.counter("t1", "7")
        r = self.run_lab("apply", "all")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual([stack for stack, _ in self.calls()],
                         ["firewall", "elastic", "targets", "attacker", "gateway"])
        self.assertEqual(dict(self.calls())["targets"], '{"t1": 7}')

    def test_every_target_with_a_counter_is_in_the_map(self):
        """Not just the one being worked on: an entry left out is the same unguarded rebuild for that target."""
        self.counter("t1", "7")
        self.counter("t3", "2")
        self.assertEqual(self.run_lab("plan", "targets").returncode, 0)
        self.assertEqual(self.calls(), [("targets", '{"t1": 7, "t3": 2}')])

    def test_a_first_build_with_no_counter_yet_is_the_empty_map(self):
        r = self.run_lab("apply", "targets")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.calls(), [("targets", "{}")])

    def test_an_explicit_variable_is_never_overridden(self):
        self.counter("t1", "7")
        self.env["TF_VAR_rebuild_generation"] = '{"t1": 9}'
        self.assertEqual(self.run_lab("plan", "targets").returncode, 0)
        self.assertEqual(self.calls(), [("targets", '{"t1": 9}')])

    def test_an_empty_variable_is_treated_as_absent_not_passed_through(self):
        """It is not valid HCL for a map(number): passing it on fails the stack with the counter sitting there."""
        self.counter("t1", "7")
        self.env["TF_VAR_rebuild_generation"] = ""
        self.assertEqual(self.run_lab("plan", "targets").returncode, 0)
        self.assertEqual(self.calls(), [("targets", '{"t1": 7}')])

    def test_a_corrupt_counter_refuses_instead_of_falling_back_to_one(self):
        for bad in ("0", "", "7; rm -rf /", "nine"):
            with self.subTest(generation=bad):
                self.counter("t1", bad)
                r = self.run_lab("plan", "targets")
                self.assertNotEqual(r.returncode, 0, r.stdout)
                self.assertIn("bad generation", r.stderr)
                self.assertEqual(self.calls(), [], "tofu ran on a counter we could not read")


if __name__ == "__main__":
    unittest.main()
