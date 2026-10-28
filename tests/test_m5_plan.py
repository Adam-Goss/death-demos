"""Offline guards for M5 (issue #24): attacker stack isolation, id uniqueness, marker template, stack runner."""
import json
import os
import re
import subprocess
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PLAN = json.load(open(os.path.join(ROOT, "network/plan.json")))


def read(rel):
    with open(os.path.join(ROOT, rel)) as f:
        return f.read()


class AttackerStack(unittest.TestCase):
    def test_vm_ids_are_unique_across_the_lab(self):
        ids = [PLAN["firewall"]["vm_id"], PLAN["elastic"]["vm_id"], PLAN["elastic"]["template_vm_id"],
               PLAN["attacker"]["vm_id"], PLAN["attacker"]["template_vm_id"], 2100]
        ids += [t["vm_id"] for t in PLAN["targets"].values() if "vm_id" in t]
        ids += [t["template_vm_id"] for t in PLAN["targets"].values() if "template_vm_id" in t]
        self.assertEqual(len(ids), len(set(ids)))

    def test_attacker_address_and_bridge_come_from_the_plan(self):
        tf = read("tofu/stacks/attacker/main.tf")
        self.assertIn('zones["attacker"]', tf)
        self.assertIn("local.zone.bridge", tf)
        self.assertNotRegex(tf, r"vmbr\d+")

    def test_attacker_stack_has_no_ssh_block_home_bridge_or_literal_token(self):
        tf = read("tofu/stacks/attacker/main.tf") + read("tofu/stacks/attacker/versions.tf")
        self.assertNotRegex(tf, r"(?m)^\s*ssh\s*\{")
        self.assertNotRegex(tf, r"zones\.home|zones\[\"home\"\]")
        self.assertNotRegex(tf, r"api_token\s*=\s*\"")
        self.assertIn("attacker.tfstate", tf)
        self.assertRegex(tf, r"enforced\s*=\s*true")

    def test_attacker_has_its_own_pool_token_and_state(self):
        self.assertIn("attacker", re.search(r"for stack in ([a-z ]+);", read("scripts/bootstrap-proxmox.sh")).group(1))
        self.assertEqual(PLAN["attacker"]["pool"], "lab-attacker")
        self.assertIn('default     = "lab-attacker"', read("tofu/stacks/attacker/main.tf"))

    def test_runner_orders_attacker_after_targets_and_still_skips_elastic_on_destroy(self):
        sh = read("scripts/lab.sh")
        self.assertIn('ORDER="firewall elastic targets attacker"', sh)
        self.assertIn("grep -v '^elastic$'", sh)

    def test_targets_stack_does_not_manage_the_attacker(self):
        for rel in os.listdir(os.path.join(ROOT, "tofu/stacks/targets")):
            if rel.endswith(".tf"):
                code = [ln for ln in read("tofu/stacks/targets/" + rel).splitlines() if not ln.lstrip().startswith("#")]
                self.assertNotIn("attacker", "\n".join(code), rel)


class Markers(unittest.TestCase):
    def test_marker_template_matches_the_marker_stream_and_uses_evidence_retention(self):
        y = read("ansible/roles/elastic/tasks/markers.yml")
        self.assertIn("plan.ops.marker_stream", y)
        self.assertIn("el.retention.evidence.policy", y)
        self.assertRegex(PLAN["ops"]["marker_stream"], r"^logs-lab_marker\.events-default$")

    def test_marker_stream_is_not_in_the_dataset_lists_that_expect_a_custom_template(self):
        self.assertNotIn("logs-lab_marker.events", PLAN["elastic"]["datasets"]["evidence"])

    def test_the_drain_log_is_shipped_by_the_apache_access_stream(self):
        self.assertIn('plan["ops"]["drain"]["log"]', read("scripts/fleetctl.py"))
        self.assertTrue(PLAN["ops"]["drain"]["log"].startswith(PLAN["target_stack"]["apache_log_dir"] + "/"))
        self.assertIn("plan.ops.drain.log", read("ansible/roles/target/tasks/dvwa.yml"))

    def test_reset_uses_target_sh_and_not_the_stack_runner(self):
        text = read("scripts/labops.py")
        self.assertIn("target.sh", text)
        self.assertNotIn("lab.sh", text.replace("labmode", ""))


class Playbooks(unittest.TestCase):
    def test_attacker_playbook_passes_syntax_check_when_ansible_is_installed(self):
        if subprocess.run(["which", "ansible-playbook"], capture_output=True).returncode != 0:
            self.skipTest("ansible not installed")
        r = subprocess.run(["ansible-playbook", "playbooks/attacker.yml", "--syntax-check"],
                           cwd=os.path.join(ROOT, "ansible"), capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
