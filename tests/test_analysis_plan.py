"""Offline guards for the malware analysis zone (#52): plan wiring, resource sizes, scoping of the stack and its token."""
import ipaddress
import json
import os
import re
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import netpolicy  # noqa: E402

PLAN = netpolicy.load_plan(os.path.join(ROOT, "network", "plan.json"))
AN = PLAN["analysis"]


def read(rel):
    with open(os.path.join(ROOT, rel)) as f:
        return f.read()


class Resources(unittest.TestCase):
    def test_sizes_match_the_decision(self):
        self.assertEqual([AN["hosts"]["remnux"][k] for k in ("vcpu", "memory_mb", "disk_gb")], [4, 8192, 50])
        self.assertEqual([AN["hosts"]["flare"][k] for k in ("vcpu", "memory_mb", "disk_gb")], [4, 8192, 100])

    def test_vm_and_template_ids_are_unique_across_the_plan(self):
        ids = [PLAN["firewall"]["vm_id"], PLAN["elastic"]["vm_id"], PLAN["elastic"]["template_vm_id"], PLAN["attacker"]["vm_id"],
               PLAN["attacker"]["template_vm_id"], PLAN["gateway"]["vm_id"], PLAN["gateway"]["template_vm_id"], 2100,
               PLAN["targets"]["t1"]["vm_id"], PLAN["targets"]["t1"]["template_vm_id"]]
        for h in AN["hosts"].values():
            ids += [h["vm_id"], h["template_vm_id"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_hosts_sit_in_the_analysis_zone_at_plan_addresses(self):
        net = ipaddress.ip_network(PLAN["zones"]["analysis"]["cidr"])
        for h in AN["hosts"]:
            self.assertEqual(PLAN["hosts"][h]["zone"], "analysis")
            self.assertIn(ipaddress.ip_address(PLAN["hosts"][h]["ip"]), net)

    def test_images_are_pinned_by_sha256_or_carry_the_explicit_placeholder(self):
        for h, v in AN["hosts"].items():
            self.assertRegex(v["image"]["sha256"], r"^([0-9a-f]{64}|REPLACE-WITH-PINNED-SHA256-[A-Z-]+)$", h)


class Isolation(unittest.TestCase):
    def test_private_ranges_cover_rfc1918_and_the_lab(self):
        nets = [ipaddress.ip_network(n) for n in AN["private_ranges"]]
        for probe in ("10.77.1.10", "10.77.20.11", "172.16.5.5", "192.168.0.161", "192.168.0.1", "169.254.1.1", "100.64.0.1", "127.0.0.1"):
            self.assertTrue(any(ipaddress.ip_address(probe) in n for n in nets), probe)
        for public in ("1.1.1.1", "203.0.113.55", "8.8.8.8"):
            self.assertFalse(any(ipaddress.ip_address(public) in n for n in nets), public)

    def test_every_private_block_is_ahead_of_every_internet_allow_on_the_interface(self):
        rules = [r for r in netpolicy.render_rules(PLAN, "exercise", None, True) if r["iface"] == "opt6"]
        first_allow = next(i for i, r in enumerate(rules) if r["id"].startswith("analysis-internet"))
        blocks = [i for i, r in enumerate(rules) if r["id"].startswith("analysis-block")]
        self.assertTrue(blocks and max(blocks) < first_allow)

    def test_ipv6_stays_blocked_on_the_analysis_interface_even_online(self):
        rules = netpolicy.render_rules(PLAN, "exercise", None, True)
        self.assertTrue(any(r["iface"] == "opt6" and r["family"] == "inet6" and r["action"] == "block" and r["enabled"] for r in rules))
        self.assertFalse(any(r["iface"] == "opt6" and r["family"] == "inet6" and r["action"] == "pass" for r in rules))

    def test_only_the_gateway_has_a_pass_rule_into_the_analysis_addresses(self):
        for online in (False, True):
            passes = {r["src"] for r in netpolicy.render_rules(PLAN, "exercise", None, online)
                      if r["action"] == "pass" and r["iface"] != "opt6" and r["dst"] in ("10.77.20.10/32", "10.77.20.11/32", "10.77.20.0/24")}
            self.assertEqual(passes, {"10.77.2.10/32"})


class Scoping(unittest.TestCase):
    def test_the_stack_is_off_by_default_and_state_is_encrypted(self):
        self.assertRegex(read("tofu/stacks/analysis/main.tf"), r'variable "started"[^}]*default\s*=\s*false')
        self.assertIn("analysis.tfstate", read("tofu/stacks/analysis/versions.tf"))
        self.assertRegex(read("tofu/stacks/analysis/versions.tf"), r"enforced\s*=\s*true")

    def test_the_all_order_never_builds_the_analysis_stack(self):
        sh = read("scripts/lab.sh")
        self.assertIn('ORDER="firewall elastic targets attacker gateway"', sh)
        self.assertIn('" $ORDER analysis "', sh)

    def test_only_the_analysis_token_gets_snapshot_rights(self):
        sh = read("scripts/bootstrap-proxmox.sh")
        self.assertRegex(sh, r'if \[ "\$stack" = analysis \]; then\s+pveum acl modify "/pool/\$pool" \$who --roles "\$SNAP_ROLE"')
        deploy = next(l for l in sh.splitlines() if l.startswith("PRIVS="))
        self.assertNotIn("Snapshot", deploy)

    def test_pve_client_has_rollback_but_still_no_delete_or_config(self):
        src = read("scripts/pve.py")
        self.assertIn("def rollback", src)
        self.assertNotIn("def delete", src)
        self.assertNotIn("def config", src)

    def test_analysis_hosts_are_audited_in_their_own_pool(self):
        self.assertIn('"analysis": "lab-analysis"', read("scripts/nicaudit.py"))

    def test_remnux_agent_is_left_unenrolled_by_the_role(self):
        tasks = read("ansible/roles/analysis_remnux/tasks/main.yml")
        self.assertNotIn("--enrollment-token", tasks)
        self.assertNotIn("--url", tasks)

    def test_no_secrets_in_the_analysis_role_or_runbook(self):
        for rel in ("ansible/roles/analysis_remnux/tasks/main.yml", "docs/runbooks/malware-analysis.md", "scripts/labops.py"):
            self.assertNotRegex(read(rel), r"(?i)password\s*[=:]\s*['\"]?[A-Za-z0-9]{12,}")


if __name__ == "__main__":
    unittest.main()
