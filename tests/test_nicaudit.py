import os
import sys
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import netpolicy  # noqa: E402
import nicaudit  # noqa: E402

PLAN = netpolicy.load_plan(os.path.join(ROOT, "network", "plan.json"))
FW = PLAN["firewall"]["vm_id"]


def vm(vmid, *bridges):
    return {"vmid": vmid, "name": "vm%d" % vmid, "config": {"net%d" % i: "virtio=BC:24:11:00:00:0%d,bridge=%s,firewall=0" % (i, b) for i, b in enumerate(bridges)}}


class NicAudit(unittest.TestCase):
    def test_firewall_on_home_and_lab_bridges_and_guests_on_one_lab_bridge_pass(self):
        vms = [vm(FW, "vmbr0", "vmbr2001", "vmbr2003", "vmbr2011", "vmbr2012"), vm(120, "vmbr2011"), vm(121, "vmbr2003")]
        self.assertEqual(nicaudit.audit(PLAN, vms), [])

    def test_a_guest_on_the_home_bridge_is_a_violation(self):
        bad = nicaudit.audit(PLAN, [vm(130, "vmbr2011", "vmbr0")])
        self.assertEqual(len(bad), 1)
        self.assertIn("home bridge", bad[0])

    def test_a_guest_on_two_lab_bridges_bypasses_the_firewall(self):
        bad = nicaudit.audit(PLAN, [vm(131, "vmbr2011", "vmbr2012")])
        self.assertTrue(any("more than one" in b for b in bad), bad)

    def test_a_guest_on_an_unknown_bridge_is_a_violation(self):
        self.assertTrue(nicaudit.audit(PLAN, [vm(132, "vmbr1000")]))

    def test_only_the_firewall_vm_may_have_a_home_nic(self):
        self.assertTrue(nicaudit.audit(PLAN, [vm(FW + 1, "vmbr0")]))

    def test_the_firewall_must_not_be_missing_a_zone_nic(self):
        bad = nicaudit.audit(PLAN, [vm(FW, "vmbr0", "vmbr2001")], require_firewall=True)
        self.assertTrue(any("missing" in b for b in bad), bad)

    def test_vlan_tagged_and_unusual_nic_lines_are_parsed(self):
        v = {"vmid": 140, "name": "x", "config": {"net0": "e1000=AA:BB:CC:DD:EE:FF,bridge=vmbr2011,tag=5", "memory": "512"}}
        self.assertEqual(nicaudit.bridges_of(v), ["vmbr2011"])


class InternetCanary(unittest.TestCase):
    def test_internet_probes_target_a_routable_address(self):
        import ipaddress
        self.assertTrue(ipaddress.ip_address(PLAN["hosts"]["internet"]["ip"]).is_global)


if __name__ == "__main__":
    unittest.main()
