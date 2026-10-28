import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import nicaudit  # noqa: E402
import netpolicy  # noqa: E402
import v6probe  # noqa: E402

PLAN = netpolicy.load_plan(os.path.join(ROOT, "network", "plan.json"))
FW_MAC = "BC:24:11:AA:BB:CC"
NEIGH_ROUTER = "fe80::1 dev eth0 lladdr 10:20:30:40:50:60 router REACHABLE\n"


class NeighborVerdict(unittest.TestCase):
    def test_firewall_answering_the_all_nodes_ping_means_ipv6_is_alive(self):
        text = NEIGH_ROUTER + "fe80::be24:11ff:feaa:bbcc dev eth0 lladdr bc:24:11:aa:bb:cc STALE\n"
        self.assertEqual(v6probe.verdict(text, FW_MAC), "allow")

    def test_other_neighbors_answering_but_not_the_firewall_is_a_deny(self):
        self.assertEqual(v6probe.verdict(NEIGH_ROUTER, FW_MAC), "deny")

    def test_no_neighbor_at_all_proves_nothing(self):
        self.assertEqual(v6probe.verdict("", FW_MAC), "ERROR")


class WanMac(unittest.TestCase):
    def test_wan_mac_is_the_first_nic_of_the_firewall_vm(self):
        vms = [{"vmid": 2100, "name": "tpl", "config": {"net0": "virtio=AA:AA:AA:AA:AA:AA,bridge=vmbr2001"}},
               {"vmid": 2000, "name": "fw", "config": {"net1": "virtio=11:11:11:11:11:11,bridge=vmbr2001",
                                                     "net0": "virtio=" + FW_MAC + ",bridge=vmbr0,firewall=0"}}]
        self.assertEqual(nicaudit.wan_mac(PLAN, vms), FW_MAC)


class V6Rows(unittest.TestCase):
    def test_ipv6_is_also_probed_from_the_vpn_and_home_side(self):
        v6 = {r["src"]: r for r in netpolicy.matrix(PLAN, "exercise", "t1") if r["family"] == "inet6"}
        for h in ("operator", "workstation"):
            self.assertEqual((v6[h]["expected"], v6[h]["kind"]), ("deny", "no-ipv6"), h)


if __name__ == "__main__":
    unittest.main()
