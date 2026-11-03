"""Firewall flow shipping (scripts/firewall_flow.py): exercise targets keep their generations; analysis hosts (#52) are shipped by address."""
import json
import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
firewall_flow = None


def setUpModule():
    global firewall_flow
    try:
        import firewall_flow as module  # the shipper uses fcntl (Linux/WSL only)
    except ImportError as e:
        raise unittest.SkipTest("firewall_flow needs Linux: %s" % e)
    firewall_flow = module

PLAN = json.load(open(os.path.join(ROOT, "network/plan.json")))
T1 = PLAN["hosts"]["t1"]["ip"]
REMNUX, FLARE = PLAN["hosts"]["remnux"]["ip"], PLAN["hosts"]["flare"]["ip"]
TARGETS = {"t1": {"ip": T1, "generations": [{"generation": 2, "since": "2026-01-01T00:00:00Z"}]}}


def row(src, dst, digest="d1", action="block", when="2026-11-03T08:00:00"):
    return {"__timestamp__": when, "__digest__": digest, "__host__": "fw", "action": action, "src": src, "dst": dst,
            "srcport": "40000", "dstport": "22", "protoname": "tcp", "label": "deny-all", "rid": "r1"}


class Events(unittest.TestCase):
    def ship(self, rows, analysis=True):
        return list(firewall_flow.events(rows, TARGETS, "now", firewall_flow.analysis_hosts(PLAN) if analysis else None))

    def test_analysis_hosts_come_from_the_plan(self):
        self.assertEqual(firewall_flow.analysis_hosts(PLAN), {"flare": FLARE, "remnux": REMNUX})

    def test_a_blocked_flow_from_an_analysis_host_is_shipped_with_its_zone(self):
        (identity, doc), = self.ship([row(REMNUX, "10.77.1.10")])
        self.assertEqual(doc["lab"], {"zone": "analysis", "host_id": "remnux"})
        self.assertEqual((doc["source"]["ip"], doc["destination"]["ip"], doc["destination"]["port"]), (REMNUX, "10.77.1.10", 22))
        self.assertEqual(doc["event"]["action"], "block")
        self.assertNotIn("rebuild_generation", doc["lab"])  # analysis hosts have no generation registry

    def test_traffic_to_an_analysis_host_is_shipped_too(self):
        (_, doc), = self.ship([row("10.77.2.10", FLARE, action="pass")])
        self.assertEqual(doc["lab"]["host_id"], "flare")

    def test_target_flows_keep_their_generation_and_are_not_tagged_with_a_zone(self):
        (_, doc), = self.ship([row("10.77.1.10", T1)])
        self.assertEqual(doc["lab"], {"target_id": "t1", "rebuild_generation": 2})

    def test_a_flow_between_a_target_and_an_analysis_host_is_shipped_once_per_side_with_distinct_ids(self):
        out = self.ship([row(T1, REMNUX)])
        self.assertEqual(len(out), 2)
        self.assertEqual(len({i for i, _ in out}), 2)

    def test_unrelated_flows_are_not_shipped(self):
        self.assertEqual(self.ship([row("10.77.1.10", "192.168.0.161")]), [])

    def test_without_analysis_hosts_nothing_changes(self):
        self.assertEqual(self.ship([row(REMNUX, "10.77.1.10")], analysis=False), [])

    def test_the_same_row_has_a_stable_identity(self):
        a = self.ship([row(REMNUX, "10.77.1.10")])
        b = self.ship([row(REMNUX, "10.77.1.10")])
        self.assertEqual(a[0][0], b[0][0])


if __name__ == "__main__":
    unittest.main()
