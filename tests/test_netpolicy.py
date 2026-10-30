import json, os, sys, unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import netpolicy  # noqa: E402

PLAN = netpolicy.load_plan(os.path.join(ROOT, "network", "plan.json"))


def verdicts(mode, selected):
    rules = netpolicy.render_rules(PLAN, mode, selected)
    return {p["id"]: netpolicy.evaluate(PLAN, rules, p) for p in netpolicy.matrix(PLAN, mode, selected)}


class RulesMatchProbeMatrix(unittest.TestCase):
    def test_exercise_rules_give_every_probe_its_expected_verdict(self):
        self.assertEqual(netpolicy.lint(PLAN, "exercise", "t1"), [])

    def test_maintenance_rules_give_every_probe_its_expected_verdict(self):
        self.assertEqual(netpolicy.lint(PLAN, "maintenance", None), [])

    def test_only_the_selected_target_is_reachable_from_attacker(self):
        v = verdicts("exercise", "t1")
        self.assertEqual((v["p01"], v["p03"]), ("allow", "deny"))
        rules = netpolicy.render_rules(PLAN, "exercise", "t2")
        probe = {"src": "attacker", "dst": "t2", "proto": "tcp", "port": 80}
        self.assertEqual(netpolicy.evaluate(PLAN, rules, probe), "allow")
        probe["dst"] = "t1"
        self.assertEqual(netpolicy.evaluate(PLAN, rules, probe), "deny")

    def test_only_targets_reach_the_ingestion_ports_never_the_attacker(self):
        for mode, sel in (("exercise", "t1"), ("maintenance", None)):
            rules = netpolicy.render_rules(PLAN, mode, sel)
            for port in (9200, 8220):
                for src, want in (("t1", "allow"), ("t2", "allow"), ("attacker", "deny")):
                    probe = {"src": src, "dst": "elastic", "proto": "tcp", "port": port}
                    self.assertEqual(netpolicy.evaluate(PLAN, rules, probe), want, (mode, src, port))

    def test_exercise_with_no_target_selected_denies_attacker_to_every_target(self):
        self.assertEqual(netpolicy.lint(PLAN, "exercise", None), [])
        row = next(r for r in netpolicy.matrix(PLAN, "exercise", None) if r["id"] == "p01")
        self.assertEqual(row["expected"], "deny")

    def test_exercise_with_t2_selected_allows_t2_and_denies_t1(self):
        self.assertEqual(netpolicy.lint(PLAN, "exercise", "t2"), [])
        rows = {r["id"]: r["expected"] for r in netpolicy.matrix(PLAN, "exercise", "t2")}
        self.assertEqual((rows["p01"], rows["p03"]), ("deny", "allow"))

    def test_lint_catches_an_overpermissive_rule(self):
        rules = netpolicy.render_rules(PLAN, "exercise", "t1")
        rules.insert(0, {"id": "oops", "iface": "opt2", "action": "pass", "family": "inet", "proto": "tcp",
                         "src": "10.77.11.0/24", "dst": "10.77.12.0/24", "ports": [80], "enabled": True, "log": False})
        bad = netpolicy.lint(PLAN, "exercise", "t1", rules=rules)
        self.assertTrue(any("p04" in b for b in bad), bad)


class GuacamoleGateway(unittest.TestCase):
    def verdict(self, mode, sel, src, dst, port):
        rules = netpolicy.render_rules(PLAN, mode, sel)
        return netpolicy.evaluate(PLAN, rules, {"src": src, "dst": dst, "proto": "tcp", "port": port})

    def test_gateway_flows_in_both_modes(self):
        for mode, sel in (("exercise", "t1"), ("exercise", None), ("maintenance", None)):
            for src, dst, port, want in (
                    ("operator", "gateway", 443, "allow"), ("workstation", "gateway", 443, "deny"),
                    ("attacker", "gateway", 443, "deny"), ("t1", "gateway", 443, "deny"),
                    ("gateway", "attacker", 3389, "allow"), ("gateway", "attacker", 22, "deny"),
                    ("gateway", "t1", 22, "allow"), ("gateway", "t2", 22, "allow"), ("gateway", "t1", 80, "deny"),
                    ("gateway", "elastic", 22, "deny"), ("gateway", "elastic", 5601, "deny"),
                    ("operator", "attacker", 3389, "deny")):
                self.assertEqual(self.verdict(mode, sel, src, dst, port), want, (mode, sel, src, dst, port))

    def test_gateway_has_no_internet_in_exercise_mode_only_updates_in_maintenance(self):
        rows = {r["id"]: r["expected"] for r in netpolicy.matrix(PLAN, "maintenance", None)}
        self.assertEqual(rows["p71"], "allow")
        self.assertEqual(rows["p68"], "deny")
        rows = {r["id"]: r["expected"] for r in netpolicy.matrix(PLAN, "exercise", "t1")}
        self.assertEqual(rows["p71"], "deny")

    def test_gateway_is_not_on_the_home_bridge_and_has_its_own_zone(self):
        self.assertEqual(PLAN["hosts"]["gateway"]["zone"], "gateway")
        self.assertNotEqual(PLAN["zones"]["gateway"]["bridge"], PLAN["zones"]["home"]["bridge"])
        self.assertEqual(PLAN["nic_order"][-2:], ["gateway", "analysis"])


class AnalysisZone(unittest.TestCase):
    """#52: isolated analysis zone; Internet only while the operator toggle is on."""

    def verdict(self, mode, sel, online, src, dst, port, proto="tcp"):
        rules = netpolicy.render_rules(PLAN, mode, sel, online)
        return netpolicy.evaluate(PLAN, rules, {"src": src, "dst": dst, "proto": proto, "port": port})

    def test_rules_match_the_probe_matrix_in_every_mode_and_toggle_state(self):
        for mode, sel in (("exercise", "t1"), ("exercise", None), ("maintenance", None)):
            for online in (False, True):
                self.assertEqual(netpolicy.lint(PLAN, mode, sel, online=online), [], (mode, sel, online))

    def test_only_the_gateway_initiates_into_the_zone(self):
        for mode, sel in (("exercise", "t1"), ("maintenance", None)):
            for online in (False, True):
                for src, dst, port, want in (
                        ("gateway", "flare", 3389, "allow"), ("gateway", "remnux", 22, "allow"),
                        ("gateway", "remnux", 3389, "deny"),
                        ("operator", "flare", 3389, "deny"), ("operator", "remnux", 22, "deny"),
                        ("attacker", "flare", 3389, "deny"), ("t1", "remnux", 22, "deny"), ("elastic", "flare", 3389, "deny")):
                    self.assertEqual(self.verdict(mode, sel, online, src, dst, port), want, (mode, online, src, dst, port))

    def test_zone_reaches_no_lab_or_home_host_in_either_state(self):
        for online in (False, True):
            for dst, port in (("attacker", 22), ("t1", 80), ("t2", 80), ("gateway", 443), ("proxmox", 8006), ("proxmox", 22),
                              ("home_router", 80), ("workstation", 445), ("elastic", 5601), ("elastic", 22), ("fw", 443), ("fw", 22)):
                for src in ("flare", "remnux"):
                    self.assertEqual(self.verdict("exercise", "t1", online, src, dst, port), "deny", (online, src, dst, port))

    def test_zone_reaches_only_the_ingestion_ports_on_elastic(self):
        for online in (False, True):
            for src in ("flare", "remnux"):
                for port, want in ((9200, "allow"), (8220, "allow"), (5601, "deny")):
                    self.assertEqual(self.verdict("exercise", None, online, src, "elastic", port), want)

    def test_internet_is_off_by_default_and_on_only_when_toggled(self):
        for src in ("flare", "remnux"):
            self.assertEqual(self.verdict("exercise", None, False, src, "internet", 443), "deny")
            self.assertEqual(self.verdict("exercise", None, True, src, "internet", 443), "allow")
        self.assertEqual(self.verdict("exercise", None, False, "flare", "fw", 53, "udp"), "deny")
        self.assertEqual(self.verdict("exercise", None, True, "flare", "fw", 53, "udp"), "allow")

    def test_online_rules_are_present_but_disabled_when_offline(self):
        off = {r["id"]: r["enabled"] for r in netpolicy.render_rules(PLAN, "exercise", None, False)}
        on = {r["id"]: r["enabled"] for r in netpolicy.render_rules(PLAN, "exercise", None, True)}
        key = "analysis-internet@opt6@flare"
        self.assertEqual((off[key], on[key]), (False, True))

    def test_private_ranges_are_blocked_before_the_internet_allow(self):
        rules = [r for r in netpolicy.render_rules(PLAN, "exercise", None, True) if r["iface"] == "opt6"]
        ids = [r["id"] for r in rules]
        allow = ids.index("analysis-internet@opt6@flare")
        for r in PLAN["analysis"]["private_ranges"]:
            blk = next(i for i, x in enumerate(rules) if x["action"] == "block" and x["dst"] == r and x["src"].startswith("10.77.20.10"))
            self.assertLess(blk, allow)
            self.assertTrue(rules[blk]["enabled"] and rules[blk]["log"])
        self.assertTrue(rules[allow]["log"])

    def test_internet_flows_are_logged(self):
        for r in netpolicy.render_rules(PLAN, "exercise", None, True):
            if r["id"].startswith("analysis-internet"):
                self.assertTrue(r["log"])

    def test_zone_has_its_own_bridge_and_both_vms_share_it(self):
        self.assertEqual(PLAN["hosts"]["flare"]["zone"], PLAN["hosts"]["remnux"]["zone"], "analysis")
        self.assertNotEqual(PLAN["zones"]["analysis"]["bridge"], PLAN["zones"]["home"]["bridge"])
        self.assertEqual(netpolicy.plan_errors(PLAN), [])


class MatrixShape(unittest.TestCase):
    def test_rows_carry_evidence_fields(self):
        row = netpolicy.matrix(PLAN, "exercise", "t1")[0]
        for k in ("id", "src", "dst", "proto", "port", "mode", "expected", "enforcement", "family"):
            self.assertIn(k, row)

    def test_ipv6_is_probed_from_every_zone_and_expected_absent(self):
        v6 = [r for r in netpolicy.matrix(PLAN, "exercise", "t1") if r["family"] == "inet6"]
        self.assertEqual({r["src"] for r in v6}, {"attacker", "elastic", "t1", "t2", "gateway", "flare", "operator", "workstation"})
        self.assertTrue(all(r["expected"] == "deny" and r["kind"] == "no-ipv6" for r in v6))


class OperatorReach(unittest.TestCase):
    def test_every_lab_probe_vantage_is_reachable_by_the_operator_over_ssh(self):
        rules = netpolicy.render_rules(PLAN, "exercise", "t1")
        for h in ("attacker", "elastic", "t1", "t2"):
            self.assertEqual(netpolicy.evaluate(PLAN, rules, {"src": "operator", "dst": h, "proto": "tcp", "port": 22}), "allow", h)


class ProbeAddresses(unittest.TestCase):
    def row(self, pid):
        return next(r for r in netpolicy.matrix(PLAN, "exercise", "t1") if r["id"] == pid)

    def test_firewall_destination_is_the_gateway_of_the_source_zone(self):
        self.assertEqual(self.row("p24")["dst_ip"], "10.77.11.1")
        self.assertEqual(self.row("p35")["dst_ip"], "10.77.9.1")
        self.assertEqual(self.row("p46")["dst_ip"], "10.77.1.1")
        self.assertEqual(self.row("p47")["expected"], "deny")

    def test_firewall_destination_from_the_home_side_is_its_wan_address(self):
        self.assertEqual(self.row("p39")["dst_ip"], PLAN["firewall"]["wan_ip"])

    def test_hosts_resolve_to_plan_addresses_and_update_sources_are_resolved_at_run_time(self):
        r = self.row("p04")
        self.assertEqual((r["src_ip"], r["dst_ip"]), ("10.77.11.10", "10.77.12.10"))
        self.assertEqual(self.row("p10")["dst_ip"], "UPDATE_SOURCE")


class RuleSetInvariants(unittest.TestCase):
    def test_every_interface_ends_in_logged_block_all(self):
        rules = netpolicy.render_rules(PLAN, "exercise", "t1")
        for z in PLAN["zones"].values():
            mine = [r for r in rules if r["iface"] == z["iface"]]
            self.assertTrue(mine, z)
            self.assertEqual((mine[-1]["action"], mine[-1]["src"], mine[-1]["dst"], mine[-1]["log"]), ("block", "any", "any", True))

    def test_ipv6_blocked_and_logged_on_every_interface(self):
        rules = netpolicy.render_rules(PLAN, "exercise", "t1")
        for z in PLAN["zones"].values():
            self.assertTrue(any(r["iface"] == z["iface"] and r["family"] == "inet6" and r["action"] == "block" and r["log"] for r in rules))

    def test_maintenance_never_opens_target_to_target_or_management(self):
        rules = netpolicy.render_rules(PLAN, "maintenance", None)
        for r in rules:
            if r["enabled"] and r["action"] == "pass":
                self.assertNotIn(r["dst"], ("any", "192.168.0.0/24"))


class PlanSanity(unittest.TestCase):
    def test_bridges_unique_and_only_firewall_zone_uses_home_bridge(self):
        errs = netpolicy.plan_errors(PLAN)
        self.assertEqual(errs, [])
        bad = json.loads(json.dumps(PLAN)); bad["zones"]["t1"]["bridge"] = PLAN["zones"]["home"]["bridge"]
        self.assertTrue(netpolicy.plan_errors(bad))

    def test_zone_cidrs_do_not_overlap_each_other_or_ludus(self):
        bad = json.loads(json.dumps(PLAN)); bad["zones"]["t2"]["cidr"] = "10.1.4.0/24"
        self.assertTrue(netpolicy.plan_errors(bad))


class BridgeStanzas(unittest.TestCase):
    def test_lab_bridges_are_isolated_and_exclude_home_bridge(self):
        text = netpolicy.bridge_stanzas(PLAN)
        self.assertNotIn("iface vmbr0", text)
        for name in ("vmbr2001", "vmbr2002", "vmbr2003", "vmbr2011", "vmbr2012", "vmbr2020"):
            self.assertIn("iface %s inet manual" % name, text)
        self.assertEqual(text.count("bridge-ports none"), 6)
        self.assertNotIn("address", text)


if __name__ == "__main__":
    unittest.main()
