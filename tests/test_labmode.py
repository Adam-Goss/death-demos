import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))
from fake_opnsense import Fake  # noqa: E402

T0 = 1_800_000_000


class LabMode(unittest.TestCase):
    def setUp(self):
        self.fw = Fake()
        self.state = tempfile.mkdtemp()

    def tearDown(self):
        self.fw.close()

    def run_cli(self, *args, now=T0, creds=True, **extra_env):
        env = dict(os.environ, LABMODE_STATE_DIR=self.state, LABMODE_NOW=str(now), OPNSENSE_URL=self.fw.url, **extra_env)
        if creds:
            env.update(OPNSENSE_API_KEY="k", OPNSENSE_API_SECRET="s")
        else:
            env.pop("OPNSENSE_API_KEY", None)
            env.pop("OPNSENSE_API_SECRET", None)
        return subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "labmode.py"), *args],
                              env=env, capture_output=True, text=True)

    def enabled(self, prefix):
        return {r["description"]: r["enabled"] for r in self.fw.rules.values()
                if r["description"].startswith("opaleye:" + prefix)}

    def audit(self):
        with open(os.path.join(self.state, "labmode.log")) as f:
            return [json.loads(line) for line in f]

    def state_json(self):
        with open(os.path.join(self.state, "labmode.json")) as f:
            return json.load(f)

    def test_exercise_enables_only_the_selected_target_rules(self):
        r = self.run_cli("exercise", "t1")
        self.assertEqual(r.returncode, 0, r.stderr)
        t1 = self.enabled("exercise-t1@lan")
        t2 = self.enabled("exercise-t2@lan")
        self.assertTrue(t1 and all(v == "1" for v in t1.values()))
        self.assertTrue(t2 and all(v == "0" for v in t2.values()))
        self.assertTrue(all(v == "0" for v in self.enabled("maint-updates").values()))

    def test_changes_go_through_savepoint_apply_then_confirm(self):
        self.run_cli("exercise", "t1")
        names = [n for n in self.fw.names() if n in ("savepoint", "apply", "cancelRollback")]
        self.assertEqual(names, ["savepoint", "apply", "cancelRollback"])

    def test_core_firewall_without_savepoint_is_refused_unless_explicitly_allowed(self):
        self.fw.core_only = True
        r = self.run_cli("exercise", "t1")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.fw.mutations(), [])
        self.assertFalse(os.path.exists(os.path.join(self.state, "labmode.json")))

    def test_core_firewall_applies_plainly_when_opted_in_and_warns(self):
        self.fw.core_only = True
        r = self.run_cli("exercise", "t1", OPNSENSE_NO_SAVEPOINT="true")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("no savepoint", r.stderr)
        self.assertIn("apply", self.fw.names())
        self.assertNotIn("cancelRollback", self.fw.names())
        self.assertTrue(all(v == "1" for v in self.enabled("exercise-t1@lan").values()))

    def test_unconfirmed_when_apply_fails_so_the_firewall_reverts(self):
        self.fw.fail_apply = True
        r = self.run_cli("exercise", "t1")
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("cancelRollback", self.fw.names())
        self.assertFalse(os.path.exists(os.path.join(self.state, "labmode.json")))

    def test_second_identical_run_changes_nothing(self):
        self.run_cli("exercise", "t1")
        self.fw.calls.clear()
        self.assertEqual(self.run_cli("exercise", "t1").returncode, 0)
        self.assertEqual(self.fw.mutations(), [])
        self.assertNotIn("apply", self.fw.names())

    def test_the_run_says_whether_it_changed_the_firewall(self):
        first = self.run_cli("exercise", "t1")
        second = self.run_cli("exercise", "t1")
        self.assertIn("applied", first.stdout)
        self.assertIn("no changes", second.stdout)

    def test_update_sources_alias_is_created_from_the_plan(self):
        self.run_cli("exercise", "t1")
        alias = next(iter(self.fw.aliases.values()))
        self.assertEqual(alias["name"], "opaleye_update_sources")
        self.assertIn("deb.debian.org", alias["content"])

    def test_maintenance_opens_updates_closes_exercise_and_is_logged(self):
        self.run_cli("exercise", "t1")
        r = self.run_cli("maintenance", "--minutes", "30", "--reason", "apt upgrade targets")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(all(v == "1" for v in self.enabled("maint-updates").values()))
        self.assertTrue(all(v == "0" for v in self.enabled("exercise-").values()))
        st = self.state_json()
        self.assertEqual((st["mode"], st["expires"]), ("maintenance", T0 + 1800))
        last = self.audit()[-1]
        self.assertEqual((last["event"], last["reason"], last["minutes"]), ("maintenance-on", "apt upgrade targets", 30))

    def test_maintenance_refuses_without_reason_or_beyond_the_limit(self):
        self.run_cli("exercise", "t1")
        self.fw.calls.clear()
        self.assertNotEqual(self.run_cli("maintenance", "--minutes", "30").returncode, 0)
        self.assertNotEqual(self.run_cli("maintenance", "--minutes", "121", "--reason", "x").returncode, 0)
        self.assertNotEqual(self.run_cli("maintenance", "--minutes", "0", "--reason", "x").returncode, 0)
        self.assertEqual(self.fw.mutations(), [])

    def test_maintenance_cannot_be_extended_by_calling_it_again(self):
        self.run_cli("exercise", "t1")
        self.run_cli("maintenance", "--minutes", "30", "--reason", "r")
        self.assertNotEqual(self.run_cli("maintenance", "--minutes", "30", "--reason", "again", now=T0 + 1700).returncode, 0)
        self.assertEqual(self.state_json()["expires"], T0 + 1800)

    def test_tick_leaves_maintenance_until_expiry_then_restores_exercise(self):
        self.run_cli("exercise", "t1")
        self.run_cli("maintenance", "--minutes", "30", "--reason", "r")
        self.run_cli("tick", now=T0 + 1799)
        self.assertEqual(self.state_json()["mode"], "maintenance")
        r = self.run_cli("tick", now=T0 + 1800)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.state_json()["mode"], "exercise")
        self.assertTrue(all(v == "0" for v in self.enabled("maint-updates").values()))
        self.assertEqual(self.audit()[-1]["event"], "maintenance-expired")

    def test_no_target_is_selectable_until_exercise_denies_are_reverified(self):
        self.run_cli("exercise", "t1")
        self.run_cli("maintenance", "--minutes", "5", "--reason", "r")
        self.run_cli("exercise")
        self.assertTrue(self.state_json()["reverify_required"])
        self.assertNotEqual(self.run_cli("select", "t1").returncode, 0)
        self.assertTrue(all(v == "0" for v in self.enabled("exercise-").values()))
        self.assertEqual(self.run_cli("reverified").returncode, 0)
        self.assertEqual(self.run_cli("select", "t2").returncode, 0)
        self.assertTrue(all(v == "1" for v in self.enabled("exercise-t2@lan").values()))

    def test_denylog_reports_whether_the_firewall_logged_the_block(self):
        row = {"action": "block", "src": "10.77.11.10", "dst": "10.77.12.10", "dstport": "80", "interface": "opt2"}
        self.assertNotEqual(self.run_cli("denylog", "10.77.11.10", "10.77.12.10", "80").returncode, 0)
        self.fw.log.append(row)
        self.assertEqual(self.run_cli("denylog", "10.77.11.10", "10.77.12.10", "80").returncode, 0)
        self.assertNotEqual(self.run_cli("denylog", "10.77.11.10", "10.77.12.10", "22").returncode, 0)

    def test_denylog_with_a_baseline_ignores_blocks_logged_before_the_mark(self):
        base = os.path.join(self.state, "baseline")
        old = {"action": "block", "src": "10.77.11.10", "dst": "10.77.12.10", "dstport": "80", "__digest__": "aaa"}
        self.fw.log.append(old)
        self.assertEqual(self.run_cli("logmark", base).returncode, 0)
        self.assertNotEqual(self.run_cli("denylog", "10.77.11.10", "10.77.12.10", "80", LABMODE_LOG_BASELINE=base).returncode, 0)
        self.fw.log.append(dict(old, __digest__="bbb"))
        self.assertEqual(self.run_cli("denylog", "10.77.11.10", "10.77.12.10", "80", LABMODE_LOG_BASELINE=base).returncode, 0)

    def test_wgv4only_passes_only_when_the_peer_routes_no_ipv6(self):
        peer = {"type": "peer", "name": "workstation", "endpoint": "192.168.0.223:51490", "allowed-ips": "10.77.9.2/32"}
        self.assertNotEqual(self.run_cli("wgv4only", "workstation").returncode, 0)  # no such peer
        self.fw.wg_rows = [dict(peer)]
        self.assertEqual(self.run_cli("wgv4only", "workstation").returncode, 0)
        self.fw.wg_rows = [dict(peer, **{"allowed-ips": "10.77.9.2/32,fd00::2/128"})]
        self.assertNotEqual(self.run_cli("wgv4only", "workstation").returncode, 0)

    def test_wgpeer_accepts_only_a_fresh_handshake_from_the_expected_source(self):
        peer = {"type": "peer", "name": "workstation", "endpoint": "192.168.0.223:51490", "latest-handshake-age": 112}
        args = ("wgpeer", "workstation", "192.168.0.223")
        self.assertNotEqual(self.run_cli(*args).returncode, 0)  # no peers at all
        self.fw.wg_rows = [dict(peer)]
        self.assertEqual(self.run_cli(*args).returncode, 0)
        self.fw.wg_rows = [dict(peer, **{"latest-handshake-age": 400})]
        self.assertNotEqual(self.run_cli(*args).returncode, 0)  # stale
        self.fw.wg_rows = [dict(peer, **{"latest-handshake-age": None})]
        self.assertNotEqual(self.run_cli(*args).returncode, 0)  # never shook hands
        self.fw.wg_rows = [dict(peer, endpoint="192.168.0.50:51490")]
        self.assertNotEqual(self.run_cli(*args).returncode, 0)  # wrong source address

    def test_refuses_without_credentials(self):
        r = self.run_cli("exercise", "t1", creds=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.fw.calls, [])


if __name__ == "__main__":
    unittest.main()
