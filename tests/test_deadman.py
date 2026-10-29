import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts", "firewall"))
import opaleye_deadman as dm  # noqa: E402

CFG = """<opnsense><OPNsense><Firewall><Alias><aliases>
<alias uuid="1"><name>opaleye_pending</name><description>%s</description></alias>
<alias uuid="2"><name>opaleye_confirmed</name><description>%s</description></alias>
</aliases></Alias></Firewall></OPNsense><marker>%s</marker></opnsense>"""


class Deadman(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        self.cfg, self.state = os.path.join(d, "config.xml"), os.path.join(d, "state")
        self.reloaded = []

    def write(self, pending, confirmed, marker):
        with open(self.cfg, "w") as f:
            f.write(CFG % (pending, confirmed, marker))

    def run_at(self, now):
        # reload commands are recorded, not run
        out = dm.run(self.cfg, self.state, 120, now, [])
        return out

    def marker(self):
        return dm.ET.parse(self.cfg).getroot().findtext("marker")

    def test_confirmed_config_is_saved_as_the_restore_point(self):
        self.write("a", "a", "good")
        self.assertEqual(self.run_at(1000), "confirmed")
        self.write("a", "a", "good2")
        self.run_at(1060)
        with open(os.path.join(self.state, "confirmed.xml")) as f:
            self.assertIn("good2", f.read())

    def test_unconfirmed_push_is_left_alone_inside_the_grace_period(self):
        self.write("a", "a", "good")
        self.run_at(1000)
        self.write("b", "a", "bad")
        self.assertEqual(self.run_at(1060), "pending")
        self.assertEqual(self.run_at(1179), "pending")
        self.assertEqual(self.marker(), "bad")

    def test_unconfirmed_push_is_reverted_after_the_grace_period_and_filter_reloaded(self):
        self.write("a", "a", "good")
        self.run_at(1000)
        self.write("b", "a", "bad")
        self.run_at(1060)
        calls = []
        orig = dm.subprocess.run
        dm.subprocess.run = lambda cmd, **kw: calls.append(cmd)
        try:
            self.assertEqual(dm.run(self.cfg, self.state, 120, 1180, ["configctl filter reload"]), "reverted")
        finally:
            dm.subprocess.run = orig
        self.assertEqual(self.marker(), "good")
        self.assertEqual(calls, [["configctl", "filter", "reload"]])

    def test_failed_reload_is_retried_before_another_config_is_saved(self):
        self.write("a", "a", "good")
        self.run_at(1000)
        self.write("b", "a", "bad")
        self.run_at(1060)
        with patch.object(dm.subprocess, "run", side_effect=dm.subprocess.CalledProcessError(1, "reload")):
            with self.assertRaises(dm.subprocess.CalledProcessError):
                dm.run(self.cfg, self.state, 120, 1180, ["configctl filter reload"])
        with patch.object(dm.subprocess, "run") as reload:
            self.assertEqual(dm.run(self.cfg, self.state, 120, 1240, ["configctl filter reload"]), "reverted")
            reload.assert_called_once_with(["configctl", "filter", "reload"], check=True)
        self.assertEqual(self.marker(), "good")

    def test_the_bad_config_never_becomes_the_restore_point(self):
        self.write("a", "a", "good")
        self.run_at(1000)
        self.write("b", "a", "bad")
        self.run_at(1060)
        self.run_at(1120)
        with open(os.path.join(self.state, "confirmed.xml")) as f:
            self.assertIn("good", f.read())

    def test_confirming_in_time_keeps_the_push(self):
        self.write("a", "a", "good")
        self.run_at(1000)
        self.write("b", "a", "new")
        self.run_at(1060)
        self.write("b", "b", "new")
        self.assertEqual(self.run_at(1200), "confirmed")
        self.assertEqual(self.marker(), "new")

    def test_a_new_unconfirmed_token_restarts_the_clock(self):
        self.write("a", "a", "good")
        self.run_at(1000)
        self.write("b", "a", "bad1")
        self.run_at(1060)
        self.write("c", "a", "bad2")
        self.assertEqual(self.run_at(1170), "pending")

    def test_without_markers_nothing_is_touched(self):
        with open(self.cfg, "w") as f:
            f.write("<opnsense><marker>x</marker></opnsense>")
        self.assertEqual(self.run_at(1000), "unarmed")
        self.assertEqual(self.marker(), "x")

    def test_unreadable_config_is_skipped(self):
        with open(self.cfg, "w") as f:
            f.write("<opnsense><half")
        self.assertEqual(self.run_at(1000), "unarmed")

    def test_no_restore_point_means_no_revert(self):
        self.write("b", "a", "bad")
        self.run_at(1000)
        self.assertEqual(self.run_at(1200), "no-backup")
        self.assertEqual(self.marker(), "bad")


if __name__ == "__main__":
    unittest.main()
