"""Workstation timers as one unit (scripts/ops-timers.sh): install, status, stale detection, the lab.sh hook."""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "scripts"))
from labcommon import BASH  # noqa: E402

TAGS = ("opaleye-labmode-tick", "opaleye-firewall-flow", "opaleye-elastic-tunnel")


class OpsTimers(unittest.TestCase):
    def setUp(self):
        # A scratch copy of the scripts, so each test has its own "checkout" (the tag lines name the directory).
        self.repo = pathlib.Path(tempfile.mkdtemp()) / "checkout"
        shutil.copytree(ROOT / "scripts", self.repo / "scripts", ignore=shutil.ignore_patterns("__pycache__", "firewall"))
        (self.repo / "secrets").mkdir()
        (self.repo / "secrets" / "env.sh").write_text("# test env\n")
        self.cron = pathlib.Path(tempfile.mkdtemp()) / "crontab"
        self.env = dict(os.environ, CRON_FILE=str(self.cron),
                        CRONTAB="%s %s" % (pathlib.Path(sys.executable).as_posix(), (HERE / "stub_crontab.py").as_posix()))

    def sh(self, *args, repo=None):
        script = ((repo or self.repo) / "scripts" / "ops-timers.sh").as_posix()
        return subprocess.run([BASH, script, *args], env=self.env, capture_output=True, text=True)

    def table(self):
        return self.cron.read_text() if self.cron.exists() else ""

    def test_install_adds_all_three_timers_for_this_checkout(self):
        r = self.sh("install")
        self.assertEqual(r.returncode, 0, r.stderr)
        table = self.table()
        for tag in TAGS:
            self.assertEqual(table.count("# " + tag), 1, tag)
        for line in table.splitlines():
            self.assertIn("/checkout", line)  # every line runs in this checkout
        self.assertIn("labmode.py tick", table)
        self.assertIn("firewall_flow.py", table)
        self.assertIn("tunnel-keepalive.sh", table)

    def test_install_is_idempotent_and_keeps_other_entries(self):
        self.cron.write_text("0 3 * * * backup.sh\n")
        self.sh("install")
        once = self.table()
        self.sh("install")
        self.assertEqual(self.table(), once)
        self.assertIn("0 3 * * * backup.sh", once)

    def test_status_is_ok_after_install_and_reports_each_timer(self):
        self.sh("install")
        r = self.sh("status")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for tag in TAGS:
            self.assertIn("ok " + tag, r.stdout)

    def test_status_reports_missing_timers(self):
        r = self.sh("status")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout.count("MISSING"), 3)

    def test_status_flags_lines_pointing_at_a_directory_that_no_longer_exists(self):
        # The failure that stopped the firewall logs: the lines named a removed checkout.
        self.cron.write_text("".join("* * * * * cd '/nonexistent/old' && true # %s\n" % t for t in TAGS))
        r = self.sh("status")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout.count("STALE"), 3)
        self.assertIn("/nonexistent/old", r.stdout)

    def test_install_from_the_new_checkout_replaces_stale_lines(self):
        self.cron.write_text("".join("* * * * * cd '/nonexistent/old' && true # %s\n" % t for t in TAGS))
        self.assertEqual(self.sh("install").returncode, 0)
        self.assertNotIn("/nonexistent/old", self.table())
        self.assertEqual(self.sh("status").returncode, 0)

    def test_status_flags_timers_installed_from_another_live_checkout(self):
        other = pathlib.Path(tempfile.mkdtemp()) / "other"
        shutil.copytree(self.repo, other)
        self.sh("install", repo=other)
        r = self.sh("status")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout.count("OTHER-CHECKOUT"), 3)

    def test_remove_takes_only_the_lab_timers(self):
        self.cron.write_text("0 3 * * * backup.sh\n")
        self.sh("install")
        self.assertEqual(self.sh("remove").returncode, 0)
        table = self.table()
        self.assertEqual(table.strip(), "0 3 * * * backup.sh")

    def test_install_needs_the_env_file_for_the_timers_that_read_it(self):
        (self.repo / "secrets" / "env.sh").unlink()
        r = self.sh("install")
        self.assertEqual(r.returncode, 1)
        self.assertIn("missing secrets/env.sh", r.stderr)

    def test_unknown_command_is_refused(self):
        self.assertEqual(self.sh("bogus").returncode, 2)


class Hooks(unittest.TestCase):
    def test_lab_sh_installs_the_timers_after_a_full_apply_and_never_fails_it(self):
        text = (ROOT / "scripts" / "lab.sh").read_text()
        self.assertIn('[ "$cmd" = apply ] && [ "$target" = all ]', text)
        self.assertIn("ops-timers.sh install ||", text)

    def test_the_setup_skill_is_user_invoked_and_names_only_files_that_exist(self):
        import re
        text = (ROOT / ".claude" / "skills" / "lab-workstation-setup" / "SKILL.md").read_text(encoding="utf-8")
        head = text.split("---")[1]
        self.assertIn("name: lab-workstation-setup", head)
        self.assertIn("disable-model-invocation: true", head)  # it edits the crontab: only the operator starts it
        for path in set(re.findall(r"(?:scripts|docs)/[\w./-]+\.(?:sh|py|md)", text)):
            self.assertTrue((ROOT / path).exists(), path)

    def test_the_runbooks_describe_the_known_issue_and_the_skill(self):
        ops = (ROOT / "docs" / "runbooks" / "ops-timers.md").read_text(encoding="utf-8")
        self.assertIn("/lab-workstation-setup", ops)
        self.assertIn("Known issue", ops)
        self.assertIn("ops-timers.md", (ROOT / "docs" / "runbooks" / "malware-analysis.md").read_text(encoding="utf-8"))

    def test_the_tunnel_script_runs_unattended(self):
        text = (ROOT / "scripts" / "elastic-tunnel.sh").read_text()
        for opt in ("BatchMode=yes", "ServerAliveInterval=30", "ExitOnForwardFailure=yes"):
            self.assertIn(opt, text)

    def test_keepalive_is_silent_when_the_tunnel_is_up_and_single_instance_otherwise(self):
        text = (ROOT / "scripts" / "tunnel-keepalive.sh").read_text()
        self.assertIn("/dev/tcp/127.0.0.1/19200", text)
        self.assertIn("flock -n .state/tunnel.lock", text)


if __name__ == "__main__":
    unittest.main()
