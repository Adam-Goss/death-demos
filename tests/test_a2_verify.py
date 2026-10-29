"""A2 verifier CLI: incomplete evidence must not clear the maintenance gate."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent


@unittest.skipIf(os.name == "nt", "run the Bash verifier tests under WSL/Linux")
class VerifyCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.marker = self.directory / "reverified"
        self.baseline = self.directory / "baseline-path"
        self.python = self.directory / "python"
        self.python.write_text('''#!/usr/bin/env python3
import os
from pathlib import Path
import subprocess
import sys

args = sys.argv[1:]
if args[0] == "scripts/netpolicy.py":
    if args[1] == "matrix":
        if os.environ.get("MATRIX_FAIL"):
            sys.exit(1)
        if os.environ.get("ALIAS_REFRESH"):
            print("p01\\tattacker\\tupdate_source\\ttcp\\t443\\ttcp\\tinet\\texercise\\tallow\\tfirewall\\t10.77.1.10\\tUPDATE_SOURCE")
        else:
            print("p01\\tattacker\\tt1\\ttcp\\t80\\ttcp\\tinet\\texercise\\tallow\\tfirewall\\t10.77.1.10\\t10.77.11.10")
        print("p02\\telastic\\tinternet\\ttcp\\t443\\ttcp\\tinet\\texercise\\tdeny\\tfirewall\\t10.77.3.10\\t1.1.1.1")
    sys.exit(0)
if args[0] == "scripts/labmode.py":
    if args[1] == "logmark":
        Path(os.environ["BASELINE_PATH"]).write_text(args[2])
    if args[1] == "reverified":
        if os.environ.get("RECORD_FAIL"):
            sys.exit(1)
        Path(os.environ["REVERIFIED_PATH"]).touch()
    sys.exit(0)
sys.exit(subprocess.call([sys.executable, *args]))
''')
        self.python.chmod(0o755)
        self.ssh = self.directory / "ssh"
        self.ssh.write_text('''#!/usr/bin/env python3
import os
import sys
from pathlib import Path
if sys.argv[-1] == "true":
    sys.exit(0)
if "getent ahostsv4" in sys.argv[-1]:
    print("198.51.100.10")
    sys.exit(0)
if os.environ.get("ALIAS_REFRESH") and "198.51.100.10" in sys.argv[-1]:
    counter = Path(os.environ["PROBE_COUNT_PATH"])
    count = int(counter.read_text()) + 1 if counter.exists() else 1
    counter.write_text(str(count))
    # The alias refresh arrives after the former six-attempt retry window.
    print("rc=124" if count < 7 else "rc=0")
    sys.exit(0)
if os.environ.get("PROBE_FAIL"):
    print("rc=124")
else:
    print("rc=124" if "10.77.3.10" in sys.argv[1] else "rc=0")
''')
        self.ssh.chmod(0o755)
        sleep = self.directory / "sleep"
        sleep.write_text("#!/bin/sh\nexit 0\n")
        sleep.chmod(0o755)

    def verify(self, mode="exercise", phase="lab", **options):
        env = dict(os.environ, PYTHON=str(self.python), PROBE_SSH=str(self.ssh),
                   REVERIFIED_PATH=str(self.marker), BASELINE_PATH=str(self.baseline),
                   PROBE_COUNT_PATH=str(self.directory / "attempts"),
                   PATH=str(self.directory) + os.pathsep + os.environ["PATH"])
        for key in ("REVERIFY", "ONLY_DST", "SKIP_SOURCES", "MATRIX_FAIL", "RECORD_FAIL", "PROBE_FAIL", "ALIAS_REFRESH"):
            env.pop(key, None)
        return subprocess.run(["bash", str(ROOT / "scripts/a2-verify.sh"), mode, "none", phase],
                              env=dict(env, **options), capture_output=True, text=True, timeout=15)

    def test_skipped_sources_cannot_clear_the_reverification_gate(self):
        result = self.verify(REVERIFY="1", SKIP_SOURCES="elastic")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(self.marker.exists())

    def test_approved_update_waits_for_a_later_alias_refresh(self):
        result = self.verify(mode="maintenance", ALIAS_REFRESH="1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.marker.exists())

    def test_complete_exercise_lab_run_clears_the_gate(self):
        result = self.verify(REVERIFY="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("rows=2 skipped=0 PASS", result.stdout)
        self.assertTrue(self.marker.exists())
        self.assertFalse(Path(self.baseline.read_text()).exists())

    def test_filtered_run_cannot_clear_the_gate_even_if_its_rows_pass(self):
        result = self.verify(REVERIFY="1", ONLY_DST="t1")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(self.marker.exists())

    def test_empty_filtered_run_fails(self):
        result = self.verify(ONLY_DST="unknown-host")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("NO PROBES", result.stdout)

    def test_matrix_generation_failure_fails_before_probing(self):
        result = self.verify(REVERIFY="1", MATRIX_FAIL="1")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(self.marker.exists())

    def test_state_write_failure_is_not_reported_as_a_pass(self):
        result = self.verify(REVERIFY="1", RECORD_FAIL="1")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("rows=2 skipped=0 FAIL", result.stdout)
        self.assertFalse(self.marker.exists())

    def test_invalid_phase_fails(self):
        result = self.verify(phase="typo", REVERIFY="1")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(self.marker.exists())

    def test_invalid_mode_fails(self):
        result = self.verify(mode="typo", REVERIFY="1")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(self.marker.exists())

    def test_maintenance_run_cannot_clear_the_gate(self):
        result = self.verify(mode="maintenance", REVERIFY="1")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(self.marker.exists())

    def test_skipped_sources_remain_available_for_diagnostic_runs(self):
        result = self.verify(SKIP_SOURCES="elastic")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("rows=1 skipped=1 PASS-WITH-SKIPS", result.stdout)
        self.assertFalse(self.marker.exists())

    def test_failed_probe_does_not_clear_the_gate_and_cleans_up(self):
        result = self.verify(REVERIFY="1", PROBE_FAIL="1")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(self.marker.exists())
        self.assertFalse(Path(self.baseline.read_text()).exists())


if __name__ == "__main__":
    unittest.main()
