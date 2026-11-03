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
if args[0] == "scripts/netpolicy.py" and args[1] == "vantage" and os.environ.get("CRLF"):
    # Windows python prints CRLF; the verifier has to tolerate it (see the dip/ufqdn handling).
    real = subprocess.run([sys.executable, *args], capture_output=True, text=True)
    sys.stdout.write(real.stdout.replace("\\n", "\\r\\n"))
    sys.exit(real.returncode)
if args[0] == "scripts/netpolicy.py" and args[1] in ("matrix", "lint"):
    if args[1] == "matrix":
        if os.environ.get("MATRIX_FAIL"):
            sys.exit(1)
        if os.environ.get("ALIAS_REFRESH"):
            print("p01\\tattacker\\tupdate_source\\ttcp\\t443\\ttcp\\tinet\\texercise\\tallow\\tfirewall\\t10.77.1.10\\tUPDATE_SOURCE")
        else:
            print("p01\\tattacker\\tt1\\ttcp\\t80\\ttcp\\tinet\\texercise\\tallow\\tfirewall\\t10.77.1.10\\t10.77.11.10")
        print("p02\\telastic\\tinternet\\ttcp\\t443\\ttcp\\tinet\\texercise\\tdeny\\tfirewall\\t10.77.3.10\\t1.1.1.1")
        if os.environ.get("ANALYSIS_ROW"):  # a source only the gateway may reach
            print("p03\\tflare\\telastic\\ttcp\\t9200\\ttcp\\tinet\\texercise\\tallow\\tfirewall\\t10.77.20.10\\t10.77.3.10")
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
with open(os.environ["PROBE_ARGV_PATH"], "a") as log:
    log.write("\\t".join(sys.argv[1:]) + "\\n")
vantage = [a for a in sys.argv if a.startswith("opaleye@")][-1]  # the host this probe runs on
dead = os.environ.get("VANTAGE_DEAD")
if dead and dead in vantage:
    print("Host key verification failed.", file=sys.stderr)
    sys.exit(255)
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
    print("rc=124" if "10.77.3.10" in vantage else "rc=0")
''')
        self.ssh.chmod(0o755)
        sleep = self.directory / "sleep"
        sleep.write_text("#!/bin/sh\nexit 0\n")
        sleep.chmod(0o755)

    def verify(self, mode="exercise", phase="lab", **options):
        self.argv = self.directory / "probe-argv"
        env = dict(os.environ, PYTHON=str(self.python), PROBE_SSH=str(self.ssh),
                   REVERIFIED_PATH=str(self.marker), BASELINE_PATH=str(self.baseline),
                   PROBE_COUNT_PATH=str(self.directory / "attempts"), PROBE_ARGV_PATH=str(self.argv),
                   PATH=str(self.directory) + os.pathsep + os.environ["PATH"])
        for key in ("REVERIFY", "ONLY_DST", "SKIP_SOURCES", "MATRIX_FAIL", "RECORD_FAIL", "PROBE_FAIL", "ALIAS_REFRESH",
                    "ANALYSIS_ROW", "PROBE_SSH_FLARE", "VANTAGE_DEAD", "CRLF", "RESET_HOST_KEYS", "KEYGEN_LOG"):
            env.pop(key, None)
        return subprocess.run(["bash", str(ROOT / "scripts/a2-verify.sh"), mode, "none", phase],
                              env=dict(env, **options), capture_output=True, text=True, timeout=15)

    def probes_on(self, source_ip):
        """Every stub-SSH invocation whose probe ran on that source address."""
        lines = self.argv.read_text().splitlines() if self.argv.exists() else []
        return [line for line in lines if ("opaleye@" + source_ip) in line]

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

    def test_analysis_rows_are_probed_through_the_gateway_and_clear_the_gate(self):
        """#64: the stock invocation must cover the zones the operator may not enter."""
        result = self.verify(REVERIFY="1", ANALYSIS_ROW="1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("rows=3 skipped=0 PASS", result.stdout)
        self.assertTrue(self.marker.exists())
        flare = self.probes_on("10.77.20.10")
        self.assertTrue(flare)
        for call in flare:
            self.assertIn("-J\topaleye@10.77.2.10", call, call)
        for call in self.probes_on("10.77.1.10") + self.probes_on("10.77.3.10"):
            self.assertNotIn("-J", call, call)

    def test_a_crlf_vantage_map_is_read_the_same_as_a_unix_one(self):
        """Windows python prints CRLF: a stray \\r must not become part of the jump host."""
        result = self.verify(REVERIFY="1", ANALYSIS_ROW="1", CRLF="1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("rows=3 skipped=0 PASS", result.stdout)
        for call in self.probes_on("10.77.20.10"):
            self.assertIn("-J\topaleye@10.77.2.10\t", call + "\t", call)
        for call in self.probes_on("10.77.1.10"):
            self.assertNotIn("-J", call, call)

    def test_one_sources_vantage_can_be_overridden_without_touching_the_others(self):
        result = self.verify(REVERIFY="1", ANALYSIS_ROW="1",
                             PROBE_SSH_FLARE=str(self.ssh) + " -o ProxyJump=bastion.example")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for call in self.probes_on("10.77.20.10"):
            self.assertIn("-o\tProxyJump=bastion.example", call, call)
            self.assertNotIn("-J", call, call)
        for call in self.probes_on("10.77.1.10"):
            self.assertNotIn("ProxyJump", call, call)

    def test_named_sources_get_their_stale_host_key_cleared_first(self):
        """A probe guest recreated at a fixed address has a new host key (#64, comment 2)."""
        keygen = self.directory / "ssh-keygen"
        keygen.write_text('#!/bin/sh\necho "$@" >>"$KEYGEN_LOG"\n')
        keygen.chmod(0o755)
        log = self.directory / "keygen-log"
        result = self.verify(REVERIFY="1", ANALYSIS_ROW="1", RESET_HOST_KEYS="flare", KEYGEN_LOG=str(log))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(log.read_text().split(), ["-R", "10.77.20.10"])

    def test_host_keys_are_left_alone_unless_a_source_is_named(self):
        keygen = self.directory / "ssh-keygen"
        keygen.write_text('#!/bin/sh\necho "$@" >>"$KEYGEN_LOG"\n')
        keygen.chmod(0o755)
        log = self.directory / "keygen-log"
        result = self.verify(REVERIFY="1", ANALYSIS_ROW="1", KEYGEN_LOG=str(log))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(log.exists())

    def test_a_probe_ssh_that_already_jumps_is_not_jumped_twice(self):
        """The documented pre-#64 workaround was a wrapper with its own jump: keep it working."""
        result = self.verify(REVERIFY="1", ANALYSIS_ROW="1",
                             PROBE_SSH=str(self.ssh) + " -J opaleye@10.77.2.10")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for call in self.probes_on("10.77.20.10"):
            self.assertEqual(call.count("-J"), 1, call)

    def test_a_dead_vantage_reports_the_ssh_error_once_per_source(self):
        """ERROR rows read like a dead probe guest; the usual cause is a stale host key."""
        result = self.verify(REVERIFY="1", ANALYSIS_ROW="1", VANTAGE_DEAD="10.77.20.10")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(self.marker.exists())
        self.assertIn("Host key verification failed", result.stderr)
        self.assertEqual(result.stderr.count("cannot reach flare"), 1, result.stderr)
        self.assertIn("-J opaleye@10.77.2.10", result.stderr)

    def test_failed_probe_does_not_clear_the_gate_and_cleans_up(self):
        result = self.verify(REVERIFY="1", PROBE_FAIL="1")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(self.marker.exists())
        self.assertFalse(Path(self.baseline.read_text()).exists())


if __name__ == "__main__":
    unittest.main()
