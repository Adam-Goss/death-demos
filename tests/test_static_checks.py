"""#77: operator-visible offline guards in an extracted, non-Git checkout."""
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

from scripts.labcommon import BASH

ROOT = pathlib.Path(__file__).resolve().parent.parent


@unittest.skipIf(os.environ.get("STATIC_CHECKS_NESTED"), "run archive regression separately; it invokes static-checks")
class ExtractedCheckout(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name) / "checkout"
        shutil.copytree(ROOT, self.root, ignore=shutil.ignore_patterns(
            ".git", ".state", "secrets", ".terraform", "__pycache__"))

    def run_checks(self):
        env = dict(os.environ, STATIC_CHECKS_NESTED="1", GIT_CEILING_DIRECTORIES=str(self.root.parent))
        return subprocess.run([BASH, "tests/static-checks.sh"], cwd=self.root,
                              env=env, capture_output=True, text=True, timeout=900)

    def test_clean_archive_reports_git_checks_as_skipped(self):
        for directory in ("secrets", ".state", ".terraform"):
            folder = self.root / directory
            folder.mkdir()
            (folder / "legitimate.key").write_text("-----BEGIN " + "OPENSSH PRIVATE KEY-----")
            (folder / "config.xml").write_text(
                "<opnsense><system><user><password>real-password</password></user></system></opnsense>")
        # A live workstation also holds legitimate ignored material outside secrets/.
        for name in (".env", ".env.local", "operator.pem", "operator.key", "terraform.tfvars"):
            (self.root / name).write_text(
                "operator@pve!firewall=" + "12345678-1234-1234-1234-123456789abc\n"
                + "-----BEGIN " + "OPENSSH PRIVATE KEY-----")
        if hasattr(os, "mkfifo"):
            os.mkfifo(self.root / "operator.pipe")
        result = self.run_checks()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("SKIP seed ISO stays out of git", result.stdout)
        self.assertIn("SKIP no tfstate/tfvars tracked", result.stdout)
        self.assertRegex(result.stdout, r"Summary: \d+ ok, 0 FAIL, 5 SKIP")
        self.assertNotIn("not a git repository", result.stderr)

    def test_archive_detects_planted_secrets_without_printing_them(self):
        specimens = {
            "leaked token.txt": "operator@pve!firewall=" + "12345678-1234-1234-1234-123456789abc",
            "leaked 'key;$file.txt": "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
            "leaked seed.xml": "<opnsense><system><user><password>" + "leaked-password" + "</password></user></system></opnsense>",
        }
        for name, content in specimens.items():
            (self.root / name).write_text(content)
        # Legitimate workstation material must not make a clean source scan fail.
        for directory in ("secrets", ".state", ".terraform"):
            (self.root / directory).mkdir()
            (self.root / directory / "legitimate.key").write_text(specimens["leaked 'key;$file.txt"])
        result = self.run_checks()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        for description in ("no PVE token secrets (uuid) in repo", "no private keys in repo",
                            "no real secrets in any non-ignored XML (config.xml seeds)"):
            self.assertIn("FAIL " + description, result.stdout)
        self.assertRegex(result.stdout, r"Summary: \d+ ok, 3 FAIL, 5 SKIP")
        for content in specimens.values():
            self.assertNotIn(content, result.stdout + result.stderr)
