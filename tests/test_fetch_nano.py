import bz2
import hashlib
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
import fetch_nano  # noqa: E402

PAYLOAD = b"raw disk bytes " * 1000


class FetchNano(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)
        src = os.path.join(self.d.name, "nano.img.bz2")
        with open(src, "wb") as f:
            f.write(bz2.compress(PAYLOAD))
        self.url = pathlib.Path(src).as_uri()
        self.sha = hashlib.sha256(open(src, "rb").read()).hexdigest()  # published sha256 is of the .bz2
        self.out = os.path.join(self.d.name, "nano.raw")

    def test_downloads_verifies_and_decompresses(self):
        self.assertEqual(fetch_nano.fetch(self.url, self.sha, self.out), "built")
        self.assertEqual(open(self.out, "rb").read(), PAYLOAD)
        self.assertFalse(os.path.exists(self.out + ".bz2"))

    def test_second_run_is_a_no_op(self):
        fetch_nano.fetch(self.url, self.sha, self.out)
        self.assertEqual(fetch_nano.fetch(self.url, self.sha, self.out), "up to date")

    def test_checksum_mismatch_leaves_no_image(self):
        with self.assertRaises(SystemExit) as e:
            fetch_nano.fetch(self.url, "0" * 64, self.out)
        self.assertIn("mismatch", str(e.exception))
        self.assertFalse(os.path.exists(self.out))
        self.assertFalse(os.path.exists(self.out + ".bz2"))

    def test_a_new_sha_rebuilds(self):
        fetch_nano.fetch(self.url, self.sha, self.out)
        open(self.out + ".sha256", "w").write("stale")
        self.assertEqual(fetch_nano.fetch(self.url, self.sha, self.out), "built")


if __name__ == "__main__":
    unittest.main()
