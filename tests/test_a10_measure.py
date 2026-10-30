"""A10 measurement report (issue #25): size is estimated from docs x average bytes, not the raw store delta (merges shrink it)."""
import contextlib
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import a10_measure  # noqa: E402


def snap(label, docs, size, rss=100.0):
    return {"label": label, "classes": {n: {"docs": docs, "bytes": size} for n in a10_measure.CLASSES},
            "processes": {n: {"rss_mb": rss, "cpu_pct_lifetime": 1.5} for n in a10_measure.PROCESSES}}


class Report(unittest.TestCase):
    def run_report(self, a, b, hours=None):
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d)
            (out / "a.json").write_text(json.dumps(a))
            (out / "b.json").write_text(json.dumps(b))
            old, a10_measure.OUT = a10_measure.OUT, out
            try:
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    a10_measure.report("a", "b", hours)
                return buf.getvalue()
            finally:
                a10_measure.OUT = old

    def test_size_is_docs_times_average_even_when_the_store_shrank(self):
        # 1,000 -> 1,500 docs at 2,000 bytes/doc in total; the raw store went DOWN after a merge.
        text = self.run_report(snap("a", 1000, 3_000_000), snap("b", 1500, 3_000_000 - 4096))
        row = next(l for l in text.splitlines() if l.startswith("| auditd "))
        cols = [c.strip() for c in row.strip("|").split("|")]
        self.assertEqual(cols[1], "500")                  # docs
        self.assertEqual(cols[3], str(round((3_000_000 - 4096) / 1500)))  # avg bytes/doc
        self.assertGreater(float(cols[2]), 0)             # estimate is positive
        self.assertLess(float(cols[4]), 0)                # raw delta is shown, and is negative

    def test_hours_scales_to_a_rate(self):
        text = self.run_report(snap("a", 0, 0), snap("b", 100, 100_000), hours=0.5)
        row = next(l for l in text.splitlines() if l.startswith("| apache access "))
        self.assertEqual([c.strip() for c in row.strip("|").split("|")][1], "200")

    def test_a_class_missing_from_a_snapshot_is_skipped_not_fatal(self):
        a = snap("a", 1, 1)
        del a["classes"]["auditd"]
        text = self.run_report(a, snap("b", 2, 2))
        self.assertIn("| auditd | n/a", text)

    def test_hours_must_be_positive(self):
        with self.assertRaises(SystemExit):
            self.run_report(snap("a", 1, 1), snap("b", 2, 2), hours=0)

    def test_empty_stats_response_counts_as_zero(self):
        class Es:
            def call(self, path):
                return {"_shards": {}}
        self.assertEqual(a10_measure.store(Es(), "logs-none-*"), {"docs": 0, "bytes": 0})

    def test_process_table_lists_every_component(self):
        text = self.run_report(snap("a", 1, 1), snap("b", 2, 2))
        for name in a10_measure.PROCESSES:
            self.assertIn("| %s |" % name, text)


if __name__ == "__main__":
    unittest.main()
