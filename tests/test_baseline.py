import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from baseline import filter_baselined, load_baseline, write_baseline
from scan import scan_text


class BaselineTests(unittest.TestCase):
    def test_load_missing_baseline_returns_empty_set(self):
        self.assertEqual(load_baseline("/no/such/file.json"), set())

    def test_baselined_finding_is_filtered_out(self):
        findings = scan_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", "x.env")
        self.assertEqual(len(findings), 1)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
            path = fh.name
        try:
            write_baseline(path, findings)
            baseline = load_baseline(path)
            remaining = filter_baselined(findings, baseline)
            self.assertEqual(remaining, [])
        finally:
            os.remove(path)

    def test_unrelated_finding_is_not_filtered(self):
        findings = scan_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", "x.env")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
            path = fh.name
        try:
            write_baseline(path, [])  # empty baseline
            baseline = load_baseline(path)
            remaining = filter_baselined(findings, baseline)
            self.assertEqual(len(remaining), 1)
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
