import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cli

EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples")


class CliTests(unittest.TestCase):
    def test_dirty_file_without_baseline_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            baseline = os.path.join(tmp, "baseline.json")
            exit_code = cli.main([os.path.join(EXAMPLES, "dirty.env"), "--baseline", baseline])
            self.assertEqual(exit_code, 1)

    def test_clean_file_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            baseline = os.path.join(tmp, "baseline.json")
            exit_code = cli.main([os.path.join(EXAMPLES, "clean.env"), "--baseline", baseline])
            self.assertEqual(exit_code, 0)

    def test_update_baseline_then_rerun_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            baseline = os.path.join(tmp, "baseline.json")
            dirty = os.path.join(EXAMPLES, "dirty.env")

            first = cli.main([dirty, "--baseline", baseline, "--update-baseline"])
            self.assertEqual(first, 0)
            self.assertTrue(os.path.exists(baseline))

            second = cli.main([dirty, "--baseline", baseline])
            self.assertEqual(second, 0)

    def test_no_paths_and_not_staged_is_a_noop(self):
        exit_code = cli.main([])
        self.assertEqual(exit_code, 0)

    def test_staged_and_explicit_paths_is_an_error(self):
        exit_code = cli.main(["--staged", os.path.join(EXAMPLES, "clean.env")])
        self.assertEqual(exit_code, 2)


if __name__ == "__main__":
    unittest.main()
