import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scan import scan_text


class ScanTextTests(unittest.TestCase):
    def test_detects_aws_access_key(self):
        findings = scan_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", "x.env")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("aws-access-key-id", rule_ids)

    def test_detects_aws_secret_key(self):
        text = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
        findings = scan_text(text, "x.env")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("aws-secret-key", rule_ids)

    def test_detects_private_key_block(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJ...\n"
        findings = scan_text(text, "id_rsa")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("private-key-block", rule_ids)

    def test_detects_generic_api_key(self):
        text = 'api_key = "example-credential-do-not-use"\n'
        findings = scan_text(text, "config.py")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("generic-api-key", rule_ids)

    def test_detects_unquoted_password_assignment(self):
        text = "DB_PASSWORD=super-secret-password-do-not-use\n"
        findings = scan_text(text, ".env")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("generic-api-key", rule_ids)

    def test_clean_text_has_no_findings(self):
        text = "APP_NAME=widget-service\nAPP_ENV=staging\n"
        findings = scan_text(text, ".env")
        self.assertEqual(findings, [])

    def test_env_variable_reference_is_not_flagged(self):
        text = "DB_PASSWORD=${DB_PASSWORD}\n"
        findings = scan_text(text, ".env")
        self.assertEqual(findings, [])

    def test_inline_allow_marker_suppresses_finding(self):
        text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE  # secret-scan: allow\n"
        findings = scan_text(text, "x.env")
        self.assertEqual(findings, [])

    def test_high_entropy_string_is_flagged(self):
        text = 'token = "zQ8kP2vLxM9wR3tN7yB1cJ6hF4sD0eA5gU"\n'
        findings = scan_text(text, "config.py", entropy_threshold=4.3)
        rule_ids = {f.rule_id for f in findings}
        self.assertTrue({"generic-api-key", "high-entropy-string"} & rule_ids)

    def test_low_entropy_string_is_not_flagged_by_entropy_rule(self):
        text = 'label = "aaaaaaaaaaaaaaaaaaaaaaaa"\n'
        findings = scan_text(text, "config.py")
        rule_ids = {f.rule_id for f in findings}
        self.assertNotIn("high-entropy-string", rule_ids)

    def test_finding_line_hash_is_stable_across_line_number_shift(self):
        text_a = "x = 1\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        text_b = "y = 2\ny = 3\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        hash_a = scan_text(text_a, "x.env")[0].line_hash
        hash_b = scan_text(text_b, "x.env")[0].line_hash
        self.assertEqual(hash_a, hash_b)


if __name__ == "__main__":
    unittest.main()
