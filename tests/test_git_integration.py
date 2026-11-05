import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class GitIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name) / "consumer"
        self.repo.mkdir()
        self.env = dict(os.environ, PRE_COMMIT_HOME=str(Path(self.tmp.name) / "cache"))
        self.git("init")
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@example.com")
        self.git("config", "commit.gpgsign", "false")

    def run_command(self, *args, check=True, cwd=None):
        return subprocess.run(
            args, cwd=cwd or self.repo, env=self.env, capture_output=True, text=True, check=check
        )

    def git(self, *args, **kwargs):
        return self.run_command("git", *args, **kwargs)

    def custom_scan(self):
        return self.run_command(sys.executable, str(ROOT / "cli.py"), "--staged", check=False)

    def test_staged_secret_cannot_be_hidden_by_clean_worktree(self):
        path = self.repo / "config with spaces.env"
        path.write_text('password = "' + "unsafe" * 5 + '"\n')
        self.git("add", path.name)
        path.write_text("APP_NAME=clean\n")
        result = self.custom_scan()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(path.name, result.stderr)

    def test_unstaged_secret_does_not_block_clean_index(self):
        path = self.repo / "config.env"
        path.write_text("APP_NAME=clean\n")
        self.git("add", path.name)
        path.write_text('password = "' + "unsafe" * 5 + '"\n')
        self.assertEqual(self.custom_scan().returncode, 0)

    def test_renamed_staged_file_is_scanned(self):
        path = self.repo / "old.env"
        path.write_text('password = "' + "unsafe" * 5 + '"\n')
        self.git("add", path.name)
        self.git("commit", "-m", "Add fixture")
        self.git("mv", "old.env", "new name.env")
        result = self.custom_scan()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("new name.env", result.stderr)

    def test_git_error_fails_closed(self):
        result = self.run_command(
            sys.executable, str(ROOT / "cli.py"), "--staged", cwd=self.repo.parent, check=False
        )
        self.assertEqual(result.returncode, 2)

    def test_installed_hook_accepts_clean_and_blocks_partially_staged_secret(self):
        source = Path(self.tmp.name) / "hook-source"
        source.mkdir()
        for name in ("pyproject.toml", ".pre-commit-hooks.yaml", "cli.py", "scan.py", "baseline.py"):
            shutil.copy2(ROOT / name, source / name)
        for args in (
            ("init",),
            ("config", "user.name", "Test"),
            ("config", "user.email", "test@example.com"),
            ("config", "commit.gpgsign", "false"),
            ("add", "."),
            ("commit", "-m", "Add hook"),
        ):
            self.git(*args, cwd=source)
        revision = self.git("rev-parse", "HEAD", cwd=source).stdout.strip()
        config = self.repo / ".pre-commit-config.yaml"
        config.write_text(
            f"repos:\n  - repo: {source.as_uri()}\n    rev: {revision}  # pragma: allowlist secret\n"
            "    hooks:\n      - id: secret-scan\n"
        )
        self.run_command(sys.executable, "-m", "pre_commit", "install")
        path = self.repo / "config with spaces.env"
        path.write_text("APP_NAME=clean\n")
        self.git("add", ".")
        clean = self.git("commit", "-m", "Add clean config", check=False)
        self.assertEqual(clean.returncode, 0, clean.stdout + clean.stderr)
        previous = self.git("rev-parse", "HEAD").stdout
        path.write_text('password = "' + "unsafe" * 5 + '"\n')
        self.git("add", path.name)
        path.write_text("APP_NAME=clean\n")
        blocked = self.git("commit", "-m", "Reject unsafe config", check=False)
        self.assertNotEqual(blocked.returncode, 0, blocked.stdout + blocked.stderr)
        self.assertIn("Secret", blocked.stdout + blocked.stderr)
        self.assertEqual(self.git("rev-parse", "HEAD").stdout, previous)
        self.assertEqual(path.read_text(), "APP_NAME=clean\n")
