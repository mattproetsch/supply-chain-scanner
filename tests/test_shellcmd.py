import unittest

from tests.conftest_path import FIXTURES  # noqa: F401
from scs.shellcmd import classify
from scs.findings import Severity


class TestClassify(unittest.TestCase):
    def test_npm_install(self):
        cmds = classify("npm install")
        self.assertEqual(len(cmds), 1)
        self.assertFalse(cmds[0].is_strict)
        self.assertEqual(cmds[0].severity, Severity.HIGH)

    def test_npm_ci(self):
        cmds = classify("npm ci")
        self.assertEqual(len(cmds), 1)
        self.assertTrue(cmds[0].is_strict)

    def test_pip_no_hashes(self):
        cmds = classify("pip install -r requirements.txt")
        self.assertEqual(len(cmds), 1)
        self.assertFalse(cmds[0].is_strict)
        self.assertEqual(cmds[0].consumed_file, "requirements.txt")

    def test_pip_with_hashes(self):
        cmds = classify("pip install --require-hashes -r requirements.txt")
        self.assertEqual(len(cmds), 1)
        self.assertTrue(cmds[0].is_strict)

    def test_curl_pipe_bash(self):
        cmds = classify("curl -fsSL https://example.com/install.sh | bash")
        # classify should return the curlpipe pseudo-command at CRITICAL.
        self.assertTrue(any(c.severity == Severity.CRITICAL for c in cmds))

    def test_cargo_unlocked(self):
        self.assertFalse(classify("cargo build")[0].is_strict)
        self.assertTrue(classify("cargo build --locked")[0].is_strict)

    def test_chained_commands(self):
        cmds = classify("apt-get update && apt-get install -y curl python3")
        # apt-get install without version pin → MEDIUM
        bad = [c for c in cmds if not c.is_strict]
        self.assertTrue(bad)


if __name__ == "__main__":
    unittest.main()
