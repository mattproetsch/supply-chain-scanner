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

    def test_inline_comment_after_install(self):
        # Comment after the command should not turn into spurious tokens.
        cmds = classify("npm install # legacy CI step")
        self.assertEqual(len(cmds), 1)
        self.assertEqual(cmds[0].tool, "npm")
        self.assertNotIn("#", cmds[0].raw)
        self.assertNotIn("legacy", cmds[0].raw)

    def test_inline_comment_pip_with_hashes(self):
        # The earlier bug: `# comment` confused the pip handler into treating
        # `#` as a positional package arg → wrong (HIGH "ad-hoc install") finding.
        cmds = classify("pip install --require-hashes -r req.txt # locked")
        self.assertEqual(len(cmds), 1)
        self.assertTrue(cmds[0].is_strict)
        self.assertEqual(cmds[0].consumed_file, "req.txt")

    def test_pure_comment_line(self):
        # Lines that are only a comment yield no commands.
        self.assertEqual(classify("# just a comment"), [])
        self.assertEqual(classify("   # leading-whitespace comment"), [])

    def test_yarn_install_modes(self):
        self.assertFalse(classify("yarn install")[0].is_strict)
        self.assertTrue(classify("yarn install --frozen-lockfile")[0].is_strict)
        self.assertTrue(classify("yarn install --immutable")[0].is_strict)
        # `yarn add foo` is ad-hoc.
        self.assertFalse(classify("yarn add lodash")[0].is_strict)

    def test_pnpm_install_modes(self):
        self.assertFalse(classify("pnpm install")[0].is_strict)
        self.assertTrue(classify("pnpm install --frozen-lockfile")[0].is_strict)
        self.assertFalse(classify("pnpm add lodash")[0].is_strict)

    def test_npm_install_with_pkg(self):
        # `npm install lodash` is ad-hoc package install (different reason).
        cmds = classify("npm install lodash")
        self.assertEqual(len(cmds), 1)
        self.assertFalse(cmds[0].is_strict)
        self.assertIn("ad-hoc", cmds[0].reason)

    def test_python_dash_m_pip(self):
        # `python -m pip install --require-hashes -r req.txt` is the canonical
        # CI form — should classify the same as `pip install`.
        cmds = classify("python3 -m pip install --require-hashes -r req.txt")
        self.assertEqual(len(cmds), 1)
        self.assertEqual(cmds[0].tool, "pip")
        self.assertTrue(cmds[0].is_strict)

    def test_pip_dry_run_safe(self):
        cmds = classify("pip install --dry-run requests")
        self.assertTrue(cmds[0].is_strict)

    def test_pip_editable(self):
        cmds = classify("pip install -e .")
        self.assertEqual(cmds[0].severity, Severity.MEDIUM)

    def test_pip_install_pkg_directly(self):
        cmds = classify("pip install requests")
        self.assertFalse(cmds[0].is_strict)

    def test_poetry_install_and_add(self):
        self.assertTrue(classify("poetry install")[0].is_strict)
        self.assertFalse(classify("poetry add requests")[0].is_strict)
        self.assertFalse(classify("poetry update")[0].is_strict)

    def test_uv_sync_and_pip(self):
        self.assertTrue(classify("uv sync")[0].is_strict)
        self.assertTrue(classify("uv pip sync requirements.txt")[0].is_strict)
        self.assertFalse(classify("uv pip install requests")[0].is_strict)

    def test_go_install_floating_vs_pinned(self):
        # `@latest` / `@master` / `@main` → floating.
        self.assertFalse(classify("go install example.com/foo@latest")[0].is_strict)
        self.assertFalse(classify("go install example.com/foo@main")[0].is_strict)
        # Pinned version → strict.
        self.assertTrue(classify("go install example.com/foo@v1.2.3")[0].is_strict)

    def test_go_build_mod_modes(self):
        self.assertFalse(classify("go build ./...")[0].is_strict)
        self.assertTrue(classify("go build -mod=readonly ./...")[0].is_strict)
        self.assertTrue(classify("go build -mod=vendor ./...")[0].is_strict)
        # `go get` is mutating.
        self.assertFalse(classify("go get example.com/foo")[0].is_strict)

    def test_dotnet_restore(self):
        self.assertFalse(classify("dotnet restore")[0].is_strict)
        self.assertTrue(classify("dotnet restore --locked-mode")[0].is_strict)
        self.assertFalse(classify("dotnet add package Newtonsoft.Json")[0].is_strict)

    def test_apk_pinning(self):
        # apk add WITHOUT version pin → MEDIUM, WITH `=` version → strict.
        self.assertFalse(classify("apk add curl")[0].is_strict)
        self.assertTrue(classify("apk add curl=8.5.0-r0")[0].is_strict)

    def test_brew_install_unpinned(self):
        cmds = classify("brew install jq")
        self.assertEqual(cmds[0].tool, "brew")
        self.assertFalse(cmds[0].is_strict)

    def test_apt_pinned_vs_unpinned(self):
        self.assertFalse(classify("apt-get install -y curl")[0].is_strict)
        self.assertTrue(classify("apt-get install -y curl=7.81.0-1ubuntu1.18")[0].is_strict)

    def test_env_and_sudo_wrappers(self):
        # `env FOO=bar npm ci` and `sudo npm ci` should still recognize npm ci.
        e = classify("env DEBIAN_FRONTEND=noninteractive npm ci")
        self.assertEqual(e[0].tool, "npm")
        self.assertTrue(e[0].is_strict)
        s = classify("sudo apt-get install -y curl=7.81.0-1ubuntu1.18")
        self.assertEqual(s[0].tool, "apt")
        self.assertTrue(s[0].is_strict)

    def test_unrecognized_command_returns_empty(self):
        self.assertEqual(classify("echo hello world"), [])
        self.assertEqual(classify("ls -la"), [])

    def test_empty_and_whitespace_only(self):
        self.assertEqual(classify(""), [])
        self.assertEqual(classify("   \t  "), [])


if __name__ == "__main__":
    unittest.main()
