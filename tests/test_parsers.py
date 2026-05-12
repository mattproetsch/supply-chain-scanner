import unittest
from pathlib import Path

from tests.conftest_path import FIXTURES  # noqa: F401  (sets sys.path)
from scs.repo import make_repo
from scs.parsers import npm, python as pyparser, dockerfile, gh_actions, rust, golang, dotnet
from scs.findings import Severity


def _run(parser, fixture_dir):
    repo = make_repo(Path(fixture_dir))
    files = [f for f in repo.tracked_files if parser.matches(repo.rel(f))]
    return parser.parse(repo, files), repo


class TestNpm(unittest.TestCase):
    def test_unpinned_fixture(self):
        res, _ = _run(npm, FIXTURES / "npm-unpinned")
        codes = sorted({f.code for f in res.findings})
        self.assertIn("UNPINNED_DIRECT", codes)
        self.assertIn("MISSING_LOCKFILE", codes)
        # express ^4.18.0, lodash *, left-pad latest, jest ~29 should all be flagged
        unpinned = [f for f in res.findings if f.code == "UNPINNED_DIRECT"]
        names = sorted(f.package for f in unpinned)
        self.assertIn("express", names)
        self.assertIn("lodash", names)
        self.assertIn("left-pad", names)
        self.assertIn("jest", names)
        # react 18.3.1 is exact → not flagged
        self.assertNotIn("react", names)


class TestPython(unittest.TestCase):
    def test_requirements_unpinned(self):
        res, _ = _run(pyparser, FIXTURES / "python-unpinned")
        # requests, flask>=2.0, numpy~=, git+url should be HIGH-severity findings
        unpinned = sorted({f.code for f in res.findings if f.severity == Severity.HIGH})
        self.assertIn("UNPINNED_DIRECT", unpinned)
        self.assertIn("VCS_INSTALL", unpinned)
        # django==4.2.7 should NOT be flagged as UNPINNED, and sqlalchemy has --hash so it should be a clean resolved
        codes_for_sqla = [f.code for f in res.findings if f.package == "sqlalchemy"]
        self.assertNotIn("UNPINNED_DIRECT", codes_for_sqla)

    def test_pyproject_buildsystem_floating(self):
        res, _ = _run(pyparser, FIXTURES / "python-unpinned")
        # build-system.requires should produce HIGH UNPINNED on `setuptools>=64`
        bs_finds = [f for f in res.findings if f.package == "setuptools"]
        self.assertTrue(any(f.severity == Severity.HIGH for f in bs_finds), bs_finds)


class TestDockerfile(unittest.TestCase):
    def test_npm_install_flagged(self):
        res, _ = _run(dockerfile, FIXTURES / "dockerfile-bad")
        codes = [f.code for f in res.findings]
        # `RUN npm install` → INSTALL_NOT_STRICT (HIGH)
        self.assertIn("INSTALL_NOT_STRICT", codes)
        # curl|bash → INSTALL_NOT_STRICT (CRITICAL)
        crit = [f for f in res.findings if f.severity == Severity.CRITICAL]
        self.assertTrue(crit, "expected at least one CRITICAL finding for curl|bash")
        # apt-get install -y curl (no version pin) → MEDIUM
        meds = [f for f in res.findings if f.severity == Severity.MEDIUM]
        self.assertTrue(meds)


class TestGhActions(unittest.TestCase):
    def test_unpinned_actions(self):
        res, _ = _run(gh_actions, FIXTURES / "gh-actions-floating")
        codes = [f.code for f in res.findings]
        self.assertIn("ACTION_UNPINNED_REF", codes)
        # tj-actions/changed-files@v45 → HIGH (third-party); actions/checkout@v4 → MEDIUM (first-party)
        sevs = {f.package: f.severity for f in res.findings if f.code == "ACTION_UNPINNED_REF"}
        self.assertEqual(sevs.get("tj-actions/changed-files"), Severity.HIGH)
        self.assertEqual(sevs.get("actions/checkout"), Severity.MEDIUM)
        # actions/setup-node@<sha> should NOT be flagged
        self.assertNotIn("actions/setup-node", sevs)


class TestInlineCommentRobustness(unittest.TestCase):
    """Regressions for the class of bug where an inline `# comment` was
    treated as part of a value (gh_actions ref, gitlab image, requirements
    spec, shell command).  Each parser must accept SHA-pinned values with
    a trailing annotation like `# v4` without complaint.
    """

    def test_gh_action_with_sha_and_comment(self):
        import tempfile, os
        from scs.parsers import gh_actions
        from scs.repo import make_repo
        with tempfile.TemporaryDirectory() as td:
            wf = Path(td) / ".github" / "workflows" / "ci.yml"
            wf.parent.mkdir(parents=True)
            wf.write_text(
                "name: CI\n"
                "on: push\n"
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4\n"
                "      - uses: third-party/x@v1\n"  # this one *should* still flag
            )
            repo = make_repo(Path(td))
            files = [f for f in repo.tracked_files if gh_actions.matches(repo.rel(f))]
            res = gh_actions.parse(repo, files)
            codes = [(f.code, f.package) for f in res.findings]
            # SHA-pinned actions/checkout with `# v4` annotation must NOT be flagged.
            self.assertNotIn(("ACTION_UNPINNED_REF", "actions/checkout"), codes)
            # Floating third-party/x@v1 must still be flagged.
            self.assertIn(("ACTION_UNPINNED_REF", "third-party/x"), codes)

    def test_requirements_url_fragment_preserved(self):
        # The bug: split on bare `#` shredded URL fragments like `#egg=`.
        from scs.parsers import python as pyparser
        from scs.repo import make_repo
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            req = Path(td) / "requirements.txt"
            req.write_text(
                "git+https://github.com/example/foo.git@deadbeef0123456789012345678901234567abcd#egg=foo\n"
                "django==4.2.7  # web framework\n"
                "numpy==1.26.0\n"
            )
            repo = make_repo(Path(td))
            res = pyparser.parse(repo, [req])
            # django==4.2.7 with inline comment should not be unpinned
            unpinned = [f for f in res.findings if f.code == "UNPINNED_DIRECT" and f.package == "django"]
            self.assertEqual(unpinned, [], "django==4.2.7 # ... should not be flagged unpinned")
            # numpy==1.26.0 still parses (no false-positive PARSE_ERROR)
            errors = [f for f in res.findings if f.code == "PARSE_ERROR"]
            self.assertEqual(errors, [])

    def test_gitlab_image_with_inline_comment(self):
        from scs.parsers import gitlab_ci
        from scs.repo import make_repo
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            ci = Path(td) / ".gitlab-ci.yml"
            ci.write_text(
                "image: alpine:3.18@sha256:" + "a" * 64 + "  # base image, sha-pinned\n"
                "stages:\n  - test\n"
            )
            repo = make_repo(Path(td))
            res = gitlab_ci.parse(repo, [ci])
            # SHA-pinned image should NOT be flagged as floating.
            tag_findings = [f for f in res.findings if f.code == "DOCKER_FLOATING_TAG"]
            self.assertEqual(tag_findings, [], f"Got false-positive: {tag_findings}")


class TestRust(unittest.TestCase):
    def test_floating_serde(self):
        res, _ = _run(rust, FIXTURES / "rust-floating")
        unpinned = sorted({f.package for f in res.findings if f.code == "UNPINNED_DIRECT"})
        self.assertIn("serde", unpinned)
        self.assertIn("tokio", unpinned)
        # rand = "=0.8.5" is exact → NOT flagged
        self.assertNotIn("rand", unpinned)


class TestGo(unittest.TestCase):
    def test_bad_version(self):
        res, _ = _run(golang, FIXTURES / "go-bad")
        # MISSING_LOCKFILE because we have go.mod but no go.sum
        codes = [f.code for f in res.findings]
        self.assertIn("MISSING_LOCKFILE", codes)
        # The third "require" line has a bogus version
        bad = [f for f in res.findings if f.code == "UNPINNED_DIRECT"]
        self.assertTrue(bad, res.findings)


class TestDotnet(unittest.TestCase):
    def test_floating_versions(self):
        res, _ = _run(dotnet, FIXTURES / "dotnet-bad")
        unpinned = sorted({f.package for f in res.findings if f.code == "UNPINNED_DIRECT"})
        self.assertIn("Newtonsoft.Json", unpinned)  # 13.0.*
        self.assertIn("AutoMapper", unpinned)        # [12.0,13.0) range
        self.assertNotIn("Serilog", unpinned)        # 3.1.1 exact


if __name__ == "__main__":
    unittest.main()
