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
        # No-Version PackageReference in a non-CPM repo → still UNPINNED_DIRECT.
        self.assertIn("Bare", unpinned)

    def test_cpm_drift_and_orphan(self):
        res, _ = _run(dotnet, FIXTURES / "dotnet-cpm")
        codes = {(f.code, f.package) for f in res.findings}
        # Directory.Packages.props is a CPM declaration file — no MISSING_LOCKFILE.
        missing_lock_files = {f.file for f in res.findings if f.code == "MISSING_LOCKFILE"}
        self.assertNotIn("Directory.Packages.props", missing_lock_files)
        # Drifty 1.0.0 declared, 0.9.5 locked.
        self.assertIn(("CPM_DECLARED_VS_LOCKED_DRIFT", "Drifty"), codes)
        # OrphanRef has no <PackageVersion> entry.
        self.assertIn(("CPM_REFERENCE_WITHOUT_VERSION", "OrphanRef"), codes)
        # Newtonsoft.Json + Serilog match → no drift, no missing.
        self.assertNotIn(("CPM_DECLARED_VS_LOCKED_DRIFT", "Newtonsoft.Json"), codes)
        self.assertNotIn(("CPM_DECLARED_VS_LOCKED_DRIFT", "Serilog"), codes)
        # PackageReference without Version under CPM is *not* an UNPINNED_DIRECT
        # when a matching <PackageVersion> exists.
        unpinned = {f.package for f in res.findings if f.code == "UNPINNED_DIRECT"}
        self.assertNotIn("Newtonsoft.Json", unpinned)
        self.assertNotIn("Serilog", unpinned)


class TestDockerfileMultistage(unittest.TestCase):
    def test_from_stage_alias_not_flagged(self):
        res, _ = _run(dockerfile, FIXTURES / "dockerfile-multistage")
        no_tag = [f for f in res.findings if f.code == "DOCKER_NO_TAG"]
        # `FROM base AS deps`, `FROM base AS build`, and `FROM Base as Runtime`
        # all reference the prior stage — none should flag.
        offenders = [f.spec for f in no_tag]
        self.assertNotIn("base", offenders)
        self.assertNotIn("Base", offenders)
        # `FROM unknown-image` must still flag.
        self.assertIn("unknown-image", offenders)
        self.assertEqual(len(no_tag), 1, [(f.line, f.spec) for f in no_tag])


class TestNpmWorkspace(unittest.TestCase):
    def test_pnpm_workspace_member_suppressed(self):
        res, _ = _run(npm, FIXTURES / "pnpm-workspace")
        missing = {f.file for f in res.findings if f.code == "MISSING_LOCKFILE"}
        self.assertNotIn("apps/cli/package.json", missing)
        self.assertNotIn("packages/util/package.json", missing)
        # `outside/` is not matched by `apps/*` or `packages/*` globs.
        self.assertIn("outside/package.json", missing)

    def test_npm_workspaces_array_with_recursive_glob(self):
        # Root has `workspaces: ["apps/*", "libs/**"]` + a co-located
        # package-lock.json. Members in apps/ and arbitrarily-deep libs/
        # subtrees must be suppressed.
        res, _ = _run(npm, FIXTURES / "npm-workspace-array")
        missing = {f.file for f in res.findings if f.code == "MISSING_LOCKFILE"}
        self.assertNotIn("apps/web/package.json", missing)
        # `libs/**` is recursive — must match `libs/util/nested`.
        self.assertNotIn("libs/util/nested/package.json", missing)

    def test_yarn_workspaces_dict_form(self):
        # Yarn berry uses `workspaces: { packages: [...] }` — make sure we
        # honor the dict form, not just the array form.
        res, _ = _run(npm, FIXTURES / "yarn-workspace-dict")
        missing = {f.file for f in res.findings if f.code == "MISSING_LOCKFILE"}
        self.assertNotIn("members/a/package.json", missing)


class TestDotnetCpmNested(unittest.TestCase):
    def test_nested_props_overrides_root(self):
        # Root Directory.Packages.props declares Newtonsoft.Json 13.0.4 and
        # OnlyInRoot 1.0.0. legacy/Directory.Packages.props overrides
        # Newtonsoft.Json to 12.0.0 and does NOT inherit OnlyInRoot
        # (MSBuild's closest-ancestor rule, no merging).
        res, _ = _run(dotnet, FIXTURES / "dotnet-cpm-nested")
        drifts = [
            f for f in res.findings
            if f.code == "CPM_DECLARED_VS_LOCKED_DRIFT"
        ]
        # apps/Api locks Newtonsoft.Json at 13.0.4 → matches root → NO drift.
        self.assertNotIn(("apps/Api/Api.csproj", "Newtonsoft.Json"),
                         {(f.file, f.package) for f in drifts})
        # legacy locks Newtonsoft.Json at 13.0.4 but its props pin is 12.0.0 → DRIFT.
        # Finding should point at legacy/Directory.Packages.props (closest props),
        # NOT at the root props.
        legacy_drift = [
            f for f in drifts
            if f.package == "Newtonsoft.Json"
            and f.file == "legacy/Directory.Packages.props"
        ]
        self.assertEqual(len(legacy_drift), 1, drifts)
        self.assertEqual(legacy_drift[0].spec, "12.0.0")
        self.assertEqual(legacy_drift[0].resolved_version, "13.0.4")

        # Orphan refs: legacy/Old.csproj references OnlyInRoot, but legacy's
        # props doesn't declare it (and root is NOT inherited).
        orphans = {
            (f.file, f.package) for f in res.findings
            if f.code == "CPM_REFERENCE_WITHOUT_VERSION"
        }
        self.assertIn(("legacy/Old.csproj", "OnlyInRoot"), orphans)
        # apps/Api references OnlyInRoot — root *does* declare it → not an orphan.
        self.assertNotIn(("apps/Api/Api.csproj", "OnlyInRoot"), orphans)

    def test_transitive_lockfile_entries_are_not_drift(self):
        # OnlyTransitive is declared in props at 5.0.0 but appears only as
        # a Transitive entry (resolved 4.0.0) in the lockfile. Transitive
        # resolutions can legitimately differ — must not flag as drift.
        res, _ = _run(dotnet, FIXTURES / "dotnet-cpm")
        drifts = {f.package for f in res.findings if f.code == "CPM_DECLARED_VS_LOCKED_DRIFT"}
        self.assertNotIn("OnlyTransitive", drifts)


if __name__ == "__main__":
    unittest.main()
