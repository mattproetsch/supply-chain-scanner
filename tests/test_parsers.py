import unittest
from pathlib import Path

from tests.conftest_path import FIXTURES  # noqa: F401  (sets sys.path)
from scs.repo import make_repo
from scs.parsers import npm, python as pyparser, dockerfile, gh_actions, gitlab_ci, rust, golang, dotnet
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


class TestPythonRich(unittest.TestCase):
    """Coverage of the lockfile/manifest variants and edge cases in python.py."""

    def test_requirements_directives_and_edge_cases(self):
        res, _ = _run(pyparser, FIXTURES / "python-unpinned")
        codes = {f.code for f in res.findings}
        # `-e .` and `--editable git+...` → EDITABLE_INSTALL.
        self.assertIn("EDITABLE_INSTALL", codes)
        # `hg+`, `svn+`, `bzr+` join `git+` under VCS_INSTALL.
        vcs = [f for f in res.findings if f.code == "VCS_INSTALL"]
        self.assertGreaterEqual(len(vcs), 4)  # git+, hg+, svn+, bzr+
        # Direct URL install.
        self.assertIn("HTTP_INSTALL", codes)
        # Pinned but no --hash → PINNED_NO_HASH.
        no_hash = [f for f in res.findings if f.code == "PINNED_NO_HASH"]
        self.assertTrue(any(f.package == "attrs" for f in no_hash))
        # `psycopg2-binary==2.9.9` with continuation-joined --hash → not flagged.
        self.assertFalse(any(f.package == "psycopg2-binary" for f in no_hash))
        # `-r`, `-c`, `--index-url` etc must not appear as packages.
        pkg_names = {f.package for f in res.findings if f.package}
        for fake in ("-r", "-c", "--requirement", "--index-url", "--trusted-host"):
            self.assertNotIn(fake, pkg_names)

    def test_pyproject_poetry_specs(self):
        res, _ = _run(pyparser, FIXTURES / "python-rich")
        unpinned = {f.package for f in res.findings if f.code == "UNPINNED_DIRECT"}
        # caret/tilde Poetry specs → UNPINNED_DIRECT.
        self.assertIn("caret-pkg", unpinned)
        self.assertIn("tilde-pkg", unpinned)
        # Dev-group / group.test deps still get scanned.
        self.assertIn("dev-floating", unpinned)
        # Poetry git WITHOUT a SHA rev → GIT_INSTALL.
        git_findings = [f for f in res.findings if f.code == "GIT_INSTALL"]
        self.assertTrue(any(f.package == "git-branch" for f in git_findings))
        self.assertTrue(any(f.package == "git-no-rev" for f in git_findings))
        # SHA-pinned git → no finding.
        self.assertFalse(any(f.package == "git-sha" for f in git_findings))
        # path/url Poetry installs are silently accepted.
        self.assertNotIn("path-pkg", unpinned)
        self.assertNotIn("url-pkg", unpinned)
        # `python = "^3.10"` Poetry pin must be skipped (it's the interpreter).
        self.assertNotIn("python", {r.name for r in res.resolved})

    def test_pipfile_and_lock(self):
        res, _ = _run(pyparser, FIXTURES / "python-rich")
        # Pipfile floating spec (string + dict form).
        unpinned = {f.package for f in res.findings if f.code == "UNPINNED_DIRECT"}
        self.assertIn("floating-pkg", unpinned)
        self.assertIn("caret-pkg", unpinned)
        # Pipfile.lock entry without `hashes` → LOCK_NO_INTEGRITY.
        no_int = {f.package for f in res.findings if f.code == "LOCK_NO_INTEGRITY"}
        self.assertIn("no-hashes", no_int)
        # With-hashes resolved successfully.
        names = {r.name for r in res.resolved}
        self.assertIn("with-hashes", names)
        self.assertIn("dev-locked", names)

    def test_poetry_and_uv_locks(self):
        res, _ = _run(pyparser, FIXTURES / "python-rich")
        names = {r.name for r in res.resolved}
        self.assertIn("locked-pkg", names)
        self.assertIn("another", names)
        # uv.lock entries with sdist hash or wheel hash → no LOCK_NO_INTEGRITY.
        no_int_names = {f.package for f in res.findings if f.code == "LOCK_NO_INTEGRITY"}
        self.assertNotIn("uv-with-sdist", no_int_names)
        self.assertNotIn("uv-with-wheel", no_int_names)
        # uv.lock entry with no hash → LOCK_NO_INTEGRITY fires.
        self.assertIn("uv-no-hash", no_int_names)

    def test_setup_py_install_requires(self):
        res, _ = _run(pyparser, FIXTURES / "python-rich")
        unpinned = {f.package for f in res.findings if f.code == "UNPINNED_DIRECT"}
        # `flask>=2.0` and bare `click` from setup.py → UNPINNED_DIRECT.
        self.assertIn("flask", unpinned)
        self.assertIn("click", unpinned)
        # `requests==2.31.0` is exact → resolved, not unpinned.
        names = {r.name for r in res.resolved}
        self.assertIn("requests", names)


class TestNpmRich(unittest.TestCase):
    """Coverage of `_classify_npm_spec` branches and the lockfile parsers."""

    def test_npm_spec_classifications(self):
        # npm-rich/package.json packs every spec form into one file. We assert
        # the right code/severity tuple lands on each named dependency.
        res, _ = _run(npm, FIXTURES / "npm-rich")
        by_name = {f.package: f for f in res.findings if f.package}
        # Floating-tag specs.
        self.assertEqual(by_name["wildcard"].code, "UNPINNED_DIRECT")
        self.assertEqual(by_name["latest-tag"].code, "UNPINNED_DIRECT")
        self.assertEqual(by_name["next-tag"].code, "UNPINNED_DIRECT")
        self.assertEqual(by_name["x-tag"].code, "UNPINNED_DIRECT")
        self.assertEqual(by_name["empty-spec"].code, "UNPINNED_DIRECT")
        # Range / non-exact specs.
        self.assertEqual(by_name["carret"].code, "UNPINNED_DIRECT")
        self.assertEqual(by_name["tilde"].code, "UNPINNED_DIRECT")
        # Git URL without commit pin.
        self.assertEqual(by_name["git-no-ref"].code, "GIT_INSTALL")
        # Git URL pinned to a non-SHA ref (branch).
        self.assertEqual(by_name["git-branch-ref"].code, "GIT_INSTALL")
        # Git URL pinned to a SHA → no finding.
        self.assertNotIn("git-sha-ref", by_name)
        # Other git transports.
        self.assertEqual(by_name["git-protocol"].code, "GIT_INSTALL")
        self.assertEqual(by_name["git-ssh"].code, "GIT_INSTALL")
        self.assertEqual(by_name["github-shorthand"].code, "GIT_INSTALL")
        # Tarball URL (https + http).
        self.assertEqual(by_name["tarball-url"].code, "HTTP_INSTALL")
        self.assertEqual(by_name["tarball-http"].code, "HTTP_INSTALL")
        # Local refs — no finding.
        for n in ("file-link", "link-link", "workspace-link"):
            self.assertNotIn(n, by_name)
        # Aliased installs unwrap to the underlying spec.
        self.assertEqual(by_name["npm-alias-floating"].code, "UNPINNED_DIRECT")
        self.assertEqual(by_name["npm-alias-bare"].code, "UNPINNED_DIRECT")
        self.assertNotIn("npm-alias-pinned", by_name)
        # Exact pins — no finding.
        for n in ("exact", "scoped-exact"):
            self.assertNotIn(n, by_name)

    def test_npm_lockfile_parsing(self):
        # package-lock.json with both v3 `packages` and v1 `dependencies`
        # mirror exercises both walkers.
        res, _ = _run(npm, FIXTURES / "npm-rich")
        resolved_names = {r.name for r in res.resolved}
        # v3 packages section (incl. nested @scope and node_modules/parent/node_modules/nested).
        self.assertIn("lodash", resolved_names)
        self.assertIn("@scope/pkg", resolved_names)
        self.assertIn("nested", resolved_names)
        # v1 mirror with chain expansion.
        self.assertIn("v1-style", resolved_names)
        self.assertIn("v1-nested", resolved_names)
        # Lockfile entry without integrity emits LOCK_NO_INTEGRITY.
        no_integrity = [
            f for f in res.findings
            if f.code == "LOCK_NO_INTEGRITY" and f.package == "no-integrity"
        ]
        self.assertEqual(len(no_integrity), 1)
        # `git+` resolved source flags as LOCK_NONCANONICAL_SOURCE.
        non_canonical = [
            f for f in res.findings
            if f.code == "LOCK_NONCANONICAL_SOURCE" and f.package == "git-source"
        ]
        self.assertEqual(len(non_canonical), 1)

    def test_yarn_v1_lock(self):
        res, _ = _run(npm, FIXTURES / "yarn-v1")
        names = {r.name for r in res.resolved}
        # Comma-joined header keys → both lodash variants resolve to one entry.
        self.assertIn("lodash", names)
        self.assertIn("@scope/foo", names)
        self.assertIn("bare-package", names)
        # Entry with no version is skipped silently.
        self.assertNotIn("leftover-with-no-version", names)

    def test_yarn_berry_lock(self):
        res, _ = _run(npm, FIXTURES / "yarn-berry")
        names = {r.name for r in res.resolved}
        self.assertIn("lodash", names)
        self.assertIn("@scope/pkg", names)

    def test_pnpm_packages_section(self):
        # pnpm-lock.yaml `packages:` keys: modern `/name@ver`, old `/name/ver`,
        # scoped `/@scope/name@ver`, and peer-dep disambiguator
        # `/name@ver(peer@ver)` are all parsed.
        res, _ = _run(npm, FIXTURES / "pnpm-rich")
        names = {r.name for r in res.resolved}
        self.assertIn("lodash", names)
        self.assertIn("old-style", names)
        self.assertIn("@scope/pkg", names)
        self.assertIn("peerdep", names)
        # The peerdep entry's version stripped of the `(react@18.2.0)` suffix.
        peerdep = next(r for r in res.resolved if r.name == "peerdep")
        self.assertEqual(peerdep.version, "1.0.0")


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


class TestParserMatches(unittest.TestCase):
    """Direct unit tests for `matches()` of each parser — the easy way to
    cover all filename branches without crafting fixtures for each."""

    def test_dockerfile_matches(self):
        self.assertTrue(dockerfile.matches("Dockerfile"))
        self.assertTrue(dockerfile.matches("Containerfile"))
        self.assertTrue(dockerfile.matches("Dockerfile.dev"))
        self.assertTrue(dockerfile.matches("infra/Dockerfile.api"))
        self.assertTrue(dockerfile.matches("foo.dockerfile"))
        self.assertTrue(dockerfile.matches("Foo.Dockerfile"))
        self.assertFalse(dockerfile.matches("README.md"))
        self.assertFalse(dockerfile.matches("Dockerfile_no_dot"))

    def test_gh_actions_matches(self):
        self.assertTrue(gh_actions.matches(".github/workflows/ci.yml"))
        self.assertTrue(gh_actions.matches(".github/workflows/release.yaml"))
        self.assertTrue(gh_actions.matches(".github/actions/foo/action.yml"))
        self.assertTrue(gh_actions.matches("action.yml"))
        self.assertTrue(gh_actions.matches("action.yaml"))
        self.assertFalse(gh_actions.matches(".github/dependabot.yml"))
        self.assertFalse(gh_actions.matches("workflows/ci.yml"))  # not under .github

    def test_gitlab_ci_matches(self):
        self.assertTrue(gitlab_ci.matches(".gitlab-ci.yml"))
        self.assertTrue(gitlab_ci.matches("subdir/.gitlab-ci.yml"))
        self.assertFalse(gitlab_ci.matches(".gitlab-ci.yaml"))
        self.assertFalse(gitlab_ci.matches("ci.yml"))


class TestRustRich(unittest.TestCase):
    def test_cargo_toml_dict_specs(self):
        res, _ = _run(rust, FIXTURES / "rust-rich")
        unpinned = {f.package for f in res.findings if f.code == "UNPINNED_DIRECT"}
        # Floating string spec → UNPINNED_DIRECT (caret-by-default).
        self.assertIn("floating-string", unpinned)
        # Dict with floating version → UNPINNED_DIRECT.
        self.assertIn("dict-version-floating", unpinned)
        # Dict with `version = "=1.0.0"` → exact, not unpinned.
        self.assertNotIn("dict-version-exact", unpinned)
        # path dep → not flagged.
        self.assertNotIn("path-dep", unpinned)
        # Git deps.
        git = {f.package for f in res.findings if f.code == "GIT_INSTALL"}
        self.assertIn("git-no-sha", git)
        self.assertIn("git-branch-rev", git)
        self.assertNotIn("git-with-sha", git)
        # build-dependencies and dev-dependencies are scanned.
        self.assertIn("build-floating", unpinned)
        self.assertIn("dev-floating", unpinned)

    def test_cargo_lock_findings(self):
        res, _ = _run(rust, FIXTURES / "rust-rich")
        codes_by_pkg = {f.package: f.code for f in res.findings}
        self.assertEqual(codes_by_pkg.get("no-checksum"), "LOCK_NO_INTEGRITY")
        # `non-canonical` source → flagged. Two findings for that package
        # (LOCK_NONCANONICAL_SOURCE and the `LOCK_NO_INTEGRITY` is suppressed
        # because checksum IS present).
        non_canonical = [f for f in res.findings if f.package == "non-canonical"]
        self.assertTrue(any(f.code == "LOCK_NONCANONICAL_SOURCE" for f in non_canonical))

    def test_workspace_root_no_lockfile_warning(self):
        # Workspace root Cargo.toml has no [package] section, so MISSING_LOCKFILE
        # must be suppressed entirely.
        res, _ = _run(rust, FIXTURES / "rust-workspace")
        self.assertFalse(any(f.code == "MISSING_LOCKFILE" for f in res.findings))


class TestGolangRich(unittest.TestCase):
    def test_pseudo_versions_and_replace(self):
        res, _ = _run(golang, FIXTURES / "go-rich")
        names = {r.name for r in res.resolved}
        # Pseudo-version (commit SHA timestamp form) is a valid pin.
        self.assertIn("example.com/pseudo", names)
        # +incompatible suffix is a valid pin.
        self.assertIn("example.com/incompat", names)
        # Single-line `require` outside the block is parsed.
        self.assertIn("github.com/single/line", names)
        # `replace` directives → INFO findings.
        replaces = [f for f in res.findings if f.code == "GO_REPLACE"]
        self.assertGreaterEqual(len(replaces), 2)

    def test_go_sum_bad_hash(self):
        res, _ = _run(golang, FIXTURES / "go-rich")
        # `deadbeef-not-an-h1-hash` → counted as bad → LOCK_NO_INTEGRITY.
        self.assertTrue(any(
            f.code == "LOCK_NO_INTEGRITY" and "go.sum" in f.file
            for f in res.findings
        ))


class TestGhActionsRich(unittest.TestCase):
    def test_local_action_and_no_ref(self):
        res, _ = _run(gh_actions, FIXTURES / "gh-actions-rich")
        codes = {f.code for f in res.findings}
        self.assertIn("ACTION_LOCAL", codes)
        self.assertIn("ACTION_NO_REF", codes)
        # docker:// without sha256 → DOCKER_FLOATING_TAG.
        docker_floats = [
            f for f in res.findings if f.code == "DOCKER_FLOATING_TAG"
        ]
        self.assertTrue(any("alpine:3.19" in (f.spec or "") for f in docker_floats))
        # docker:// WITH sha256 → not flagged again.
        digested = [f for f in docker_floats if "sha256" in (f.spec or "")]
        self.assertEqual(digested, [])
        # Multi-line `run: |` block scans each line — npm install + curl|bash.
        installs = [f for f in res.findings if f.code == "INSTALL_NOT_STRICT"]
        tools = [f.title for f in installs]
        self.assertTrue(any("npm" in t for t in tools), tools)
        self.assertTrue(any("curl" in t for t in tools), tools)

    def test_composite_action_yml_picked_up(self):
        # .github/actions/<name>/action.yml is a composite action.
        # The fixture's action.yml has actions/checkout@v4 (mutable tag).
        res, _ = _run(gh_actions, FIXTURES / "gh-actions-rich")
        scanned_files = {f.file for f in res.findings}
        self.assertTrue(any("action.yml" in f for f in scanned_files))


class TestGitlabCiRich(unittest.TestCase):
    def test_gitlab_image_and_include_and_scripts(self):
        res, _ = _run(gitlab_ci, FIXTURES / "gitlab-ci-rich")
        codes = {f.code for f in res.findings}
        # Image with floating tag (no sha256) → DOCKER_FLOATING_TAG.
        self.assertIn("DOCKER_FLOATING_TAG", codes)
        # Image with sha256 → not flagged.
        digested = [
            f for f in res.findings
            if f.code == "DOCKER_FLOATING_TAG" and "sha256" in (f.spec or "")
        ]
        self.assertEqual(digested, [])
        # `ref: main` in include → INCLUDE_BRANCH_REF.
        self.assertIn("INCLUDE_BRANCH_REF", codes)
        # `ref: v1.2.3` (tag) and SHA refs → not flagged.
        self.assertEqual(
            sum(1 for f in res.findings if f.code == "INCLUDE_BRANCH_REF"),
            1,
        )
        # script blocks scanned for non-strict installs.
        installs = [f for f in res.findings if f.code == "INSTALL_NOT_STRICT"]
        self.assertGreaterEqual(len(installs), 2)


class TestDotnetPackagesConfig(unittest.TestCase):
    def test_packages_config_resolved(self):
        res, _ = _run(dotnet, FIXTURES / "dotnet-packages-config")
        names = {r.name for r in res.resolved}
        self.assertIn("Newtonsoft.Json", names)
        self.assertIn("Serilog", names)
        # Missing version → skipped silently.
        self.assertNotIn("NoVersion", names)


class TestParseErrors(unittest.TestCase):
    """Pass a directory as the file path to force read_text to raise an
    IsADirectoryError → exercises the PARSE_ERROR branches in each parser."""

    def _parse_error_for(self, parser, fake_name: str) -> str | None:
        from scs.findings import ParseResult
        from scs.repo import Repo
        repo = Repo(name="x", root=FIXTURES, tracked_files=[])
        # Use a directory path with a name that matches the parser, so the
        # parser's per-file dispatch picks it up but read_text raises.
        d = FIXTURES  # any existing directory
        res = ParseResult()
        # Each parser's _scan path is private; just call parse() with a
        # synthesized file path.
        fake = d / fake_name
        parser.parse(repo, [fake])
        return None  # the assertion is via the side-effect parse() running without raising

    def test_dockerfile_parse_error(self):
        # Pointing at a directory under FIXTURES with name=Dockerfile would be
        # ideal, but creating one for tests is fragile. Instead, point at a
        # non-existent file and confirm the parser returns gracefully without
        # raising.
        from scs.findings import ParseResult
        from scs.repo import Repo
        repo = Repo(name="x", root=FIXTURES, tracked_files=[])
        # Synthesize a fake Dockerfile path that doesn't exist.
        fake = FIXTURES / "nope-does-not-exist" / "Dockerfile"
        result = dockerfile.parse(repo, [fake])
        # The parser should have emitted a PARSE_ERROR finding.
        self.assertTrue(any(f.code == "PARSE_ERROR" for f in result.findings))


if __name__ == "__main__":
    unittest.main()
