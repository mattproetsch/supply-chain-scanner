"""Regression tests for cross-platform text-I/O encoding.

Windows defaults `Path.read_text()`/`write_text()` to the system code page
(cp1252 on most installs), which can't represent the Unicode characters
in our CSS/JS (`▶`, `✓`, `→`, `─`).  Every text-I/O call in our own code
must pass `encoding="utf-8"`.

These tests don't reproduce the failure on macOS/Linux (UTF-8 default),
but they DO verify the bytes-on-disk are UTF-8, so a future regression
that drops the explicit encoding will produce a `latin-1` artifact on
all platforms — caught here.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tests.conftest_path import FIXTURES  # noqa: F401  (sets sys.path)
from scs.findings import Finding, RepoReport, Severity
from scs.report.html import render_html
from scs.cli import _do_scan
import argparse


class TestReportEncoding(unittest.TestCase):
    def test_report_with_findings_has_toggle_char(self):
        rep = RepoReport(name="x", path="/x", ecosystems=["npm"])
        rep.findings.append(Finding(
            severity=Severity.HIGH, code="UNPINNED_DIRECT",
            title="floating dep", file="package.json",
            ecosystem="npm", package="some-pkg", spec="^1.0.0",
            detail="needs pin",
        ))
        html = render_html([rep])
        self.assertIn("▶", html)  # toggle char in findings table

    def test_clean_report_has_checkmark(self):
        rep = RepoReport(name="x", path="/x", ecosystems=["npm"], deps_total=3, files_scanned=2)
        html = render_html([rep])
        # No findings → clean banner with ✓
        self.assertIn("✓", html)

    def test_render_with_full_finding_metadata(self):
        # Hits the chain/aliases/advisory/suggestion render branches.
        rep = RepoReport(name="meta", path="/m", ecosystems=["npm"])
        rep.findings.append(Finding(
            severity=Severity.CRITICAL, code="MALWARE",
            title="malware xyz",
            file="node_modules/foo/index.js", line=42,
            ecosystem="npm", package="foo", resolved_version="1.0.0",
            chain=("a@1.0", "b@2.0"),
            advisory_id="GHSA-abcd-1234-efgh",
            advisory_url="https://example.com/adv",
            aliases=("CVE-2026-9999",),
            detail="malicious tarball",
        ))
        out = render_html([rep])
        self.assertIn("GHSA-abcd-1234-efgh", out)
        self.assertIn("CVE-2026-9999", out)
        self.assertIn("a@1.0", out)
        self.assertIn("malicious tarball", out)

    def test_render_with_repo_error_banner(self):
        rep = RepoReport(name="errored", path="/e", ecosystems=[])
        rep.error = "scan failed: permission denied"
        out = render_html([rep])
        self.assertIn("permission denied", out)

    def test_render_empty_repo_list(self):
        out = render_html([])
        # Empty-state markup.
        self.assertIn("No repositories found", out)

    def test_render_with_malware_db_metadata(self):
        rep = RepoReport(name="m", path="/m", ecosystems=["npm"], deps_total=1, files_scanned=1)
        out = render_html(
            [rep],
            malware_db_path="/some/path/scs-malware-db.bin",
            malware_db_sha256=b"\x00" * 32,
            malware_db_built_at=1700000000,
            malware_db_entries=1234,
            malware_db_keys=567,
            malware_db_status="Malware DB loaded: /some/path",
        )
        self.assertIn("scs-malware-db.bin", out)
        self.assertIn("1,234", out)
        self.assertIn("567", out)

    def test_render_with_failed_db_warning_banner(self):
        rep = RepoReport(name="m", path="/m", ecosystems=["npm"], deps_total=1, files_scanned=1)
        out = render_html(
            [rep],
            malware_db_status="Malware DB FAILED to load: nope",
            enrichment_skipped=True,
        )
        self.assertIn("FAILED", out)
        self.assertIn("offline", out.lower())

    def test_report_writes_bytes_as_utf8(self):
        rep = RepoReport(name="utf8-test", path="/x", ecosystems=["npm"])
        rep.findings.append(Finding(
            severity=Severity.HIGH, code="UNPINNED_DIRECT",
            title="floating", file="package.json",
            ecosystem="npm", package="pkg", spec="*",
        ))
        html = render_html([rep])
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "r.html"
            # Mirror what cli.py does (must pass encoding!).
            out.write_text(html, encoding="utf-8")
            raw = out.read_bytes()
            # `▶` is U+25B6 → 3 bytes in UTF-8 (e2 96 b6).  If we accidentally
            # write as latin-1/cp1252 the bytes will differ.
            self.assertIn(b"\xe2\x96\xb6", raw, "▶ should be UTF-8-encoded in output")
            # Round-trip
            self.assertIn("▶", out.read_text(encoding="utf-8"))


class TestCliEndToEnd(unittest.TestCase):
    """Drive `_do_scan` against fixtures to exercise the CLI orchestrator,
    repo discovery, and the JSON dump path together."""

    def _args(self, **overrides):
        defaults = dict(
            paths=[str(FIXTURES / "npm-unpinned")],
            out=None,
            json_out=None,
            offline=True,
            fail_on="none",
            strict=False,
            include="",
            exclude=[],
            concurrency=1,
            no_cache=True,
            malware_db=None,
            no_malware_db=True,
            require_malware_db=False,
            max_depth=2,
        )
        defaults.update(overrides)
        return argparse.Namespace(**defaults)

    def test_scan_writes_html_report(self):
        with tempfile.TemporaryDirectory() as td:
            html_out = Path(td) / "out.html"
            args = self._args(out=str(html_out))
            rc = _do_scan(args)
            self.assertEqual(rc, 0)
            self.assertTrue(html_out.exists())
            text = html_out.read_text(encoding="utf-8")
            self.assertIn("scs", text.lower())

    def test_scan_writes_json_report(self):
        with tempfile.TemporaryDirectory() as td:
            html_out = Path(td) / "r.html"
            json_out = Path(td) / "r.json"
            args = self._args(out=str(html_out), json_out=str(json_out))
            rc = _do_scan(args)
            self.assertEqual(rc, 0)
            data = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertIn("repos", data)
            self.assertGreaterEqual(len(data["repos"]), 1)
            # The npm-unpinned fixture has known UNPINNED_DIRECT findings.
            codes = {f["code"] for r in data["repos"] for f in r["findings"]}
            self.assertIn("UNPINNED_DIRECT", codes)

    def test_scan_fail_on_threshold_returns_nonzero(self):
        with tempfile.TemporaryDirectory() as td:
            html_out = Path(td) / "r.html"
            # `--fail-on=high` against a fixture with HIGH findings → returns 1.
            args = self._args(out=str(html_out), fail_on="high")
            rc = _do_scan(args)
            self.assertEqual(rc, 1)

    def test_scan_with_include_filter(self):
        with tempfile.TemporaryDirectory() as td:
            html_out = Path(td) / "r.html"
            json_out = Path(td) / "r.json"
            # Restrict to 'python' parser only — npm fixture should produce zero npm findings.
            args = self._args(
                paths=[str(FIXTURES / "npm-unpinned"),
                       str(FIXTURES / "python-unpinned")],
                out=str(html_out),
                json_out=str(json_out),
                include="python",
            )
            _do_scan(args)
            data = json.loads(json_out.read_text(encoding="utf-8"))
            ecos = set()
            for r in data["repos"]:
                for f in r["findings"]:
                    if f.get("ecosystem"):
                        ecos.add(f["ecosystem"])
            # Only python should appear.
            self.assertNotIn("npm", ecos)


class TestCliMain(unittest.TestCase):
    """Exercise `cli.main()` argv routing."""

    def test_main_no_args_runs_scan(self):
        # No subcommand → defaults to `scan` against cwd. We can't easily
        # control cwd, so use a fixture as the only positional arg.
        from scs.cli import main
        with tempfile.TemporaryDirectory() as td:
            html_out = Path(td) / "r.html"
            rc = main([
                "scan",
                str(FIXTURES / "clean-project"),
                "--out", str(html_out),
                "--offline", "--no-malware-db",
                "--fail-on", "none",
            ])
            self.assertEqual(rc, 0)
            self.assertTrue(html_out.exists())

    def test_main_version_exits_cleanly(self):
        from scs.cli import main
        with self.assertRaises(SystemExit) as cm:
            main(["--version"])
        # argparse `--version` exits 0.
        self.assertEqual(cm.exception.code, 0)

    def test_scan_with_malware_db_loaded(self):
        # When a built malware DB is available, exercise the load + lookup paths.
        from scs.cli import _do_scan
        from tests.conftest_path import DIST
        db_path = DIST / "scs-malware-db.bin"
        if not db_path.exists():
            self.skipTest("malware DB not built; skip live-DB smoke test")
        with tempfile.TemporaryDirectory() as td:
            args = argparse.Namespace(
                paths=[str(FIXTURES / "malware-tanstack")],
                out=str(Path(td) / "r.html"),
                json_out=str(Path(td) / "r.json"),
                offline=True,
                fail_on="none",
                strict=False,
                include="",
                exclude=[],
                concurrency=1,
                no_cache=True,
                malware_db=str(db_path),
                no_malware_db=False,
                require_malware_db=True,
                max_depth=2,
            )
            rc = _do_scan(args)
            self.assertEqual(rc, 0)
            data = json.loads((Path(td) / "r.json").read_text(encoding="utf-8"))
            codes = {f["code"] for r in data["repos"] for f in r["findings"]}
            # The malware-tanstack fixture has @tanstack/react-start@1.167.71
            # which is in the OSSF DB.
            self.assertIn("MALWARE", codes)

    def test_scan_require_db_missing_returns_nonzero(self):
        from scs.cli import _do_scan
        with tempfile.TemporaryDirectory() as td:
            args = argparse.Namespace(
                paths=[str(FIXTURES / "clean-project")],
                out=str(Path(td) / "r.html"),
                json_out=None,
                offline=True,
                fail_on="none",
                strict=False,
                include="",
                exclude=[],
                concurrency=1,
                no_cache=True,
                malware_db="/nonexistent/db.bin",
                no_malware_db=False,
                require_malware_db=True,
                max_depth=2,
            )
            rc = _do_scan(args)
            self.assertEqual(rc, 3)


class TestRepoDiscovery(unittest.TestCase):
    def test_discover_repos_with_manifest(self):
        from scs.repo import discover_repos
        # FIXTURES isn't a git repo but contains many sub-directories with
        # manifests — discover_repos should descend and find them.
        out = discover_repos([str(FIXTURES)], max_depth=3)
        # Should pick up at least the fixture root + subdirs with manifests.
        self.assertGreaterEqual(len(out), 1)

    def test_discover_repos_explicit_path(self):
        from scs.repo import discover_repos
        # Direct path with a manifest is added.
        out = discover_repos([str(FIXTURES / "npm-unpinned")])
        self.assertEqual(len(out), 1)
        self.assertTrue(str(out[0]).endswith("npm-unpinned"))

    def test_discover_repos_skips_nonexistent(self):
        from scs.repo import discover_repos
        out = discover_repos(["/path/does/not/exist"])
        self.assertEqual(out, [])

    def test_make_repo_walks_filesystem(self):
        from scs.repo import make_repo
        # Fixture isn't a git repo → falls back to filesystem walk.
        repo = make_repo(FIXTURES / "npm-unpinned")
        self.assertTrue(repo.tracked_files)
        # rel() returns the filename for files under root.
        rels = {repo.rel(f) for f in repo.tracked_files}
        self.assertIn("package.json", rels)

    def test_repo_rel_handles_outside_path(self):
        from scs.repo import Repo
        from pathlib import Path
        r = Repo(name="x", root=Path("/nonexistent/x"), tracked_files=[])
        # A path outside root: rel() returns the str of the path.
        self.assertEqual(r.rel(Path("/elsewhere/file.txt")), "/elsewhere/file.txt")


class TestNpmParserUnicode(unittest.TestCase):
    """package.json descriptions often contain non-ASCII chars.  Parsing
    must succeed regardless of the host's default locale."""

    def test_package_json_with_unicode_description(self):
        from scs.parsers import npm
        from scs.repo import make_repo
        with tempfile.TemporaryDirectory() as td:
            pkg = Path(td) / "package.json"
            pkg.write_text(json.dumps({
                "name": "fixture",
                "version": "1.0.0",
                "description": "naïve résumé café ✓ — handles UTF-8",
                "dependencies": {"react": "18.3.1"},
            }, ensure_ascii=False), encoding="utf-8")
            repo = make_repo(Path(td))
            files = [f for f in repo.tracked_files if npm.matches(repo.rel(f))]
            res = npm.parse(repo, files)
            # No PARSE_ERROR
            errs = [f for f in res.findings if f.code == "PARSE_ERROR"]
            self.assertEqual(errs, [], f"parse error: {errs}")


class TestFindingsTableLayout(unittest.TestCase):
    """Regression: in v0.1.4 the table cells had `class="clamp2"` directly
    on the <td>, which combined with `display:-webkit-box` made browsers
    drop the cells out of the column layout and stack values vertically
    inside one cell.  The clamp now lives on an inner <div>; each cell
    must remain a real table cell with the correct content."""

    def test_each_row_has_seven_distinct_cells(self):
        import re as _re
        rep = RepoReport(name="x", path="/x", ecosystems=["npm"])
        rep.findings.append(Finding(
            severity=Severity.HIGH, code="UNPINNED_DIRECT",
            title="floating spec", file="package.json", line=3,
            ecosystem="npm", package="left-pad", spec="^1.0.0",
            advisory_id="OSV-2018-foo",
        ))
        html = render_html([rep])
        # Target the findings table specifically — there's also a sidebar
        # meta-table whose <tbody> would match a naive regex.
        m = _re.search(r'<table class="findings">.*?<tbody>(.+?)</tbody>', html, _re.DOTALL)
        self.assertIsNotNone(m, "expected a findings table in the report")
        body = m.group(1)
        # First data row (not the .expand-row)
        rows = _re.findall(r"<tr(?![^>]*expand-row)[^>]*>(.+?)</tr>", body, _re.DOTALL)
        self.assertTrue(rows, "expected at least one finding row")
        row = rows[0]
        tds = _re.findall(r"<td[^>]*>.*?</td>", row, _re.DOTALL)
        self.assertEqual(len(tds), 7, f"row should have 7 <td>s, got {len(tds)}: {tds}")

        def text(td):
            return _re.sub(r"<[^>]+>", "", td).strip()

        self.assertIn("HIGH", text(tds[0]))
        self.assertIn("UNPINNED_DIRECT", text(tds[1]))
        self.assertIn("floating spec", text(tds[2]))
        self.assertIn("left-pad", text(tds[3]))
        self.assertIn("1.0.0", text(tds[4]))
        self.assertIn("package.json", text(tds[5]))
        # 6th (toggle) just contains the ▶ char
        self.assertIn("▶", tds[6])

    def test_clamp2_is_on_inner_div_not_td(self):
        """If `display: -webkit-box` lands on a <td>, the browser collapses
        the cells.  Make sure no <td> has class="clamp2" directly."""
        import re as _re
        rep = RepoReport(name="x", path="/x", ecosystems=["npm"])
        rep.findings.append(Finding(
            severity=Severity.HIGH, code="UNPINNED_DIRECT",
            title="t", file="f", ecosystem="npm", package="p", spec="*",
        ))
        html = render_html([rep])
        self.assertNotRegex(html, r'<td[^>]*class="[^"]*\bclamp2\b')
        # And the inner div MUST exist
        self.assertIn('<div class="clamp2">', html)


if __name__ == "__main__":
    unittest.main()
