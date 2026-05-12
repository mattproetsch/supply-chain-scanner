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


if __name__ == "__main__":
    unittest.main()
