"""Go modules parsing.

Files handled:
  go.mod
  go.sum
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from scs.findings import Finding, ParseResult, ResolvedDep, Severity
from scs.repo import Repo


ECOSYSTEM = "go"

GO_VERSION_RE = re.compile(r"^v\d+\.\d+\.\d+(?:[-+][\w.\-+]*)?(?:\+incompatible)?$")
GO_PSEUDO_RE = re.compile(r"^v\d+\.\d+\.\d+-(?:0\.)?\d{14}-[0-9a-fA-F]{12}(?:\+incompatible)?$")


def matches(rel_path: str) -> bool:
    name = Path(rel_path).name
    return name in {"go.mod", "go.sum"}


def parse(repo: Repo, files: Iterable[Path]) -> ParseResult:
    res = ParseResult()
    by_dir: dict[Path, dict[str, Path]] = {}
    for f in files:
        by_dir.setdefault(f.parent, {})[f.name] = f
    for d, entries in by_dir.items():
        if "go.mod" in entries:
            res.files_scanned += 1
            _scan_go_mod(repo, entries["go.mod"], "go.sum" in entries, res)
        if "go.sum" in entries:
            res.files_scanned += 1
            _scan_go_sum(repo, entries["go.sum"], res)
    return res


def _scan_go_mod(repo: Repo, path: Path, has_sum: bool, res: ParseResult) -> None:
    rel = repo.rel(path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        res.findings.append(Finding(
            severity=Severity.MEDIUM, code="PARSE_ERROR",
            title="go.mod read error", file=rel, ecosystem=ECOSYSTEM, detail=str(e),
        ))
        return
    if not has_sum:
        res.findings.append(Finding(
            severity=Severity.HIGH, code="MISSING_LOCKFILE",
            title="go.sum missing — module hashes unverifiable",
            file=rel, ecosystem=ECOSYSTEM,
            detail="Run `go mod tidy` and commit go.sum.",
        ))

    in_require_block = False
    in_replace_block = False
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("//", 1)[0].rstrip()
        s = line.strip()
        if not s:
            continue
        if s.startswith("require ("):
            in_require_block = True
            continue
        if s.startswith("replace ("):
            in_replace_block = True
            continue
        if s == ")":
            in_require_block = False
            in_replace_block = False
            continue
        if s.startswith("require ") or in_require_block:
            body = s[len("require "):] if s.startswith("require ") else s
            parts = body.split()
            if len(parts) >= 2:
                module = parts[0]
                version = parts[1]
                _check_go_version(repo, rel, module, version, lineno, res)
        elif s.startswith("replace ") or in_replace_block:
            res.findings.append(Finding(
                severity=Severity.INFO, code="GO_REPLACE",
                title=f"`replace` directive: {s}",
                file=rel, line=lineno, ecosystem=ECOSYSTEM,
                detail="Replaces are intentional but bypass module proxy verification.",
            ))


def _check_go_version(repo: Repo, rel: str, module: str, version: str, lineno: int, res: ParseResult) -> None:
    res.deps_total += 1
    if GO_VERSION_RE.match(version) or GO_PSEUDO_RE.match(version):
        res.resolved.append(ResolvedDep(
            ecosystem=ECOSYSTEM, name=module, version=version, source_file=rel,
        ))
        return
    res.deps_unpinned += 1
    res.findings.append(Finding(
        severity=Severity.HIGH, code="UNPINNED_DIRECT",
        title=f"Suspicious go.mod version: {module} {version}",
        file=rel, line=lineno, ecosystem=ECOSYSTEM, package=module, spec=version,
    ))


def _scan_go_sum(repo: Repo, path: Path, res: ParseResult) -> None:
    rel = repo.rel(path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return
    bad = 0
    for raw in text.splitlines():
        s = raw.strip()
        if not s:
            continue
        parts = s.split()
        if len(parts) != 3:
            continue
        if not parts[2].startswith("h1:"):
            bad += 1
    if bad:
        res.findings.append(Finding(
            severity=Severity.MEDIUM, code="LOCK_NO_INTEGRITY",
            title=f"go.sum has {bad} entries without h1: hash",
            file=rel, ecosystem=ECOSYSTEM,
        ))
