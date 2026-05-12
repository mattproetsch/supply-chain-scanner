"""Rust / Cargo parsing.

Files handled:
  Cargo.toml
  Cargo.lock
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Iterable

from scs.findings import Finding, ParseResult, ResolvedDep, Severity
from scs.repo import Repo

_THIS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_THIS_DIR / "_vendor"))
import tomli  # noqa: E402

ECOSYSTEM = "crates.io"

DEP_KINDS = ("dependencies", "dev-dependencies", "build-dependencies")
SHA40_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def matches(rel_path: str) -> bool:
    name = Path(rel_path).name
    return name in {"Cargo.toml", "Cargo.lock"}


def parse(repo: Repo, files: Iterable[Path]) -> ParseResult:
    res = ParseResult()
    by_dir: dict[Path, dict[str, Path]] = {}
    for f in files:
        by_dir.setdefault(f.parent, {})[f.name] = f
    for d, entries in by_dir.items():
        if "Cargo.toml" in entries:
            res.files_scanned += 1
            _scan_cargo_toml(repo, entries["Cargo.toml"], "Cargo.lock" in entries, res)
        if "Cargo.lock" in entries:
            res.files_scanned += 1
            _scan_cargo_lock(repo, entries["Cargo.lock"], res)
    return res


def _scan_cargo_toml(repo: Repo, path: Path, has_lockfile: bool, res: ParseResult) -> None:
    rel = repo.rel(path)
    try:
        data = tomli.loads(path.read_text())
    except Exception as e:
        res.findings.append(Finding(
            severity=Severity.MEDIUM, code="PARSE_ERROR",
            title="Cargo.toml parse error", file=rel, ecosystem=ECOSYSTEM, detail=str(e),
        ))
        return
    is_workspace_root = "workspace" in data and "members" in (data.get("workspace") or {})
    has_package = "package" in data
    if has_package and not has_lockfile and not is_workspace_root:
        res.findings.append(Finding(
            severity=Severity.HIGH, code="MISSING_LOCKFILE",
            title="No Cargo.lock alongside Cargo.toml — installs are non-reproducible",
            file=rel, ecosystem=ECOSYSTEM,
            detail="Commit `Cargo.lock` (it's recommended even for libraries since 2023).",
        ))
    for kind in DEP_KINDS:
        for name, spec in (data.get(kind) or {}).items():
            res.deps_total += 1
            sev_floor = Severity.MEDIUM if kind == "dev-dependencies" else Severity.HIGH
            issue = _classify_cargo(name, spec)
            if issue is None:
                if isinstance(spec, str):
                    ver = spec.lstrip("=")
                else:
                    ver = (spec.get("version") or "").lstrip("=")
                if ver:
                    res.resolved.append(ResolvedDep(
                        ecosystem=ECOSYSTEM, name=name, version=ver, source_file=rel,
                    ))
                continue
            res.deps_unpinned += 1
            sev, code, title = issue
            res.findings.append(Finding(
                severity=max(sev, sev_floor), code=code, title=title,
                file=rel, ecosystem=ECOSYSTEM, package=name,
                spec=spec if isinstance(spec, str) else str(spec),
                detail=f"`[{kind}]` declares `{name}`",
            ))


def _classify_cargo(name: str, spec) -> tuple[Severity, str, str] | None:
    if isinstance(spec, str):
        v = spec.strip()
        if v.startswith("="):
            return None  # exact pin
        return (Severity.HIGH, "UNPINNED_DIRECT", f"Floating Cargo dep `{name} = \"{v}\"` (caret-by-default)")
    if isinstance(spec, dict):
        if "git" in spec:
            rev = str(spec.get("rev") or "")
            if SHA40_RE.match(rev):
                return None
            return (Severity.MEDIUM, "GIT_INSTALL", f"Cargo `git` dep `{name}` without `rev = <sha>`")
        if "path" in spec:
            return None  # local path, intentional
        v = str(spec.get("version") or "").strip()
        if not v.startswith("="):
            return (Severity.HIGH, "UNPINNED_DIRECT", f"Floating Cargo dep `{name} = \"{v or '*'}\"`")
        return None
    return None


def _scan_cargo_lock(repo: Repo, path: Path, res: ParseResult) -> None:
    rel = repo.rel(path)
    try:
        data = tomli.loads(path.read_text())
    except Exception:
        return
    for pkg in data.get("package") or []:
        name = pkg.get("name")
        ver = pkg.get("version")
        if not name or not ver:
            continue
        source = pkg.get("source") or ""
        checksum = pkg.get("checksum") or ""
        if source and not source.startswith("registry+https://github.com/rust-lang/crates.io-index"):
            res.findings.append(Finding(
                severity=Severity.MEDIUM, code="LOCK_NONCANONICAL_SOURCE",
                title=f"Cargo.lock entry from non-canonical source: {name}@{ver}",
                file=rel, ecosystem=ECOSYSTEM, package=name, resolved_version=ver,
                detail=f"source={source}",
            ))
        if source and not checksum:
            res.findings.append(Finding(
                severity=Severity.MEDIUM, code="LOCK_NO_INTEGRITY",
                title=f"Cargo.lock entry without checksum: {name}@{ver}",
                file=rel, ecosystem=ECOSYSTEM, package=name, resolved_version=ver,
            ))
        res.resolved.append(ResolvedDep(
            ecosystem=ECOSYSTEM, name=name, version=ver, source_file=rel,
        ))
