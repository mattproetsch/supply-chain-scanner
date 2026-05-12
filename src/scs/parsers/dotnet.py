"""NuGet / .NET parsing.

Files handled:
  *.csproj, *.fsproj, *.vbproj
  Directory.Packages.props
  packages.config
  packages.lock.json
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable

from scs.findings import Finding, ParseResult, ResolvedDep, Severity
from scs.repo import Repo


ECOSYSTEM = "nuget"

PROJ_SUFFIXES = (".csproj", ".fsproj", ".vbproj")
FLOATING_VERSION_RE = re.compile(r"[\*\(\)\[\],]")


def matches(rel_path: str) -> bool:
    p = Path(rel_path)
    if p.name in {"packages.config", "packages.lock.json", "Directory.Packages.props"}:
        return True
    return p.suffix.lower() in PROJ_SUFFIXES


def parse(repo: Repo, files: Iterable[Path]) -> ParseResult:
    res = ParseResult()
    by_dir: dict[Path, dict[str, Path]] = {}
    proj_files: list[Path] = []
    for f in files:
        if f.suffix.lower() in PROJ_SUFFIXES:
            proj_files.append(f)
            by_dir.setdefault(f.parent, {})[f.suffix.lower()] = f
        else:
            by_dir.setdefault(f.parent, {})[f.name] = f
    for f in proj_files:
        res.files_scanned += 1
        d_entries = by_dir.get(f.parent, {})
        _scan_csproj(repo, f, d_entries, res)
    for d, entries in by_dir.items():
        if "Directory.Packages.props" in entries:
            res.files_scanned += 1
            _scan_csproj(repo, entries["Directory.Packages.props"], entries, res)
        if "packages.config" in entries:
            res.files_scanned += 1
            _scan_packages_config(repo, entries["packages.config"], res)
        if "packages.lock.json" in entries:
            res.files_scanned += 1
            _scan_packages_lock(repo, entries["packages.lock.json"], res)
    return res


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag


def _scan_csproj(repo: Repo, path: Path, dir_entries: dict[str, Path], res: ParseResult) -> None:
    rel = repo.rel(path)
    try:
        tree = ET.parse(path)
    except Exception as e:
        res.findings.append(Finding(
            severity=Severity.MEDIUM, code="PARSE_ERROR",
            title=f"{path.name} XML parse error", file=rel, ecosystem=ECOSYSTEM, detail=str(e),
        ))
        return
    root = tree.getroot()
    has_lock_setting = False
    has_lockfile = "packages.lock.json" in dir_entries
    for prop in root.iter():
        if _strip_ns(prop.tag) == "RestorePackagesWithLockFile":
            if (prop.text or "").strip().lower() == "true":
                has_lock_setting = True
    pkgs_found = 0
    for ref in root.iter():
        if _strip_ns(ref.tag) not in ("PackageReference", "PackageVersion"):
            continue
        name = ref.attrib.get("Include") or ref.attrib.get("Update")
        version = ref.attrib.get("Version")
        if version is None:
            for child in ref:
                if _strip_ns(child.tag) == "Version":
                    version = (child.text or "").strip()
                    break
        if not name:
            continue
        pkgs_found += 1
        res.deps_total += 1
        if not version:
            res.deps_unpinned += 1
            res.findings.append(Finding(
                severity=Severity.HIGH, code="UNPINNED_DIRECT",
                title=f"<PackageReference Include=\"{name}\"> has no Version",
                file=rel, ecosystem=ECOSYSTEM, package=name,
            ))
            continue
        if FLOATING_VERSION_RE.search(version):
            res.deps_unpinned += 1
            res.findings.append(Finding(
                severity=Severity.HIGH, code="UNPINNED_DIRECT",
                title=f"Floating NuGet version: {name} {version}",
                file=rel, ecosystem=ECOSYSTEM, package=name, spec=version,
                detail="Use an exact version like `Version=\"1.2.3\"` (not `1.0.*` or `[1.0,2.0)`).",
            ))
            continue
        res.resolved.append(ResolvedDep(
            ecosystem=ECOSYSTEM, name=name, version=version.strip(), source_file=rel,
        ))
    if pkgs_found and not has_lockfile and not has_lock_setting:
        res.findings.append(Finding(
            severity=Severity.HIGH, code="MISSING_LOCKFILE",
            title="No `packages.lock.json` and `<RestorePackagesWithLockFile>` not enabled",
            file=rel, ecosystem=ECOSYSTEM,
            detail="Add `<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>` and run `dotnet restore --use-lock-file`.",
        ))


def _scan_packages_config(repo: Repo, path: Path, res: ParseResult) -> None:
    rel = repo.rel(path)
    try:
        tree = ET.parse(path)
    except Exception:
        return
    for pkg in tree.getroot().iter():
        if _strip_ns(pkg.tag) != "package":
            continue
        name = pkg.attrib.get("id")
        version = pkg.attrib.get("version")
        if not name or not version:
            continue
        res.deps_total += 1
        res.resolved.append(ResolvedDep(
            ecosystem=ECOSYSTEM, name=name, version=version, source_file=rel,
        ))


def _scan_packages_lock(repo: Repo, path: Path, res: ParseResult) -> None:
    rel = repo.rel(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return
    for tfm, deps in (data.get("dependencies") or {}).items():
        if not isinstance(deps, dict):
            continue
        for name, info in deps.items():
            if not isinstance(info, dict):
                continue
            ver = info.get("resolved") or info.get("requested")
            if not ver:
                continue
            res.resolved.append(ResolvedDep(
                ecosystem=ECOSYSTEM, name=name, version=ver, source_file=rel,
            ))
            if not info.get("contentHash"):
                res.findings.append(Finding(
                    severity=Severity.MEDIUM, code="LOCK_NO_INTEGRITY",
                    title=f"packages.lock.json entry without contentHash: {name}@{ver}",
                    file=rel, ecosystem=ECOSYSTEM, package=name, resolved_version=ver,
                ))
