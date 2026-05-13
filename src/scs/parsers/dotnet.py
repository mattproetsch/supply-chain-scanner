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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from scs.findings import Finding, ParseResult, ResolvedDep, Severity
from scs.repo import Repo


ECOSYSTEM = "nuget"

PROJ_SUFFIXES = (".csproj", ".fsproj", ".vbproj")
FLOATING_VERSION_RE = re.compile(r"[\*\(\)\[\],]")


@dataclass
class _CpmState:
    """Collected state across all .NET files needed for CPM cross-checks.

    All directory keys are absolute, fully resolved (`.resolve()`) so
    set/dict membership lookups are stable.

    MSBuild rule: only the *closest ancestor* `Directory.Packages.props`
    governs a project. A child props file does NOT inherit from its
    parent unless it explicitly imports via
    `<Import Project="$([MSBuild]::GetPathOfFileAbove(...))" />`. We treat
    every props file as standalone — the import case is rare; it would
    cause us to under-report orphan refs in those subtrees, but never to
    fabricate findings.
    """
    # absolute props dir → {package name → (declared_version, props_rel_path)}
    declared_by_props: dict[Path, dict[str, tuple[str, str]]] = field(default_factory=dict)
    # csproj-side `<PackageReference Include="X">` with no Version attribute.
    # Tuple: (csproj_dir_abs, csproj_rel, package_name)
    refs_without_version: list[tuple[Path, str, str]] = field(default_factory=list)
    # Direct entries from packages.lock.json files.
    # Tuple: (lockfile_dir_abs, package_name, resolved_version, lock_rel)
    lockfile_directs: list[tuple[Path, str, str, str]] = field(default_factory=list)
    # True if any Directory.Packages.props was seen
    has_props: bool = False


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
    cpm = _CpmState()
    # Parse Directory.Packages.props files first so csproj scans can see
    # declared versions when checking references.
    for d, entries in by_dir.items():
        if "Directory.Packages.props" in entries:
            res.files_scanned += 1
            _scan_csproj(repo, entries["Directory.Packages.props"], entries, cpm, res)
    for f in proj_files:
        res.files_scanned += 1
        d_entries = by_dir.get(f.parent, {})
        _scan_csproj(repo, f, d_entries, cpm, res)
    for d, entries in by_dir.items():
        if "packages.config" in entries:
            res.files_scanned += 1
            _scan_packages_config(repo, entries["packages.config"], res)
        if "packages.lock.json" in entries:
            res.files_scanned += 1
            _scan_packages_lock(repo, entries["packages.lock.json"], cpm, res)
    _check_cpm_cross_refs(cpm, res)
    return res


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag


def _scan_csproj(repo: Repo, path: Path, dir_entries: dict[str, Path],
                  cpm: _CpmState, res: ParseResult) -> None:
    rel = repo.rel(path)
    is_props = path.name == "Directory.Packages.props"
    if is_props:
        cpm.has_props = True
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
        tag = _strip_ns(ref.tag)
        if tag not in ("PackageReference", "PackageVersion"):
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
            if tag == "PackageReference" and not is_props:
                # No Version on a PackageReference: legal under CPM if a
                # <PackageVersion> exists in the nearest-ancestor
                # Directory.Packages.props. Defer to the cross-check pass.
                cpm.refs_without_version.append((path.parent.resolve(), rel, name))
                continue
            res.deps_unpinned += 1
            res.findings.append(Finding(
                severity=Severity.HIGH, code="UNPINNED_DIRECT",
                title=f"<{tag} Include=\"{name}\"> has no Version",
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
        v = version.strip()
        if is_props and tag == "PackageVersion":
            cpm.declared_by_props.setdefault(path.parent.resolve(), {})[name] = (v, rel)
        res.resolved.append(ResolvedDep(
            ecosystem=ECOSYSTEM, name=name, version=v, source_file=rel,
        ))
    # Directory.Packages.props is a CPM declaration file, not a buildable
    # project — the lockfile concern is per-csproj and is reported there.
    if pkgs_found and not has_lockfile and not has_lock_setting and not is_props:
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


def _scan_packages_lock(repo: Repo, path: Path, cpm: _CpmState, res: ParseResult) -> None:
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
            # Only Direct entries are subject to CPM-declared-version checks;
            # transitive resolutions can legitimately differ from the props.
            if info.get("type") == "Direct" and info.get("resolved"):
                cpm.lockfile_directs.append(
                    (path.parent.resolve(), name, str(info["resolved"]), rel)
                )
            if not info.get("contentHash"):
                res.findings.append(Finding(
                    severity=Severity.MEDIUM, code="LOCK_NO_INTEGRITY",
                    title=f"packages.lock.json entry without contentHash: {name}@{ver}",
                    file=rel, ecosystem=ECOSYSTEM, package=name, resolved_version=ver,
                ))


def _nearest_props_dir(start: Path, props_dirs: set[Path]) -> Path | None:
    """Walk ancestors of `start` (inclusive) and return the first dir
    that holds a Directory.Packages.props. None if none found.

    `start` and `props_dirs` must already be `.resolve()`d.
    """
    cur = start
    while True:
        if cur in props_dirs:
            return cur
        parent = cur.parent
        if parent == cur:
            return None
        cur = parent


def _check_cpm_cross_refs(cpm: _CpmState, res: ParseResult) -> None:
    """Per-project drift + orphan-reference checks honoring nearest-ancestor
    `Directory.Packages.props` lookup (the MSBuild rule)."""
    # Non-CPM repo: ref-without-version reverts to the pre-CPM UNPINNED_DIRECT
    # behavior. Skip the rest entirely.
    if not cpm.has_props:
        for _csproj_dir, csproj_rel, name in cpm.refs_without_version:
            res.deps_unpinned += 1
            res.findings.append(Finding(
                severity=Severity.HIGH, code="UNPINNED_DIRECT",
                title=f"<PackageReference Include=\"{name}\"> has no Version",
                file=csproj_rel, ecosystem=ECOSYSTEM, package=name,
            ))
        return

    props_dirs = set(cpm.declared_by_props.keys())

    # Drift: per-lockfile, look up the nearest props ancestor and compare each
    # Direct entry's resolved version against that props's declaration only.
    for lock_dir, name, resolved_v, lock_rel in cpm.lockfile_directs:
        nearest = _nearest_props_dir(lock_dir, props_dirs)
        if nearest is None:
            continue  # lockfile lives outside any CPM tree → not subject to CPM
        decls = cpm.declared_by_props.get(nearest, {})
        decl = decls.get(name)
        if decl is None:
            continue  # package not centrally pinned in *this* tree's props
        decl_v, decl_rel = decl
        if decl_v == resolved_v:
            continue
        res.findings.append(Finding(
            severity=Severity.HIGH, code="CPM_DECLARED_VS_LOCKED_DRIFT",
            title=f"CPM declares {name} {decl_v} but lockfile resolves {resolved_v}",
            file=decl_rel, ecosystem=ECOSYSTEM, package=name,
            spec=decl_v, resolved_version=resolved_v,
            detail=(
                f"`{decl_rel}` declares `<PackageVersion Include=\"{name}\" "
                f"Version=\"{decl_v}\">`, but `{lock_rel}` has resolved `{resolved_v}`. "
                f"Re-run `dotnet restore --force-evaluate` (or update the props) so "
                f"declared and locked versions match."
            ),
        ))

    # Orphan refs: per csproj, look up nearest props and check if the
    # referenced package is declared there.
    for csproj_dir, csproj_rel, name in cpm.refs_without_version:
        nearest = _nearest_props_dir(csproj_dir, props_dirs)
        decls = cpm.declared_by_props.get(nearest, {}) if nearest is not None else {}
        if name in decls:
            continue
        res.findings.append(Finding(
            severity=Severity.MEDIUM, code="CPM_REFERENCE_WITHOUT_VERSION",
            title=f"<PackageReference Include=\"{name}\"> has no Version and no <PackageVersion> in Directory.Packages.props",
            file=csproj_rel, ecosystem=ECOSYSTEM, package=name,
            detail=(
                "Under Central Package Management, every `<PackageReference>` "
                "must have a matching `<PackageVersion>` entry in the nearest "
                "ancestor `Directory.Packages.props`. Restore will fail otherwise."
            ),
        ))
