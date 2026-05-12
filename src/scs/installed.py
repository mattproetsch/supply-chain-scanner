"""Local install-tree introspection — no scripts run, just file reading.

For npm: walk node_modules/**/package.json
For Python: importlib.metadata against project venv site-packages

Yields ResolvedDep records with parent → child chains so the report can
explain "this vulnerable transitive came in via X → Y".
"""

from __future__ import annotations

import importlib.metadata
import json
import os
import re
import sys
from pathlib import Path
from typing import Iterable

from scs.findings import ResolvedDep
from scs.repo import Repo


def discover_node_modules(repo: Repo) -> list[Path]:
    """Find node_modules directories within the repo (top-level only — not
    nested ones, those are walked recursively from there)."""
    out: list[Path] = []
    # Only top-level node_modules under each package.json dir
    for f in repo.tracked_files:
        if f.name == "package.json":
            nm = f.parent / "node_modules"
            if nm.is_dir() and nm not in out:
                out.append(nm)
    # Plus a top-level node_modules even if untracked (gitignored)
    nm = repo.root / "node_modules"
    if nm.is_dir() and nm not in out:
        out.append(nm)
    return out


def discover_venvs(repo: Repo) -> list[Path]:
    """Find venv site-packages dirs within the repo."""
    out: list[Path] = []
    for name in (".venv", "venv", "env", ".env"):
        p = repo.root / name
        if (p / "pyvenv.cfg").exists():
            # Pick site-packages dirs (one per Python version on Linux/macOS)
            lib = p / "lib"
            if lib.is_dir():
                for sub in lib.iterdir():
                    sp = sub / "site-packages"
                    if sp.is_dir():
                        out.append(sp)
            # Windows layout
            sp = p / "Lib" / "site-packages"
            if sp.is_dir():
                out.append(sp)
    return out


def walk_node_modules(nm_root: Path) -> tuple[dict[str, str], dict[str, dict]]:
    """Return ({pkg_name: version}, {pkg_name: package_json_dict}).

    Walks both flat (npm 7+) and nested (legacy) node_modules layouts.
    """
    versions: dict[str, str] = {}
    metas: dict[str, dict] = {}
    if not nm_root.exists():
        return versions, metas
    for pj in nm_root.rglob("package.json"):
        # Skip nested package.json that aren't the package's own (e.g., test fixtures inside packages)
        # The reliable signal: the path between nm_root and pj must look like (.../node_modules/(@scope/)?pkg/package.json)
        rel = pj.relative_to(nm_root).parts
        # Strip leading nested node_modules
        # Walk parts; the package starts immediately after the LAST node_modules in rel
        idx = 0
        for i in range(len(rel) - 1, -1, -1):
            if rel[i] == "node_modules":
                idx = i + 1
                break
        slug = rel[idx]
        if slug.startswith("@") and idx + 1 < len(rel) - 1:
            slug = f"{slug}/{rel[idx + 1]}"
            after = idx + 2
        else:
            after = idx + 1
        # Must point directly at this package's own package.json
        if rel[-1] != "package.json" or len(rel) - 1 != after:
            continue
        try:
            data = json.loads(pj.read_text())
        except Exception:
            continue
        name = data.get("name") or slug
        version = data.get("version") or ""
        if name and version and name not in versions:
            versions[name] = version
            metas[name] = data
    return versions, metas


def npm_install_tree(nm_root: Path, repo: Repo) -> list[ResolvedDep]:
    """Build ResolvedDeps for installed npm packages with parent chains."""
    versions, metas = walk_node_modules(nm_root)
    if not versions:
        return []
    # Build parent map: parent_pkg → (child → child_version_spec)
    children_of: dict[str, dict[str, str]] = {}
    for parent, meta in metas.items():
        d = {}
        for kind in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            for c, _spec in (meta.get(kind) or {}).items():
                d[c] = versions.get(c, "")
        if d:
            children_of[parent] = d
    # Reverse: child → set(parent)
    parents_of: dict[str, set[str]] = {}
    for parent, kids in children_of.items():
        for c in kids:
            parents_of.setdefault(c, set()).add(parent)

    rel_root = repo.rel(nm_root)
    out: list[ResolvedDep] = []
    for name, version in versions.items():
        chain = _shortest_chain(name, parents_of)
        out.append(ResolvedDep(
            ecosystem="npm",
            name=name,
            version=version,
            source_file=rel_root,
            chain=chain,
        ))
    return out


def _shortest_chain(target: str, parents_of: dict[str, set[str]], max_depth: int = 6) -> tuple[str, ...]:
    """BFS up the parent graph to find the shortest top-level→target chain."""
    if target not in parents_of:
        return ()  # direct (no parents in tree means it's top-level)
    # BFS where each node is (current, path-from-target-up-to-but-not-including-current)
    seen = {target}
    frontier: list[tuple[str, list[str]]] = [(target, [])]
    while frontier:
        nxt: list[tuple[str, list[str]]] = []
        for cur, path in frontier:
            ps = parents_of.get(cur)
            if not ps:
                # cur is a root → chain is reversed path from root → ... → target
                return tuple(reversed(path + [cur]))
            for p in ps:
                if p in seen:
                    continue
                if len(path) >= max_depth:
                    continue
                seen.add(p)
                nxt.append((p, path + [cur]))
        frontier = nxt
    return ()


def python_install_tree(site_packages: Path, repo: Repo) -> list[ResolvedDep]:
    """importlib.metadata over a venv's site-packages."""
    if not site_packages.exists():
        return []
    rel_root = repo.rel(site_packages)
    out: list[ResolvedDep] = []
    versions: dict[str, str] = {}
    requires_of: dict[str, list[str]] = {}
    for dist in importlib.metadata.distributions(path=[str(site_packages)]):
        name = (dist.metadata.get("Name") or "").lower().replace("_", "-")
        ver = dist.version or ""
        if not name or not ver:
            continue
        versions[name] = ver
        requires_of[name] = []
        for r in (dist.requires or []):
            req_name = re.split(r"[\s\[<>=!;~]", r, 1)[0].strip().lower().replace("_", "-")
            if req_name:
                requires_of[name].append(req_name)
    parents_of: dict[str, set[str]] = {}
    for parent, kids in requires_of.items():
        for c in kids:
            parents_of.setdefault(c, set()).add(parent)
    for name, version in versions.items():
        chain = _shortest_chain(name, parents_of)
        out.append(ResolvedDep(
            ecosystem="pypi",
            name=name,
            version=version,
            source_file=rel_root,
            chain=chain,
        ))
    return out


def collect_installed(repo: Repo) -> list[ResolvedDep]:
    """Run all available install-tree introspectors. Empty list if nothing
    materialized."""
    out: list[ResolvedDep] = []
    for nm in discover_node_modules(repo):
        out.extend(npm_install_tree(nm, repo))
    for sp in discover_venvs(repo):
        out.extend(python_install_tree(sp, repo))
    return out
