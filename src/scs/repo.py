from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass
class Repo:
    name: str
    root: Path
    tracked_files: list[Path]

    def rel(self, p: Path) -> str:
        try:
            return str(Path(p).resolve().relative_to(self.root.resolve()))
        except ValueError:
            return str(p)


_MANIFEST_NAMES = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock", "setup.py", "requirements.txt",
    "Cargo.toml", "Cargo.lock",
    "go.mod", "go.sum",
    "packages.config", "packages.lock.json", "Directory.Packages.props",
    "Dockerfile", "Containerfile", ".gitlab-ci.yml",
}


def _has_manifest(p: Path) -> bool:
    if not p.is_dir():
        return False
    for n in _MANIFEST_NAMES:
        if (p / n).exists():
            return True
    # *.csproj / .fsproj / .vbproj
    for ext in (".csproj", ".fsproj", ".vbproj"):
        if any(p.glob(f"*{ext}")):
            return True
    # GH Actions workflows
    if (p / ".github" / "workflows").is_dir():
        return True
    return False


def discover_repos(paths: Iterable[str], max_depth: int = 2) -> list[Path]:
    """Return paths to scannable repos under `paths`.

    An explicit path is always added (whether or not it has `.git`). If it has
    no `.git` and contains no manifest at the top level, we descend up to
    `max_depth` levels looking for either `.git` dirs OR manifest files.
    """
    seen: set[str] = set()
    out: list[Path] = []

    def add(p: Path):
        rp = str(p.resolve())
        if rp in seen:
            return
        seen.add(rp)
        out.append(p.resolve())

    for raw in paths:
        p = Path(raw)
        if not p.exists():
            continue
        # Direct path: if it's a git repo OR has a manifest, treat as scannable
        if (p / ".git").exists() or _has_manifest(p):
            add(p)
            continue
        if not p.is_dir():
            continue
        # Otherwise descend
        for root, dirs, _ in os.walk(p):
            try:
                depth = len(Path(root).resolve().relative_to(p.resolve()).parts)
            except ValueError:
                depth = 0
            if depth > max_depth:
                dirs[:] = []
                continue
            if ".git" in dirs:
                add(Path(root))
                dirs[:] = [d for d in dirs if d != ".git"]
                continue
            if _has_manifest(Path(root)):
                add(Path(root))
                dirs[:] = []
                continue
            # Skip giant common dirs
            dirs[:] = [d for d in dirs if d not in ("node_modules", ".venv", "venv", "target", "dist", "build", "__pycache__", ".git")]
    return out


def git_ls_files(root: Path) -> list[Path]:
    """Return tracked files in a git repo, or walk the filesystem if `root`
    is not itself a git repository.

    Note: a path *inside* another repo will return that outer repo's index for
    this subpath — which is empty if nothing under it is tracked. We detect
    "is this our own repo?" by checking for a `.git` entry at `root`.
    """
    git_marker = root / ".git"
    if not git_marker.exists():
        return _walk_files(root)
    try:
        cp = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True,
            check=True,
            timeout=30,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return _walk_files(root)
    files = [root / Path(p) for p in cp.stdout.decode("utf-8", "replace").split("\0") if p]
    if not files:
        # `git ls-files` returned empty — could be a fresh repo. Walk as fallback.
        return _walk_files(root)
    return files


def _walk_files(root: Path, skip={".git", "node_modules", ".venv", "venv", "target", "dist", "build", "__pycache__"}) -> list[Path]:
    out: list[Path] = []
    for r, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in skip]
        for f in files:
            out.append(Path(r) / f)
    return out


def make_repo(root: Path) -> Repo:
    return Repo(name=root.name, root=root, tracked_files=git_ls_files(root))
