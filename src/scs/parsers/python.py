"""Python ecosystem parsing.

Files handled:
  requirements*.txt
  pyproject.toml          (PEP 621 `[project]`, Poetry, Hatch, build-system.requires)
  Pipfile                 (TOML)
  Pipfile.lock            (JSON)
  poetry.lock             (TOML)
  uv.lock                 (TOML)
  setup.py                (regex extraction — best effort, no exec)
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

from scs.findings import Finding, ParseResult, ResolvedDep, Severity
from scs.repo import Repo

# Use vendored tomli (Python 3.10 still lacks tomllib)
import sys
_THIS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_THIS_DIR / "_vendor"))
import tomli  # noqa: E402

ECOSYSTEM = "pypi"

REQ_LINE_RE = re.compile(
    r"""^\s*
    (?P<name>[A-Za-z0-9_.\-]+)
    (?P<extras>\[[^\]]+\])?
    \s*
    (?P<spec>.*?)
    \s*$""",
    re.VERBOSE,
)
EXACT_REQ_RE = re.compile(r"^==\s*[A-Za-z0-9_.\-+!]+$")


def matches(rel_path: str) -> bool:
    name = Path(rel_path).name
    if name in {"pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock", "setup.py", "setup.cfg"}:
        return True
    return name.startswith("requirements") and name.endswith(".txt")


def parse(repo: Repo, files: Iterable[Path]) -> ParseResult:
    res = ParseResult()
    for f in files:
        name = f.name
        if name == "pyproject.toml":
            res.files_scanned += 1
            _scan_pyproject(repo, f, res)
        elif name == "Pipfile":
            res.files_scanned += 1
            _scan_pipfile(repo, f, res)
        elif name == "Pipfile.lock":
            res.files_scanned += 1
            _scan_pipfile_lock(repo, f, res)
        elif name == "poetry.lock":
            res.files_scanned += 1
            _scan_poetry_lock(repo, f, res)
        elif name == "uv.lock":
            res.files_scanned += 1
            _scan_uv_lock(repo, f, res)
        elif name == "setup.py":
            res.files_scanned += 1
            _scan_setup_py(repo, f, res)
        elif name.startswith("requirements") and name.endswith(".txt"):
            res.files_scanned += 1
            _scan_requirements_txt(repo, f, res)
    return res


# ──────────────────────────────────────────────────────────────────────────
# requirements.txt
# ──────────────────────────────────────────────────────────────────────────

def _scan_requirements_txt(repo: Repo, path: Path, res: ParseResult) -> None:
    rel = repo.rel(path)
    try:
        text = path.read_text()
    except Exception as e:
        res.findings.append(Finding(
            severity=Severity.MEDIUM, code="PARSE_ERROR",
            title=f"{path.name} read error", file=rel, ecosystem=ECOSYSTEM, detail=str(e),
        ))
        return
    # Join continuation lines
    joined: list[tuple[int, str]] = []
    buf = ""
    start_lineno = 0
    for i, raw in enumerate(text.splitlines(), 1):
        if not buf:
            start_lineno = i
        ln = raw.rstrip()
        # Strip inline comments — PEP 508 / pip require ` #` (whitespace before
        # `#`). Bare `#` is part of a URL fragment (`git+https://…#egg=foo`,
        # `…#sha256=…`) and must NOT be treated as a comment.
        ln = re.sub(r"\s+#.*$", "", ln)
        if ln.endswith("\\"):
            buf += ln[:-1] + " "
            continue
        buf += ln
        if buf.strip():
            joined.append((start_lineno, buf.strip()))
        buf = ""
    if buf.strip():
        joined.append((start_lineno, buf.strip()))

    for lineno, line in joined:
        if not line:
            continue
        if line.startswith("-r ") or line.startswith("--requirement"):
            continue
        if line.startswith("-c") or line.startswith("--constraint"):
            continue
        if line.startswith("--index-url") or line.startswith("--extra-index-url") or line.startswith("--find-links") or line.startswith("--trusted-host"):
            continue
        if line.startswith("-e ") or line.startswith("--editable"):
            res.findings.append(Finding(
                severity=Severity.MEDIUM, code="EDITABLE_INSTALL",
                title="Editable install in requirements", file=rel, line=lineno,
                ecosystem=ECOSYSTEM, spec=line,
                detail="Editable installs resolve at install time and bypass lock semantics.",
            ))
            continue
        if line.startswith("git+") or line.startswith("hg+") or line.startswith("svn+") or line.startswith("bzr+"):
            res.deps_total += 1
            res.deps_unpinned += 1
            res.findings.append(Finding(
                severity=Severity.HIGH, code="VCS_INSTALL",
                title="VCS-URL dependency", file=rel, line=lineno,
                ecosystem=ECOSYSTEM, spec=line,
                detail="VCS installs bypass PyPI integrity checks. Pin to a sha and switch to a wheel where possible.",
            ))
            continue
        if line.startswith("http://") or line.startswith("https://"):
            res.deps_total += 1
            res.deps_unpinned += 1
            res.findings.append(Finding(
                severity=Severity.HIGH, code="HTTP_INSTALL",
                title="Direct URL install", file=rel, line=lineno,
                ecosystem=ECOSYSTEM, spec=line,
            ))
            continue
        # Hash markers can be on this same logical line
        has_hash = "--hash=" in line
        # Drop hash markers from the spec text we examine
        spec_part = re.sub(r"\s+--hash=[A-Za-z0-9:]+", "", line).strip()
        m = REQ_LINE_RE.match(spec_part)
        if not m:
            continue
        name = m.group("name")
        spec = (m.group("spec") or "").strip()
        # Extras like `pkg[extra]` are fine
        # Now classify the spec
        res.deps_total += 1
        if not spec:
            res.deps_unpinned += 1
            res.findings.append(Finding(
                severity=Severity.HIGH, code="UNPINNED_DIRECT",
                title=f"Unbounded requirement: {name}", file=rel, line=lineno,
                ecosystem=ECOSYSTEM, package=name, spec=spec or "(any)",
            ))
            continue
        # Strip env markers (after ;)
        spec = spec.split(";", 1)[0].strip()
        if not EXACT_REQ_RE.match(spec):
            res.deps_unpinned += 1
            res.findings.append(Finding(
                severity=Severity.HIGH, code="UNPINNED_DIRECT",
                title=f"Non-exact spec: {name} {spec}", file=rel, line=lineno,
                ecosystem=ECOSYSTEM, package=name, spec=spec,
            ))
            continue
        ver = spec[2:].strip()
        # Pinned exact. If no --hash, MEDIUM (still pinned but not hash-locked).
        if not has_hash:
            res.findings.append(Finding(
                severity=Severity.MEDIUM, code="PINNED_NO_HASH",
                title=f"Pinned without `--hash=`: {name}=={ver}", file=rel, line=lineno,
                ecosystem=ECOSYSTEM, package=name, spec=spec,
                detail="Use `pip-compile --generate-hashes` or `uv pip compile --generate-hashes` to enable `pip install --require-hashes`.",
            ))
        res.resolved.append(ResolvedDep(
            ecosystem=ECOSYSTEM, name=name, version=ver, source_file=rel,
        ))


# ──────────────────────────────────────────────────────────────────────────
# pyproject.toml
# ──────────────────────────────────────────────────────────────────────────

def _scan_pyproject(repo: Repo, path: Path, res: ParseResult) -> None:
    rel = repo.rel(path)
    try:
        data = tomli.loads(path.read_text())
    except Exception as e:
        res.findings.append(Finding(
            severity=Severity.MEDIUM, code="PARSE_ERROR",
            title="pyproject.toml parse error", file=rel, ecosystem=ECOSYSTEM, detail=str(e),
        ))
        return

    # PEP 621 [project]
    proj = data.get("project") or {}
    deps = proj.get("dependencies") or []
    for spec_str in deps:
        _check_pep508(repo, rel, spec_str, res, kind="runtime")
    for group, gdeps in (proj.get("optional-dependencies") or {}).items():
        for spec_str in gdeps:
            _check_pep508(repo, rel, spec_str, res, kind=f"optional/{group}")

    # build-system.requires — runs at install time, very high risk if floating
    bs = data.get("build-system") or {}
    for spec_str in bs.get("requires") or []:
        _check_pep508(repo, rel, spec_str, res, kind="build-system", elevated=True)

    # Poetry
    tool = data.get("tool") or {}
    poetry = tool.get("poetry") or {}
    for kind in ("dependencies", "dev-dependencies"):
        pdeps = poetry.get(kind) or {}
        if isinstance(pdeps, dict):
            for name, spec in pdeps.items():
                if name == "python":
                    continue
                _check_poetry(repo, rel, name, spec, res, kind=kind)
    # Newer poetry: tool.poetry.group.<name>.dependencies
    for gname, ginfo in (poetry.get("group") or {}).items():
        if isinstance(ginfo, dict):
            for name, spec in (ginfo.get("dependencies") or {}).items():
                if name == "python":
                    continue
                _check_poetry(repo, rel, name, spec, res, kind=f"group/{gname}")


def _check_pep508(repo: Repo, rel: str, spec_str: str, res: ParseResult, kind: str, elevated: bool = False) -> None:
    res.deps_total += 1
    s = spec_str.strip().rstrip(",")
    # Drop env markers
    bare = s.split(";", 1)[0].strip()
    # Extract name
    m = re.match(r"^([A-Za-z0-9_.\-]+)(\[[^\]]+\])?\s*(.*)$", bare)
    if not m:
        return
    name = m.group(1)
    spec = (m.group(3) or "").strip()
    if not spec or not EXACT_REQ_RE.match(spec):
        res.deps_unpinned += 1
        sev = Severity.HIGH if elevated or kind == "runtime" else Severity.MEDIUM
        title = f"Floating {kind} dep: {name} {spec or '(any)'}"
        res.findings.append(Finding(
            severity=sev, code="UNPINNED_DIRECT", title=title,
            file=rel, ecosystem=ECOSYSTEM, package=name, spec=spec or "*",
            detail=("`build-system.requires` runs at install time — pin tightly." if elevated else ""),
        ))
        return
    ver = spec[2:].strip()
    res.resolved.append(ResolvedDep(
        ecosystem=ECOSYSTEM, name=name, version=ver, source_file=rel,
    ))


def _check_poetry(repo: Repo, rel: str, name: str, spec, res: ParseResult, kind: str) -> None:
    res.deps_total += 1
    is_dev = "dev" in kind
    sev_floor = Severity.MEDIUM if is_dev else Severity.HIGH
    if isinstance(spec, str):
        version = spec
        extras = ""
    elif isinstance(spec, dict):
        if "version" in spec:
            version = spec["version"]
        elif "git" in spec:
            if "rev" in spec and re.fullmatch(r"[0-9a-fA-F]{40}", str(spec["rev"])):
                # SHA-pinned
                return
            res.deps_unpinned += 1
            res.findings.append(Finding(
                severity=Severity.HIGH, code="GIT_INSTALL",
                title=f"Poetry git dependency without sha rev: {name}",
                file=rel, ecosystem=ECOSYSTEM, package=name, spec=str(spec),
            ))
            return
        elif "path" in spec or "url" in spec:
            return  # local/url install — not flagged here
        else:
            return
    else:
        return
    # Caret/tilde/star/exact
    v = str(version).strip()
    if v.startswith("^") or v.startswith("~") or "*" in v or v == "" or v.startswith(">") or v.startswith("<"):
        res.deps_unpinned += 1
        res.findings.append(Finding(
            severity=sev_floor, code="UNPINNED_DIRECT",
            title=f"Floating Poetry {kind} dep: {name} = \"{v}\"",
            file=rel, ecosystem=ECOSYSTEM, package=name, spec=v,
        ))
        return
    if v.startswith("=="):
        v = v[2:].strip()
    res.resolved.append(ResolvedDep(
        ecosystem=ECOSYSTEM, name=name, version=v, source_file=rel,
    ))


# ──────────────────────────────────────────────────────────────────────────
# Pipfile / Pipfile.lock
# ──────────────────────────────────────────────────────────────────────────

def _scan_pipfile(repo: Repo, path: Path, res: ParseResult) -> None:
    rel = repo.rel(path)
    try:
        data = tomli.loads(path.read_text())
    except Exception:
        return
    for kind in ("packages", "dev-packages"):
        deps = data.get(kind) or {}
        sev_floor = Severity.MEDIUM if "dev" in kind else Severity.HIGH
        for name, spec in deps.items():
            res.deps_total += 1
            if isinstance(spec, str):
                v = spec.strip()
            elif isinstance(spec, dict) and "version" in spec:
                v = str(spec["version"]).strip()
            else:
                continue
            if v in ("*", "") or v.startswith(("^", "~", ">", "<")):
                res.deps_unpinned += 1
                res.findings.append(Finding(
                    severity=sev_floor, code="UNPINNED_DIRECT",
                    title=f"Floating Pipfile {kind} dep: {name} {v or '(any)'}",
                    file=rel, ecosystem=ECOSYSTEM, package=name, spec=v,
                ))


def _scan_pipfile_lock(repo: Repo, path: Path, res: ParseResult) -> None:
    rel = repo.rel(path)
    try:
        data = json.loads(path.read_text())
    except Exception:
        return
    for section in ("default", "develop"):
        sec = data.get(section) or {}
        for name, info in sec.items():
            if not isinstance(info, dict):
                continue
            ver = (info.get("version") or "").lstrip("=")
            if not ver:
                continue
            hashes = info.get("hashes") or []
            if not hashes:
                res.findings.append(Finding(
                    severity=Severity.MEDIUM, code="LOCK_NO_INTEGRITY",
                    title=f"Pipfile.lock entry without hashes: {name}@{ver}",
                    file=rel, ecosystem=ECOSYSTEM, package=name, resolved_version=ver,
                ))
            res.resolved.append(ResolvedDep(
                ecosystem=ECOSYSTEM, name=name, version=ver, source_file=rel,
            ))


def _scan_poetry_lock(repo: Repo, path: Path, res: ParseResult) -> None:
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
        # poetry.lock historically embeds checksums under [metadata.files]
        res.resolved.append(ResolvedDep(
            ecosystem=ECOSYSTEM, name=name, version=ver, source_file=rel,
        ))


def _scan_uv_lock(repo: Repo, path: Path, res: ParseResult) -> None:
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
        sdist = pkg.get("sdist") or {}
        wheels = pkg.get("wheels") or []
        has_hash = bool(sdist.get("hash")) or any(w.get("hash") for w in wheels)
        if not has_hash:
            res.findings.append(Finding(
                severity=Severity.MEDIUM, code="LOCK_NO_INTEGRITY",
                title=f"uv.lock entry without hash: {name}@{ver}",
                file=rel, ecosystem=ECOSYSTEM, package=name, resolved_version=ver,
            ))
        res.resolved.append(ResolvedDep(
            ecosystem=ECOSYSTEM, name=name, version=ver, source_file=rel,
        ))


# ──────────────────────────────────────────────────────────────────────────
# setup.py — best-effort regex extraction (we DO NOT exec it)
# ──────────────────────────────────────────────────────────────────────────

INSTALL_REQUIRES_RE = re.compile(r"install_requires\s*=\s*\[(.*?)\]", re.DOTALL)
SETUP_REQ_STR_RE = re.compile(r"['\"]([^'\"]+)['\"]")


def _scan_setup_py(repo: Repo, path: Path, res: ParseResult) -> None:
    rel = repo.rel(path)
    try:
        text = path.read_text()
    except Exception:
        return
    m = INSTALL_REQUIRES_RE.search(text)
    if not m:
        return
    body = m.group(1)
    for s in SETUP_REQ_STR_RE.findall(body):
        _check_pep508(repo, rel, s, res, kind="runtime")
