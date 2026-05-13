"""npm / yarn / pnpm parsing.

Files handled:
  package.json
  package-lock.json     (npm v1, v2, v3)
  yarn.lock             (v1, v2)
  pnpm-lock.yaml
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

from scs.findings import Finding, ParseResult, ResolvedDep, Severity
from scs.repo import Repo
from scs import yaml_lite


ECOSYSTEM = "npm"
LOCKFILE_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"}
PEER_KINDS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
EXACT_VER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][\w.\-+]*)?$")
FLOATING_PREFIXES = ("^", "~", ">", "<", "=", "*")


def matches(rel_path: str) -> bool:
    name = Path(rel_path).name
    return name in {
        "package.json", "package-lock.json", "yarn.lock",
        "pnpm-lock.yaml", "pnpm-workspace.yaml", "npm-shrinkwrap.json",
    }


def parse(repo: Repo, files: Iterable[Path]) -> ParseResult:
    res = ParseResult()
    files = list(files)
    # Group by directory: each dir is a "package"
    by_dir: dict[Path, dict[str, Path]] = {}
    for f in files:
        d = f.parent
        by_dir.setdefault(d, {})[f.name] = f

    workspace_member_dirs = _find_workspace_member_dirs(by_dir)

    for d, entries in by_dir.items():
        if "package.json" in entries:
            res.files_scanned += 1
            is_member = d.resolve() in workspace_member_dirs
            _scan_package_json(repo, entries["package.json"], entries, is_member, res)
        if "package-lock.json" in entries:
            res.files_scanned += 1
            _scan_package_lock(repo, entries["package-lock.json"], res)
        if "npm-shrinkwrap.json" in entries:
            res.files_scanned += 1
            _scan_package_lock(repo, entries["npm-shrinkwrap.json"], res)
        if "yarn.lock" in entries:
            res.files_scanned += 1
            _scan_yarn_lock(repo, entries["yarn.lock"], res)
        if "pnpm-lock.yaml" in entries:
            res.files_scanned += 1
            _scan_pnpm_lock(repo, entries["pnpm-lock.yaml"], res)
    return res


# ──────────────────────────────────────────────────────────────────────────
# Workspace member resolution (pnpm + npm + yarn)
# ──────────────────────────────────────────────────────────────────────────

def _find_workspace_member_dirs(by_dir: dict[Path, dict[str, Path]]) -> set[Path]:
    """Return absolute directories that are members of a JS workspace whose
    root has a co-located lockfile.

    A workspace root is either:
      - a dir with `pnpm-workspace.yaml` AND `pnpm-lock.yaml`, or
      - a dir with `package.json` (declaring `workspaces`) AND any of
        `package-lock.json`/`yarn.lock`/`pnpm-lock.yaml`/`npm-shrinkwrap.json`.

    Member candidates are every package.json directory in `by_dir` that sits
    under a root and matches one of the root's `packages:`/`workspaces:` globs.
    """
    members: set[Path] = set()
    pkg_dirs = [d.resolve() for d, ents in by_dir.items() if "package.json" in ents]

    roots: list[tuple[Path, list[str]]] = []  # (root_dir_resolved, glob patterns)

    for d, ents in by_dir.items():
        d_resolved = d.resolve()
        if "pnpm-workspace.yaml" in ents and "pnpm-lock.yaml" in ents:
            patterns = _read_pnpm_workspace_globs(ents["pnpm-workspace.yaml"])
            if patterns:
                roots.append((d_resolved, patterns))
        if "package.json" in ents and any(n in ents for n in LOCKFILE_NAMES):
            patterns = _read_npm_workspaces_globs(ents["package.json"])
            if patterns:
                roots.append((d_resolved, patterns))

    if not roots:
        return members

    for root_dir, patterns in roots:
        positives = [p for p in patterns if not p.startswith("!")]
        negatives = [p[1:] for p in patterns if p.startswith("!")]
        for pkg_dir in pkg_dirs:
            if pkg_dir == root_dir:
                continue
            try:
                rel = pkg_dir.relative_to(root_dir)
            except ValueError:
                continue
            rel_s = rel.as_posix()
            if any(_glob_match(pat, rel_s) for pat in positives) and not any(
                _glob_match(pat, rel_s) for pat in negatives
            ):
                members.add(pkg_dir)
    return members


def _read_pnpm_workspace_globs(path: Path) -> list[str]:
    try:
        data = yaml_lite.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    pkgs = data.get("packages")
    if not isinstance(pkgs, list):
        return []
    return [str(p) for p in pkgs if isinstance(p, str)]


def _read_npm_workspaces_globs(path: Path) -> list[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    ws = data.get("workspaces")
    if isinstance(ws, list):
        return [str(p) for p in ws if isinstance(p, str)]
    if isinstance(ws, dict):
        pkgs = ws.get("packages")
        if isinstance(pkgs, list):
            return [str(p) for p in pkgs if isinstance(p, str)]
    return []


_GLOB_CACHE: dict[str, "re.Pattern[str]"] = {}


def _glob_match(pattern: str, path: str) -> bool:
    """Match `path` against an npm/pnpm/yarn workspace glob.

    `*` matches one path segment (no `/`); `**` matches across segments.
    Anchored to the start AND end of `path`. Trailing `/` is tolerated.
    """
    pat = pattern.rstrip("/")
    rx = _GLOB_CACHE.get(pat)
    if rx is None:
        out = []
        i = 0
        while i < len(pat):
            if pat[i:i + 2] == "**":
                out.append(".*")
                i += 2
            elif pat[i] == "*":
                out.append("[^/]*")
                i += 1
            elif pat[i] == "?":
                out.append("[^/]")
                i += 1
            elif pat[i] in r".\+()[]{}|^$":
                out.append(re.escape(pat[i]))
                i += 1
            else:
                out.append(pat[i])
                i += 1
        rx = re.compile("^" + "".join(out) + "$")
        _GLOB_CACHE[pat] = rx
    return rx.match(path.rstrip("/")) is not None


# ──────────────────────────────────────────────────────────────────────────
# package.json
# ──────────────────────────────────────────────────────────────────────────

def _scan_package_json(repo: Repo, path: Path, dir_entries: dict[str, Path],
                        is_workspace_member: bool, res: ParseResult) -> None:
    rel = repo.rel(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        res.findings.append(Finding(
            severity=Severity.MEDIUM, code="PARSE_ERROR",
            title="package.json parse error", file=rel, ecosystem=ECOSYSTEM,
            detail=str(e),
        ))
        return

    has_lockfile = any(n in dir_entries for n in LOCKFILE_NAMES)
    is_workspace_root = bool(data.get("workspaces"))
    has_private = bool(data.get("private"))

    # Missing lockfile is HIGH unless this is a workspace root, or a workspace
    # member whose root carries the lockfile (npm/yarn/pnpm monorepos).
    if not has_lockfile and not is_workspace_root and not is_workspace_member:
        res.findings.append(Finding(
            severity=Severity.HIGH, code="MISSING_LOCKFILE",
            title="No lockfile alongside package.json — installs are non-reproducible",
            file=rel, ecosystem=ECOSYSTEM,
            detail="Add `package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml` and commit it.",
        ))

    for kind in PEER_KINDS:
        deps = data.get(kind) or {}
        if not isinstance(deps, dict):
            continue
        sev_floor = Severity.MEDIUM if kind == "devDependencies" else Severity.HIGH
        for name, spec in deps.items():
            res.deps_total += 1
            if not isinstance(spec, str):
                continue
            issue = _classify_npm_spec(spec)
            if issue is None:
                # Pinned exact — record as resolved (no chain)
                res.resolved.append(ResolvedDep(
                    ecosystem=ECOSYSTEM, name=name, version=spec, source_file=rel,
                ))
                continue
            res.deps_unpinned += 1
            sev, code, title = issue
            # Devs with floating ranges → MEDIUM (sev_floor)
            sev = max(sev, sev_floor) if code == "UNPINNED_DIRECT" else sev
            res.findings.append(Finding(
                severity=sev, code=code, title=title,
                file=rel, ecosystem=ECOSYSTEM, package=name, spec=spec,
                detail=f"`{kind}` declares `{name}@{spec}`",
            ))


def _classify_npm_spec(spec: str) -> tuple[Severity, str, str] | None:
    s = spec.strip()
    if s.startswith("file:") or s.startswith("link:") or s.startswith("workspace:"):
        return None  # local refs — not floating
    if s.startswith("git+") or s.startswith("git://") or s.startswith("git@") or "/" in s and "github:" in s:
        if "#" not in s:
            return (Severity.HIGH, "GIT_INSTALL", "Git URL dependency without a commit pin")
        # has a #ref — could be branch or sha
        ref = s.split("#", 1)[1]
        if not re.fullmatch(r"[0-9a-fA-F]{40}", ref):
            return (Severity.HIGH, "GIT_INSTALL", "Git dependency pinned to a non-SHA ref")
        return None
    if s.startswith("http://") or s.startswith("https://"):
        return (Severity.HIGH, "HTTP_INSTALL", "Tarball URL dependency (no integrity)")
    if s in ("*", "latest", "next", "x", ""):
        return (Severity.HIGH, "UNPINNED_DIRECT", f"Floating tag `{s}`")
    if s.startswith("npm:"):
        # Aliased install: npm:other-pkg@^1.0
        return _classify_npm_spec(s.split("@", 1)[1] if "@" in s[4:] else "*")
    if s[0] in FLOATING_PREFIXES:
        return (Severity.HIGH, "UNPINNED_DIRECT", f"Floating spec `{s}`")
    if not EXACT_VER_RE.match(s):
        return (Severity.HIGH, "UNPINNED_DIRECT", f"Non-exact spec `{s}`")
    return None


# ──────────────────────────────────────────────────────────────────────────
# package-lock.json (npm v1/v2/v3)
# ──────────────────────────────────────────────────────────────────────────

def _scan_package_lock(repo: Repo, path: Path, res: ParseResult) -> None:
    rel = repo.rel(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        res.findings.append(Finding(
            severity=Severity.MEDIUM, code="PARSE_ERROR",
            title="package-lock.json parse error", file=rel, ecosystem=ECOSYSTEM,
            detail=str(e),
        ))
        return

    lock_version = data.get("lockfileVersion", 1)
    if "packages" in data and isinstance(data["packages"], dict):
        # v2 / v3
        for pkg_path, info in data["packages"].items():
            if pkg_path == "":  # root
                continue
            if not isinstance(info, dict):
                continue
            name = info.get("name") or _name_from_path(pkg_path)
            ver = info.get("version") or ""
            if not name or not ver:
                continue
            integrity = info.get("integrity") or ""
            resolved = info.get("resolved") or ""
            _record_lock_entry(repo, rel, name, ver, integrity, resolved, info.get("dev", False), res)
    if "dependencies" in data and isinstance(data["dependencies"], dict):
        # v1 — and v2 also has a legacy mirror
        _walk_v1_deps(repo, rel, data["dependencies"], chain=(), res=res, is_root=True)


def _walk_v1_deps(repo: Repo, rel: str, deps: dict, chain: tuple, res: ParseResult, is_root: bool) -> None:
    for name, info in deps.items():
        if not isinstance(info, dict):
            continue
        ver = info.get("version") or ""
        integrity = info.get("integrity") or ""
        resolved = info.get("resolved") or ""
        if ver:
            _record_lock_entry(repo, rel, name, ver, integrity, resolved, info.get("dev", False), res, chain=chain)
        sub = info.get("dependencies")
        if isinstance(sub, dict):
            _walk_v1_deps(repo, rel, sub, chain=chain + (f"{name}@{ver}",), res=res, is_root=False)


def _name_from_path(p: str) -> str:
    # node_modules/foo                  → foo
    # node_modules/@scope/bar           → @scope/bar
    # node_modules/foo/node_modules/baz → baz
    parts = p.split("node_modules/")
    if len(parts) < 2:
        return p
    last = parts[-1]
    bits = last.split("/", 2)
    if bits[0].startswith("@") and len(bits) >= 2:
        return f"{bits[0]}/{bits[1]}"
    return bits[0]


def _record_lock_entry(repo: Repo, rel: str, name: str, ver: str, integrity: str,
                        resolved: str, is_dev: bool, res: ParseResult,
                        chain: tuple[str, ...] = ()) -> None:
    res.resolved.append(ResolvedDep(
        ecosystem=ECOSYSTEM, name=name, version=ver, source_file=rel, chain=chain,
    ))
    if not integrity:
        res.findings.append(Finding(
            severity=Severity.MEDIUM, code="LOCK_NO_INTEGRITY",
            title=f"Lock entry without integrity hash: {name}@{ver}",
            file=rel, ecosystem=ECOSYSTEM, package=name, resolved_version=ver, chain=chain,
        ))
    if resolved and not resolved.startswith("https://registry.npmjs.org/") and not resolved.startswith("https://registry.yarnpkg.com/"):
        # Could be a private registry (legitimate) — flag as MEDIUM/INFO
        if resolved.startswith("git+") or resolved.startswith("git://") or resolved.startswith("http://"):
            res.findings.append(Finding(
                severity=Severity.MEDIUM, code="LOCK_NONCANONICAL_SOURCE",
                title=f"Lock entry resolved from non-canonical source: {name}@{ver}",
                file=rel, ecosystem=ECOSYSTEM, package=name, resolved_version=ver, chain=chain,
                detail=f"resolved={resolved}",
            ))


# ──────────────────────────────────────────────────────────────────────────
# yarn.lock (v1 and v2)
# ──────────────────────────────────────────────────────────────────────────

YARN_HEADER_RE = re.compile(r'^("?(?P<keys>[^"\n]+)"?:)\s*$')


def _scan_yarn_lock(repo: Repo, path: Path, res: ParseResult) -> None:
    rel = repo.rel(path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        res.findings.append(Finding(
            severity=Severity.MEDIUM, code="PARSE_ERROR",
            title="yarn.lock read error", file=rel, ecosystem=ECOSYSTEM, detail=str(e),
        ))
        return
    is_yarn_v2 = text.lstrip().startswith("__metadata:") or "__metadata:" in text[:500]
    # We can use yaml_lite for Yarn v2 (Berry) lockfiles since they ARE YAML.
    if is_yarn_v2:
        try:
            data = yaml_lite.loads(text)
            if isinstance(data, dict):
                for key, info in data.items():
                    if key == "__metadata" or not isinstance(info, dict):
                        continue
                    ver = str(info.get("version") or "")
                    name = _name_from_yarn_key(key)
                    if name and ver:
                        _record_lock_entry(
                            repo, rel, name, ver,
                            integrity=str(info.get("checksum") or ""),
                            resolved=str(info.get("resolution") or ""),
                            is_dev=False, res=res,
                        )
                return
        except Exception:
            pass  # fall through to v1 parsing
    _parse_yarn_v1(repo, rel, text, res)


def _name_from_yarn_key(key: str) -> str:
    # Yarn keys can be comma-joined: "lodash@^4.0, lodash@~4.0"
    first = key.split(",", 1)[0].strip().strip('"')
    # Split off the version spec
    if first.startswith("@"):
        # @scope/name@spec
        at = first.find("@", 1)
        if at < 0:
            return first
        return first[:at]
    at = first.rfind("@")
    if at <= 0:
        return first
    return first[:at]


def _parse_yarn_v1(repo: Repo, rel: str, text: str, res: ParseResult) -> None:
    cur_keys: list[str] = []
    cur_block: dict[str, str] = {}

    def flush():
        if not cur_keys:
            return
        ver = cur_block.get("version", "").strip().strip('"')
        integrity = cur_block.get("integrity", "").strip()
        resolved = cur_block.get("resolved", "").strip().strip('"')
        for keystr in cur_keys:
            name = _name_from_yarn_key(keystr)
            if name and ver:
                _record_lock_entry(repo, rel, name, ver, integrity, resolved, False, res)

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            if not raw.strip() and cur_keys:
                flush()
                cur_keys = []
                cur_block = {}
            continue
        if raw.startswith(" ") or raw.startswith("\t"):
            stripped = raw.strip()
            if " " in stripped:
                k, v = stripped.split(" ", 1)
                cur_block[k.strip()] = v.strip()
        else:
            if cur_keys:
                flush()
                cur_keys = []
                cur_block = {}
            # New header
            line = raw.strip().rstrip(":")
            cur_keys = [line]
    if cur_keys:
        flush()


# ──────────────────────────────────────────────────────────────────────────
# pnpm-lock.yaml
# ──────────────────────────────────────────────────────────────────────────

def _scan_pnpm_lock(repo: Repo, path: Path, res: ParseResult) -> None:
    rel = repo.rel(path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        res.findings.append(Finding(
            severity=Severity.MEDIUM, code="PARSE_ERROR",
            title="pnpm-lock.yaml read error", file=rel, ecosystem=ECOSYSTEM, detail=str(e),
        ))
        return
    # pnpm-lock.yaml `packages:` keys look like:
    #   /lodash@4.17.21:
    # or for older pnpm versions:
    #   /lodash/4.17.21:
    pkgs = []
    cur_key = None
    cur_block: dict[str, str] = {}
    in_packages = False
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line:
            continue
        if not line.startswith(" ") and not line.startswith("\t"):
            in_packages = (line.strip() == "packages:")
            cur_key = None
            continue
        if not in_packages:
            continue
        # Top-level package keys are 2-space-indented under packages:
        if line.startswith("  ") and not line.startswith("    ") and line.lstrip().endswith(":"):
            if cur_key:
                pkgs.append((cur_key, cur_block))
            cur_key = line.lstrip().rstrip(":")
            cur_block = {}
            continue
        # Inner kv pairs at 4-space indent
        if line.startswith("    ") and ":" in line:
            k, v = line.lstrip().split(":", 1)
            cur_block[k.strip()] = v.strip()
    if cur_key:
        pkgs.append((cur_key, cur_block))

    for key, info in pkgs:
        # key examples:
        #   /lodash@4.17.21
        #   /lodash/4.17.21                   (older pnpm versions)
        #   /@scope/foo@1.0.0
        #   /pkg@1.0.0(peer@2.0.0)            (peer-dep disambiguator)
        s = key.lstrip("/").strip("'\"")
        # Strip the peer-dep disambiguator BEFORE partitioning — the
        # `(peer@x)` suffix contains '@' and would otherwise capture
        # rpartition's split point.
        if "(" in s:
            s = s.split("(", 1)[0]
        if "@" in s and not s.startswith("@"):
            name, _, ver = s.rpartition("@")
        elif s.startswith("@"):
            # @scope/name@version
            at = s.find("@", 1)
            if at > 0:
                name, ver = s[:at], s[at + 1:]
            else:
                continue
        elif "/" in s:
            name, _, ver = s.rpartition("/")
        else:
            continue
        ver = ver.strip()
        if not name or not ver:
            continue
        integrity = info.get("integrity", "").strip().strip("'\"")
        resolution = info.get("resolution", "").strip()
        _record_lock_entry(repo, rel, name, ver, integrity, resolution, False, res)
