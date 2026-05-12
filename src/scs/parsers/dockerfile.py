"""Dockerfile parsing.

Files handled:
  Dockerfile, Containerfile, *.dockerfile, *.Dockerfile, **/Dockerfile.*

Findings:
  - `FROM <image>:<tag>` without `@sha256:` → MEDIUM
  - `FROM <image>` (implicit :latest) → HIGH
  - `RUN` lines tokenized via shellcmd; non-lockfile-strict installs flagged.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from scs.findings import Finding, ParseResult, Severity
from scs.repo import Repo
from scs import shellcmd


def matches(rel_path: str) -> bool:
    p = Path(rel_path)
    n = p.name
    if n in {"Dockerfile", "Containerfile"}:
        return True
    if n.startswith("Dockerfile."):
        return True
    if n.endswith(".dockerfile") or n.endswith(".Dockerfile"):
        return True
    return False


def parse(repo: Repo, files: Iterable[Path]) -> ParseResult:
    res = ParseResult()
    for f in files:
        res.files_scanned += 1
        _scan(repo, f, res)
    return res


def _scan(repo: Repo, path: Path, res: ParseResult) -> None:
    rel = repo.rel(path)
    try:
        text = path.read_text()
    except Exception as e:
        res.findings.append(Finding(
            severity=Severity.MEDIUM, code="PARSE_ERROR",
            title=f"{path.name} read error", file=rel, ecosystem="dockerfile", detail=str(e),
        ))
        return

    # Join continuation lines
    lines: list[tuple[int, str]] = []
    buf = ""
    start = 0
    for i, raw in enumerate(text.splitlines(), 1):
        s = raw.rstrip()
        if not buf:
            start = i
        # Strip leading whitespace AFTER continuation
        if s.endswith("\\"):
            buf += s[:-1] + " "
            continue
        buf += s
        if buf.strip():
            lines.append((start, buf.strip()))
        buf = ""
    if buf.strip():
        lines.append((start, buf.strip()))

    for lineno, line in lines:
        if line.startswith("#"):
            continue
        upper = line.split(None, 1)[0].upper() if line.split() else ""
        rest = line[len(upper):].strip() if upper else ""
        if upper == "FROM":
            _check_from(rel, lineno, rest, res)
        elif upper == "RUN":
            _check_run(rel, lineno, rest, res)
        elif upper == "ADD":
            # ADD <url> ... can pull arbitrary network resources
            for tok in rest.split():
                if tok.startswith("http://") or tok.startswith("https://"):
                    res.findings.append(Finding(
                        severity=Severity.MEDIUM, code="DOCKERFILE_ADD_URL",
                        title=f"`ADD {tok} ...` pulls remote URL into image",
                        file=rel, line=lineno, ecosystem="dockerfile",
                        spec=line,
                    ))
                    break


def _check_from(rel: str, lineno: int, rest: str, res: ParseResult) -> None:
    # FROM image[:tag][@sha256:digest] [AS name] [--platform=...]
    parts = [p for p in rest.split() if not p.startswith("--")]
    if not parts:
        return
    image = parts[0]
    if image.lower() == "scratch":
        return
    if "@sha256:" in image:
        return  # digest-pinned
    if ":" in image.split("/")[-1]:
        tag = image.split(":")[-1]
        # tag pinned but mutable
        sev = Severity.MEDIUM
        if tag in ("latest", "main", "master", "edge", "stable"):
            sev = Severity.HIGH
        res.findings.append(Finding(
            severity=sev, code="DOCKER_FLOATING_TAG",
            title=f"`FROM {image}` — tag `{tag}` is mutable",
            file=rel, line=lineno, ecosystem="dockerfile", spec=image,
            detail="Pin via `FROM image@sha256:<digest>` for reproducibility.",
        ))
    else:
        res.findings.append(Finding(
            severity=Severity.HIGH, code="DOCKER_NO_TAG",
            title=f"`FROM {image}` — no tag (implicit :latest)",
            file=rel, line=lineno, ecosystem="dockerfile", spec=image,
        ))


def _check_run(rel: str, lineno: int, rest: str, res: ParseResult) -> None:
    for cmd in shellcmd.classify(rest):
        if cmd.is_strict:
            continue
        res.findings.append(Finding(
            severity=cmd.severity, code="INSTALL_NOT_STRICT",
            title=f"Non-lockfile-strict install in Dockerfile: `{cmd.tool}`",
            file=rel, line=lineno, ecosystem="dockerfile",
            spec=cmd.raw, detail=cmd.reason,
        ))
