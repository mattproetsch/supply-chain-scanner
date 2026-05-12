"""GitLab CI / .gitlab-ci.yml parsing.

Findings:
  - `image: <name>:<tag>` without `@sha256:` → MEDIUM
  - `include: { project, ref }` where ref is a branch (not SHA/tag) → HIGH
  - `script:`/`before_script:`/`after_script:` blocks scanned via shellcmd
    for non-lockfile-strict install commands.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from scs.findings import Finding, ParseResult, Severity
from scs.repo import Repo
from scs import shellcmd


SHA40 = re.compile(r"^[0-9a-fA-F]{40}$")


def matches(rel_path: str) -> bool:
    p = Path(rel_path)
    if p.name == ".gitlab-ci.yml":
        return True
    # GitLab `include:` files are arbitrary YAMLs; detection is up to the user.
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
            title=f"{path.name} read error", file=rel, ecosystem="gitlab_ci", detail=str(e),
        ))
        return

    lines = text.splitlines()
    # Find `image:` and `include:` lines
    for i, raw in enumerate(lines, 1):
        s = raw.strip()
        if s.startswith("image:"):
            val = s[6:].strip().strip("'\"")
            if val and not val.startswith("$"):
                _check_image(rel, i, val, res)
        elif s.startswith("- ref:") or s.startswith("ref:"):
            # Inside an `include:` mapping — best-effort
            val = s.split(":", 1)[1].strip().strip("'\"")
            if val and not SHA40.match(val) and val not in ("main", "master") and not re.fullmatch(r"v?\d+(?:\.\d+){0,2}(?:-[\w.\-+]+)?", val):
                pass  # treat below
            if val and not SHA40.match(val):
                # branch / tag / something
                # tags are usually safe (immutable per convention), but Git tags can be re-pointed.
                if val in ("main", "master", "develop", "staging"):
                    res.findings.append(Finding(
                        severity=Severity.HIGH, code="INCLUDE_BRANCH_REF",
                        title=f"`include` ref is a branch: {val}",
                        file=rel, line=i, ecosystem="gitlab_ci", spec=val,
                        detail="Branches can be force-pushed by the upstream owner; pin to a commit SHA or tag.",
                    ))

    # Walk YAML-ish script blocks
    in_script = False
    script_indent = 0
    script_start = 0
    script_buf: list[str] = []
    script_buffers: list[tuple[int, str]] = []
    SCRIPT_KEYS = ("script:", "before_script:", "after_script:", "run:")
    for i, raw in enumerate(lines, 1):
        if not in_script:
            s = raw.strip()
            if any(s.startswith(k) for k in SCRIPT_KEYS):
                inline = s.split(":", 1)[1].strip()
                if not inline or inline in ("|", ">"):
                    in_script = True
                    script_indent = len(raw) - len(raw.lstrip()) + 2
                    script_start = i + 1
                    script_buf = []
                else:
                    # Single-line script (sometimes shown inline)
                    script_buffers.append((i, inline))
            continue
        if not raw.strip():
            script_buf.append("")
            continue
        ind = len(raw) - len(raw.lstrip())
        if ind < script_indent:
            in_script = False
            script_buffers.append((script_start, "\n".join(script_buf).strip()))
        else:
            block_line = raw[script_indent:]
            # Each `- cmd` item or naked line
            if block_line.startswith("- "):
                block_line = block_line[2:]
            script_buf.append(block_line)
    if in_script and script_buf:
        script_buffers.append((script_start, "\n".join(script_buf).strip()))

    for start, body in script_buffers:
        for off, ln in enumerate(body.splitlines()):
            for cmd in shellcmd.classify(ln):
                if cmd.is_strict:
                    continue
                res.findings.append(Finding(
                    severity=cmd.severity, code="INSTALL_NOT_STRICT",
                    title=f"Non-lockfile-strict install in CI: `{cmd.tool}`",
                    file=rel, line=start + off, ecosystem="gitlab_ci",
                    spec=cmd.raw, detail=cmd.reason,
                ))


def _check_image(rel: str, lineno: int, val: str, res: ParseResult) -> None:
    if "@sha256:" in val:
        return  # digest-pinned
    # Allow "scratch" / images with no tag (defaults to :latest, which IS bad)
    if ":" not in val.split("/")[-1]:
        res.findings.append(Finding(
            severity=Severity.MEDIUM, code="DOCKER_FLOATING_TAG",
            title=f"`image: {val}` — no tag (implicit :latest)",
            file=rel, line=lineno, ecosystem="gitlab_ci", spec=val,
        ))
        return
    res.findings.append(Finding(
        severity=Severity.MEDIUM, code="DOCKER_FLOATING_TAG",
        title=f"`image: {val}` — tag without sha256 digest",
        file=rel, line=lineno, ecosystem="gitlab_ci", spec=val,
        detail="Pin via `image: name@sha256:<digest>`.",
    ))
