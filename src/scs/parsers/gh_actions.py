"""GitHub Actions workflow + composite action parsing.

Files handled:
  .github/workflows/*.yml | *.yaml
  .github/actions/*/action.yml | action.yaml
  action.yml at repo root (composite action repos)

Findings:
  - `uses: <owner>/<repo>@<ref>` where ref is not a 40-char hex SHA → HIGH for
    third-party owners, MEDIUM for `actions/`, `github/`, etc.
  - `uses: docker://<image>:<tag>` without `@sha256:` → MEDIUM
  - `run:` blocks scanned by shellcmd for non-strict install commands.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from scs.findings import Finding, ParseResult, Severity
from scs.repo import Repo
from scs import yaml_lite, shellcmd


SHA40 = re.compile(r"^[0-9a-fA-F]{40}$")
TRUSTED_OWNERS = {"actions", "github", "actions-rs"}


def matches(rel_path: str) -> bool:
    p = Path(rel_path)
    parts = p.parts
    if "workflows" in parts and ".github" in parts and p.suffix in (".yml", ".yaml"):
        return True
    if p.name in {"action.yml", "action.yaml"}:
        return True
    return False


def parse(repo: Repo, files: Iterable[Path]) -> ParseResult:
    res = ParseResult()
    for f in files:
        res.files_scanned += 1
        _scan_workflow(repo, f, res)
    return res


def _scan_workflow(repo: Repo, path: Path, res: ParseResult) -> None:
    rel = repo.rel(path)
    try:
        text = path.read_text()
    except Exception as e:
        res.findings.append(Finding(
            severity=Severity.MEDIUM, code="PARSE_ERROR",
            title=f"{path.name} read error", file=rel, ecosystem="gh_actions", detail=str(e),
        ))
        return
    # Walk text looking for `uses:` and `run:` lines (with line numbers preserved).
    # Using yaml_lite for structure makes line tracking harder, so we mix:
    # YAML-parse for structure, then re-scan text for line numbers.
    line_uses: list[tuple[int, str]] = []
    line_runs: list[tuple[int, str]] = []
    for i, raw in enumerate(text.splitlines(), 1):
        s = raw.strip()
        # Allow both `uses: ...` and `- uses: ...`
        if s.startswith("- uses:"):
            s_uses = s[len("- uses:"):]
        elif s.startswith("uses:"):
            s_uses = s[len("uses:"):]
        else:
            s_uses = None
        if s_uses is not None:
            val = s_uses.strip().strip("'\"")
            if val:
                line_uses.append((i, val))
        elif s.startswith("run:"):
            # Collect potentially multi-line block
            inline = s[4:].strip()
            if inline.startswith("|") or inline.startswith(">"):
                # Block scalar; collect indented lines until dedent
                base_ind = len(raw) - len(raw.lstrip())
                block_lines: list[str] = []
                j = i
                # we're iterating with enumerate so we can't peek easily — use second pass
                line_runs.append((i, "<BLOCK>"))
            else:
                line_runs.append((i, inline))

    # Second pass to capture multi-line `run: |` blocks
    lines = text.splitlines()
    in_block = False
    block_indent = 0
    block_start = 0
    block_buf: list[str] = []
    blocks: list[tuple[int, str]] = []
    for i, raw in enumerate(lines, 1):
        if not in_block:
            s = raw.strip()
            if s.startswith("run:") and (s.endswith("|") or s.endswith(">")):
                in_block = True
                block_start = i + 1
                block_indent = len(raw) - len(raw.lstrip()) + 2
                block_buf = []
            continue
        # In block — does line still belong?
        if not raw.strip():
            block_buf.append("")
            continue
        ind = len(raw) - len(raw.lstrip())
        if ind < block_indent:
            in_block = False
            blocks.append((block_start, "\n".join(block_buf).strip()))
            continue
        block_buf.append(raw[block_indent:])
    if in_block and block_buf:
        blocks.append((block_start, "\n".join(block_buf).strip()))

    for lineno, val in line_uses:
        _check_uses(rel, lineno, val, res)
    for lineno, val in line_runs:
        if val == "<BLOCK>":
            continue
        _scan_run_line(rel, lineno, val, res)
    for lineno, body in blocks:
        for off, ln in enumerate(body.splitlines()):
            _scan_run_line(rel, lineno + off, ln, res)


def _check_uses(rel: str, lineno: int, val: str, res: ParseResult) -> None:
    if val.startswith("./") or val.startswith("../"):
        res.findings.append(Finding(
            severity=Severity.INFO, code="ACTION_LOCAL",
            title=f"Local action: {val}",
            file=rel, line=lineno, ecosystem="gh_actions", spec=val,
        ))
        return
    if val.startswith("docker://"):
        if "@sha256:" not in val:
            res.findings.append(Finding(
                severity=Severity.MEDIUM, code="DOCKER_FLOATING_TAG",
                title=f"Docker image without sha256 digest: {val}",
                file=rel, line=lineno, ecosystem="gh_actions", spec=val,
                detail="Use `docker://image@sha256:<digest>` to pin.",
            ))
        return
    if "@" not in val:
        res.findings.append(Finding(
            severity=Severity.HIGH, code="ACTION_NO_REF",
            title=f"`uses:` without ref: {val}",
            file=rel, line=lineno, ecosystem="gh_actions", spec=val,
        ))
        return
    repo_part, ref = val.split("@", 1)
    owner = repo_part.split("/", 1)[0] if "/" in repo_part else repo_part
    if SHA40.match(ref):
        return  # SHA-pinned — good
    is_trusted = owner in TRUSTED_OWNERS
    sev = Severity.MEDIUM if is_trusted else Severity.HIGH
    title = f"`uses: {val}` — ref `{ref}` is not a 40-char SHA"
    detail = (
        "Branches and tags can be force-moved by the action's owner; pin to a commit "
        "SHA. (Critical attack vector — see tj-actions/changed-files compromise of March 2025.)"
    )
    res.findings.append(Finding(
        severity=sev, code="ACTION_UNPINNED_REF",
        title=title, file=rel, line=lineno, ecosystem="gh_actions",
        package=repo_part, spec=val, detail=detail,
    ))


def _scan_run_line(rel: str, lineno: int, line: str, res: ParseResult) -> None:
    for cmd in shellcmd.classify(line):
        if cmd.is_strict:
            continue
        res.findings.append(Finding(
            severity=cmd.severity, code="INSTALL_NOT_STRICT",
            title=f"Non-lockfile-strict install in workflow: `{cmd.tool}`",
            file=rel, line=lineno, ecosystem="gh_actions",
            spec=cmd.raw, detail=cmd.reason,
        ))
