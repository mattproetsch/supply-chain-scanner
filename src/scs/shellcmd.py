"""Tokenize shell pipelines and classify install commands.

Designed for Dockerfile RUN lines and CI run/script blocks. We focus on
*recognizing* known package manager commands and answering "is this
lockfile-strict?" — we do NOT execute anything.

Returns a list of `InstallCmd` records describing each detected install.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Optional

from .findings import Severity


@dataclass
class InstallCmd:
    tool: str            # npm, yarn, pnpm, pip, poetry, uv, cargo, go, dotnet, apt, apk, brew, curlpipe
    raw: str             # original token list joined
    is_strict: bool      # lockfile-strict / verified install?
    severity: Severity   # if not strict, what severity
    reason: str          # short human explanation
    consumed_file: Optional[str] = None  # e.g. requirements.txt referenced via -r


CURL_PIPE_RE = re.compile(r"\b(curl|wget)\b[^|;&]*\|\s*(bash|sh|zsh)\b")


def split_pipeline(line: str) -> list[list[str]]:
    """Split a shell line into command-token lists.

    Handles `&&`, `;`, `|`, line continuations (`\\`), and very simple quoting.
    Returns `[]` if the line has no commands.
    """
    line = line.strip()
    if not line:
        return []
    # Replace literal `\<newline>` with space (for Dockerfile multi-line RUN already joined)
    line = re.sub(r"\\\s*\n\s*", " ", line)
    # Strip trailing inline `# comment` — shlex.posix does NOT treat `#` as a
    # comment, so `npm install # foo` would otherwise tokenize to 4 args and
    # we'd misclassify (or pick up `# foo` as a positional).  Comment must
    # follow whitespace so we don't shred URL fragments inside arguments.
    line = re.sub(r"(^|\s)#.*$", lambda m: m.group(1), line).rstrip()
    if not line:
        return []
    # Split by separators that *terminate* a command. We treat `|` like a separator
    # but preserve curl|sh detection by also returning the joined line for matching.
    parts = re.split(r"\s*(?:&&|;|\|\||\|)\s*", line)
    out: list[list[str]] = []
    for p in parts:
        p = p.strip()
        if not p:
            continue
        try:
            toks = shlex.split(p, posix=True)
        except ValueError:
            toks = p.split()
        if toks and toks[0] in ("env", "sudo", "exec", "time"):
            # Strip leading wrappers
            i = 1
            while i < len(toks) and "=" in toks[i] and toks[0] == "env":
                i += 1
            toks = toks[i:]
        if toks:
            out.append(toks)
    return out


def classify(line: str) -> list[InstallCmd]:
    """Return zero or more InstallCmd for a single shell line."""
    out: list[InstallCmd] = []

    # First, the pipeline-level pattern: curl ... | bash
    if CURL_PIPE_RE.search(line):
        out.append(InstallCmd(
            tool="curlpipe",
            raw=line.strip(),
            is_strict=False,
            severity=Severity.CRITICAL,
            reason="`curl|sh`-style install: unverified script execution from network",
        ))

    for toks in split_pipeline(line):
        cmd = _classify_one(toks)
        if cmd:
            out.append(cmd)
    return out


def _classify_one(toks: list[str]) -> Optional[InstallCmd]:
    if not toks:
        return None
    raw = " ".join(toks)
    head = toks[0]
    sub = toks[1] if len(toks) > 1 else ""
    args = toks[2:] if len(toks) > 2 else []
    flags = set(args)

    # --- npm
    if head == "npm":
        if sub in ("install", "i", "add") and not _has_arg_pkg(args, exclude_flags=True):
            # `npm install` (no pkg) — depends on lockfile
            if "--ignore-scripts" in flags and any(f.startswith("--package-lock-only") for f in flags):
                return InstallCmd("npm", raw, True, Severity.INFO, "lockfile-only mode, no scripts")
            return InstallCmd("npm", raw, False, Severity.HIGH, "use `npm ci` instead of `npm install` to enforce lockfile")
        if sub in ("install", "i", "add") and _has_arg_pkg(args):
            return InstallCmd("npm", raw, False, Severity.HIGH, "ad-hoc package install bypasses lockfile")
        if sub == "ci":
            return InstallCmd("npm", raw, True, Severity.INFO, "lockfile-strict")

    # --- yarn
    if head == "yarn":
        if sub in ("", "install"):
            if "--frozen-lockfile" in flags or "--immutable" in flags:
                return InstallCmd("yarn", raw, True, Severity.INFO, "lockfile-strict")
            return InstallCmd("yarn", raw, False, Severity.HIGH, "use `--frozen-lockfile` (yarn 1) or `--immutable` (yarn 2+)")
        if sub == "add":
            return InstallCmd("yarn", raw, False, Severity.HIGH, "ad-hoc package install bypasses lockfile")

    # --- pnpm
    if head == "pnpm":
        if sub in ("install", "i", ""):
            if "--frozen-lockfile" in flags:
                return InstallCmd("pnpm", raw, True, Severity.INFO, "lockfile-strict")
            return InstallCmd("pnpm", raw, False, Severity.HIGH, "use `pnpm install --frozen-lockfile`")
        if sub in ("add",):
            return InstallCmd("pnpm", raw, False, Severity.HIGH, "ad-hoc package install bypasses lockfile")

    # --- pip / pip3 / python -m pip
    pip_verb = None
    pip_rest: list[str] = []
    if head in ("pip", "pip3"):
        pip_verb = sub
        pip_rest = args
    elif head in ("python", "python3", "python3.10", "python3.11", "python3.12", "python3.13", "python3.14") \
            and sub == "-m" and len(toks) > 2 and toks[2] == "pip":
        pip_verb = toks[3] if len(toks) > 3 else ""
        pip_rest = toks[4:] if len(toks) > 4 else []
    if pip_verb is not None:
        if pip_verb == "install":
            require_hashes = "--require-hashes" in pip_rest
            dry = "--dry-run" in pip_rest
            req_files = _collect_req_files(pip_rest)
            if dry:
                return InstallCmd("pip", raw, True, Severity.INFO, "dry-run; safe")
            if _has_pip_pkg_arg(pip_rest):
                return InstallCmd("pip", raw, False, Severity.HIGH, "installing un-locked packages directly in CI")
            if "-e" in pip_rest:
                return InstallCmd("pip", raw, False, Severity.MEDIUM, "editable install resolves at build time")
            if req_files and not require_hashes:
                return InstallCmd("pip", raw, False, Severity.HIGH, f"`-r {req_files[0]}` without `--require-hashes`", consumed_file=req_files[0])
            if req_files and require_hashes:
                return InstallCmd("pip", raw, True, Severity.INFO, f"hash-verified install of {req_files[0]}", consumed_file=req_files[0])

    # --- poetry
    if head == "poetry":
        if sub == "install":
            return InstallCmd("poetry", raw, True, Severity.INFO, "uses poetry.lock when present")
        if sub in ("add", "update"):
            return InstallCmd("poetry", raw, False, Severity.HIGH, "mutates poetry.lock — should not run in CI build step")

    # --- uv
    if head == "uv":
        if sub == "sync" or (sub == "pip" and len(toks) > 2 and toks[2] in ("sync",)):
            return InstallCmd("uv", raw, True, Severity.INFO, "uv lockfile-strict sync")
        if sub == "pip" and len(toks) > 2 and toks[2] == "install":
            return InstallCmd("uv", raw, False, Severity.HIGH, "use `uv sync` or `uv pip sync` for reproducible installs")

    # --- cargo
    if head == "cargo":
        if sub in ("build", "install", "test", "run", "fetch"):
            if "--locked" in flags or "--frozen" in flags:
                return InstallCmd("cargo", raw, True, Severity.INFO, "lockfile-strict (--locked/--frozen)")
            return InstallCmd("cargo", raw, False, Severity.HIGH, f"`cargo {sub}` should use `--locked` or `--frozen`")

    # --- go
    if head == "go":
        if sub == "install":
            # `go install pkg@latest` → floating
            for a in args:
                if a.endswith("@latest") or a.endswith("@master") or a.endswith("@main"):
                    return InstallCmd("go", raw, False, Severity.HIGH, f"`go install {a}` resolves to a moving ref")
            return InstallCmd("go", raw, True, Severity.INFO, "go install with pinned version")
        if sub in ("build", "test", "run"):
            mod_readonly = any("-mod=readonly" in a or "-mod=vendor" in a for a in args)
            if not mod_readonly:
                return InstallCmd("go", raw, False, Severity.MEDIUM, f"`go {sub}` should use `-mod=readonly` or `-mod=vendor`")
            return InstallCmd("go", raw, True, Severity.INFO, "lockfile-strict (-mod=readonly/vendor)")
        if sub in ("get",):
            return InstallCmd("go", raw, False, Severity.MEDIUM, "`go get` mutates go.mod — should not run in CI build step")

    # --- dotnet
    if head == "dotnet":
        if sub == "restore":
            if "--locked-mode" in flags:
                return InstallCmd("dotnet", raw, True, Severity.INFO, "lockfile-strict")
            return InstallCmd("dotnet", raw, False, Severity.HIGH, "`dotnet restore` should use `--locked-mode` (and `<RestorePackagesWithLockFile>true</…>`)")
        if sub == "add" and len(toks) > 2 and toks[2] == "package":
            return InstallCmd("dotnet", raw, False, Severity.HIGH, "ad-hoc package add in CI")

    # --- system pkg managers
    if head in ("apt-get", "apt"):
        if sub in ("install",):
            if not _all_pinned_apt(args):
                return InstallCmd("apt", raw, False, Severity.MEDIUM, "system packages installed without version pin")
            return InstallCmd("apt", raw, True, Severity.INFO, "version-pinned apt install")
    if head == "apk":
        if sub == "add":
            if any("=" in a and not a.startswith("-") for a in args):
                return InstallCmd("apk", raw, True, Severity.INFO, "version-pinned apk add")
            return InstallCmd("apk", raw, False, Severity.MEDIUM, "system packages installed without version pin")
    if head == "brew":
        if sub == "install":
            return InstallCmd("brew", raw, False, Severity.MEDIUM, "homebrew installs are not pinned by default")

    return None


def _has_arg_pkg(args: list[str], exclude_flags: bool = False) -> bool:
    for a in args:
        if a.startswith("-"):
            continue
        return True
    return False


def _has_pip_pkg_arg(args: list[str]) -> bool:
    skip_next = False
    for a in args:
        if skip_next:
            skip_next = False
            continue
        if a in ("-r", "--requirement", "-c", "--constraint", "-e", "--editable", "--target", "--prefix", "--root", "-i", "--index-url", "--extra-index-url", "-f", "--find-links"):
            skip_next = True
            continue
        if a.startswith("-"):
            continue
        # Looks like a package spec
        return True
    return False


def _collect_req_files(args: list[str]) -> list[str]:
    out: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-r", "--requirement") and i + 1 < len(args):
            out.append(args[i + 1])
            i += 2
            continue
        if a.startswith("--requirement="):
            out.append(a.split("=", 1)[1])
        i += 1
    return out


def _all_pinned_apt(args: list[str]) -> bool:
    pkgs = [a for a in args if not a.startswith("-")]
    if not pkgs:
        return True
    return all("=" in p for p in pkgs)
