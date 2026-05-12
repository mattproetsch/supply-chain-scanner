from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, s: str) -> "Severity":
        return cls[s.upper()]


SEVERITY_GRADE = {
    Severity.INFO: "A",
    Severity.LOW: "B",
    Severity.MEDIUM: "C",
    Severity.HIGH: "D",
    Severity.CRITICAL: "F",
}


@dataclass(frozen=True)
class DepEdge:
    """parent → child relationship in a transitive dep graph."""

    parent_name: str
    parent_version: str
    child_name: str
    child_version: str


@dataclass
class RawDep:
    """A dependency declaration found in a manifest."""

    ecosystem: str
    name: str
    spec: str
    kind: str = "runtime"  # runtime | dev | build | optional | peer
    is_pinned: bool = False
    source_file: str = ""
    line: int = 0


@dataclass
class LockEntry:
    """A resolved entry in a lockfile."""

    ecosystem: str
    name: str
    version: str
    integrity: Optional[str] = None
    resolved: Optional[str] = None
    source_file: str = ""


@dataclass
class ResolvedDep:
    """A resolved (ecosystem, name, version) the orchestrator can cross-reference
    against malware DB + OSV."""

    ecosystem: str
    name: str
    version: str
    source_file: str = ""
    chain: tuple[str, ...] = ()  # parent → … → this; empty means direct


@dataclass
class ParseResult:
    findings: list = field(default_factory=list)
    resolved: list = field(default_factory=list)
    files_scanned: int = 0
    deps_total: int = 0
    deps_unpinned: int = 0


@dataclass
class Finding:
    """A single issue identified in a scanned repo."""

    severity: Severity
    code: str  # e.g. UNPINNED_DIRECT, MISSING_LOCKFILE, MALWARE, INSTALL_NOT_STRICT
    title: str
    file: str  # repo-relative
    ecosystem: str = ""
    package: str = ""
    spec: str = ""
    resolved_version: str = ""
    line: int = 0
    advisory_id: str = ""
    advisory_url: str = ""
    aliases: tuple[str, ...] = ()
    detail: str = ""
    suggestion: str = ""   # concrete fix snippet — rendered as a code block
    chain: tuple[str, ...] = ()  # parent → ... → vulnerable; empty means direct

    def __post_init__(self):
        # If no explicit suggestion, derive one from code.
        if not self.suggestion:
            self.suggestion = _suggest(self)

    def sort_key(self):
        return (-int(self.severity), self.ecosystem, self.file, self.package, self.line)


def _suggest(f: "Finding") -> str:
    """Per-code default fix suggestion. Parsers can override via `suggestion=`."""
    code = f.code
    pkg = f.package or "<package>"
    spec = f.spec or "<spec>"
    eco = f.ecosystem
    if code == "MALWARE":
        return (
            f"Remove `{pkg}` immediately. Audit any system that ran an install of this version:\n"
            "  • Rotate every credential/key that was reachable.\n"
            "  • Check outbound network logs for suspicious domains around install time.\n"
            "  • Pin to a known-good prior version, or switch to a maintained alternative.\n"
            f"Advisory: {f.advisory_url or 'see OSSF malicious-packages dataset'}"
        )
    if code == "VULN_KNOWN":
        return (
            f"Upgrade `{pkg}` past the affected version. Review the advisory for the\n"
            f"fixed-in version and any required code-side changes:\n"
            f"  {f.advisory_url}"
        )
    if code == "UNPINNED_DIRECT":
        if eco == "npm":
            return (
                f"Pin to an exact version in `package.json`:\n"
                f'    "{pkg}": "x.y.z"\n'
                "Then commit the resulting `package-lock.json` and use `npm ci` in CI."
            )
        if eco == "pypi":
            return (
                f"Pin to an exact version with a hash in `requirements.txt`:\n"
                f"    {pkg}==x.y.z --hash=sha256:<digest>\n"
                "Generate with `pip-compile --generate-hashes` (pip-tools) or\n"
                "`uv pip compile --generate-hashes`. Install with\n"
                "`pip install --require-hashes -r requirements.txt`."
            )
        if eco == "crates.io":
            return (
                f"Pin with `=` in `Cargo.toml`:\n"
                f'    {pkg} = "=x.y.z"\n'
                "Commit `Cargo.lock` and build with `cargo build --locked`."
            )
        if eco == "go":
            return (
                f"Use a tagged semver or pseudo-version in `go.mod` (`vMAJOR.MINOR.PATCH`),\n"
                "commit `go.sum`, and build with `-mod=readonly`."
            )
        if eco == "nuget":
            return (
                f'Pin to an exact version in your .csproj:\n'
                f'    <PackageReference Include="{pkg}" Version="x.y.z" />\n'
                "Add `<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>` and\n"
                "run `dotnet restore --use-lock-file && dotnet restore --locked-mode`."
            )
    if code == "MISSING_LOCKFILE":
        if eco == "npm":
            return (
                "Run one of, then commit the result:\n"
                "    npm install --package-lock-only --ignore-scripts\n"
                "    yarn install --frozen-lockfile\n"
                "    pnpm install --frozen-lockfile\n"
                "Then use the lockfile-strict equivalent (`npm ci`, etc.) in CI."
            )
        if eco == "crates.io":
            return "Commit `Cargo.lock` (recommended even for libraries since 2023) and use `cargo build --locked` in CI."
        if eco == "go":
            return "Run `go mod tidy` and commit `go.sum`. Build with `-mod=readonly` to enforce."
        if eco == "nuget":
            return (
                "Add to your project file:\n"
                "    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>\n"
                "Then run `dotnet restore --use-lock-file && dotnet restore --locked-mode` and commit `packages.lock.json`."
            )
    if code == "LOCK_NO_INTEGRITY":
        return (
            "Regenerate the lockfile so it includes integrity hashes:\n"
            "  npm:    rm package-lock.json && npm install --package-lock-only --ignore-scripts\n"
            "  yarn 1: yarn import\n"
            "  pnpm:   pnpm install --frozen-lockfile=false  (then commit)\n"
            "Verify each package row has an `integrity:`/`checksum:`/`hashes:` field."
        )
    if code == "LOCK_NONCANONICAL_SOURCE":
        return (
            "Either confirm the private registry is intentional and document it in the repo's README,\n"
            "or move back to the canonical public registry."
        )
    if code == "GIT_INSTALL":
        return (
            "Switch to a published artifact, or pin the git ref to a 40-char commit SHA:\n"
            "  npm:    \"name\": \"git+https://host/path#deadbeef0123…\"\n"
            "  cargo:  { git = \"https://host/path\", rev = \"deadbeef0123…\" }\n"
            "  pip:    git+https://host/path@deadbeef0123…"
        )
    if code == "HTTP_INSTALL":
        return (
            "Move this dependency to its package registry release (with integrity hashes), or vendor\n"
            "the artifact, verify its sha256, and commit the bytes alongside attribution."
        )
    if code == "VCS_INSTALL":
        return (
            "Replace the git URL with a release on PyPI, or pin to a 40-char commit SHA and add `--hash=`:\n"
            "    git+https://host/repo@<40-char-sha>#egg=name --hash=sha256:<digest>"
        )
    if code == "EDITABLE_INSTALL":
        return "Use editable installs only in development; replace with a pinned wheel for CI/production builds."
    if code == "PINNED_NO_HASH":
        return (
            f"Add `--hash=sha256:<digest>` to the `{pkg}=={spec.lstrip('==')}` line. Easiest:\n"
            "    pip-compile --generate-hashes  # pip-tools\n"
            "    uv pip compile --generate-hashes\n"
            "Then install with `pip install --require-hashes -r requirements.txt`."
        )
    if code == "ACTION_UNPINNED_REF":
        return (
            "Pin to a 40-char commit SHA. Find the SHA on the action's GitHub releases page:\n"
            f"    uses: {pkg}@<40-char-sha>  # was {spec}\n"
            "Tools like `pin-github-action` can do this automatically across a workflow file."
        )
    if code == "ACTION_NO_REF":
        return f"Add a `@<40-char-sha>` ref: `uses: {pkg}@<sha>`."
    if code == "DOCKER_FLOATING_TAG":
        return (
            "Replace the tag with a sha256 digest:\n"
            f"    {spec.split(':')[0]}@sha256:<digest>\n"
            "Find the digest with `docker buildx imagetools inspect <image:tag>` or `crane digest`."
        )
    if code == "DOCKER_NO_TAG":
        return (
            "Add an explicit tag AND digest:\n"
            f"    FROM {spec}:<tag>@sha256:<digest>"
        )
    if code == "INCLUDE_BRANCH_REF":
        return "Pin the included project to a tag or 40-char SHA, not a branch (branches can be force-pushed)."
    if code == "INSTALL_NOT_STRICT":
        # The shellcmd module already put a clear `reason` into `detail`; leave suggestion empty
        # so we don't double up. The fix is implicit in the title/detail text.
        return ""
    if code == "DOCKERFILE_ADD_URL":
        return (
            "Replace `ADD <url>` with `RUN curl -fsSL <url> -o /path && echo '<sha256>  /path' | sha256sum -c -`\n"
            "to verify integrity. Better yet, vendor the file at build time."
        )
    if code == "GO_REPLACE":
        return ""  # informational
    return ""


@dataclass
class RepoReport:
    name: str
    path: str
    ecosystems: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    deps_total: int = 0
    deps_unpinned: int = 0
    error: Optional[str] = None

    @property
    def grade(self) -> str:
        if not self.findings:
            return "A"
        return SEVERITY_GRADE[Severity(max(int(f.severity) for f in self.findings))]

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return Severity(max(int(f.severity) for f in self.findings))

    def severity_counts(self) -> dict[Severity, int]:
        c = {s: 0 for s in Severity}
        for f in self.findings:
            c[f.severity] += 1
        return c
