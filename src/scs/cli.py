"""scs scan — CLI entry point and orchestration."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import sys
import time
from pathlib import Path
from typing import Iterable, Optional

from scs.findings import Finding, ParseResult, RepoReport, ResolvedDep, Severity
from scs.repo import Repo, discover_repos, make_repo
from scs.parsers import PARSERS
from scs.installed import collect_installed
from scs.malware_db import auto_load, MalwareDB
from scs.report.html import render_html
from scs.version import __version__, BUILD_TS


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="scs", description="Supply-chain exposure scanner.")
    sub = p.add_subparsers(dest="cmd", required=False)

    s = sub.add_parser("scan", help="scan one or more repos (or dirs of repos)")
    s.add_argument("paths", nargs="*", default=["."], help="repo or container directories (default: cwd)")
    s.add_argument("--out", default="scs-report.html", help="output HTML report path")
    s.add_argument("--json", dest="json_out", default=None, help="also write JSON results")
    s.add_argument("--offline", action="store_true", help="skip OSV + registry HTTP")
    s.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"], default="high")
    s.add_argument("--strict", action="store_true", help="alias for --fail-on=low")
    s.add_argument("--include", default="", help="comma-list of ecosystems to include (default: all)")
    s.add_argument("--exclude", action="append", default=[], help="path glob to exclude (repeatable)")
    s.add_argument("--concurrency", type=int, default=8)
    s.add_argument("--no-cache", action="store_true", help="bypass HTTP cache")
    s.add_argument("--malware-db", default=None, help="explicit DB path")
    s.add_argument("--no-malware-db", action="store_true", help="disable malware DB lookup")
    s.add_argument("--require-malware-db", action="store_true", help="error if no DB found")
    s.add_argument("--max-depth", type=int, default=2, help="how many levels to descend looking for .git/")

    p.add_argument("--version", action="version", version=f"scs {__version__}")

    args = p.parse_args(argv)
    if not args.cmd:
        # Default to scan with no args
        return _do_scan(p.parse_args(["scan"] + (argv or [])))
    if args.cmd == "scan":
        return _do_scan(args)
    p.print_help(sys.stderr)
    return 2


def _do_scan(args) -> int:
    fail_on = "low" if args.strict else args.fail_on
    threshold = {
        "critical": Severity.CRITICAL, "high": Severity.HIGH,
        "medium": Severity.MEDIUM, "low": Severity.LOW, "none": None,
    }[fail_on]

    include = set(s.strip() for s in args.include.split(",") if s.strip()) if args.include else None
    excludes = list(args.exclude or [])

    repo_paths = discover_repos(args.paths, max_depth=args.max_depth)
    if not repo_paths:
        print("scs: no git repos found in", " ".join(args.paths), file=sys.stderr)

    # Malware DB
    malware_db: Optional[MalwareDB] = None
    malware_db_status = ""
    if not args.no_malware_db:
        sibling = Path(sys.argv[0]).resolve() if sys.argv and sys.argv[0] else None
        malware_db = auto_load(args.malware_db, sibling_to=sibling)
        if malware_db:
            malware_db_status = (
                f"Malware DB loaded: {malware_db.path} "
                f"({malware_db.entry_count} entries, {malware_db.keys_count} packages, "
                f"built {int(malware_db.stale_days())}d ago)"
            )
            if malware_db.stale_days() > 30:
                malware_db_status += " — STALE: re-run `make update-malware-data && make malware-db`"
        elif args.require_malware_db:
            print("scs: --require-malware-db set but no DB found", file=sys.stderr)
            return 3
        else:
            malware_db_status = (
                "No malware DB loaded. Pass --malware-db PATH or build one with `make malware-db` "
                "to enable offline malicious-package detection."
            )

    # Scan repos in parallel
    reports: list[RepoReport] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as pool:
        futures = [pool.submit(_scan_repo, p, include, excludes, malware_db, args.offline) for p in repo_paths]
        for f in concurrent.futures.as_completed(futures):
            try:
                reports.append(f.result())
            except Exception as e:
                reports.append(RepoReport(name="?", path="?", error=str(e)))
    reports.sort(key=lambda r: r.name)

    # Render HTML
    html = render_html(
        reports,
        version=__version__,
        build_ts=BUILD_TS,
        malware_db_path=str(malware_db.path) if malware_db else None,
        malware_db_built_at=malware_db.built_at if malware_db else None,
        malware_db_sha256=malware_db.payload_sha256 if malware_db else None,
        malware_db_entries=malware_db.entry_count if malware_db else None,
        malware_db_keys=malware_db.keys_count if malware_db else None,
        malware_db_status=malware_db_status,
        enrichment_skipped=args.offline,
    )
    out_path = Path(args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    print(f"scs: wrote report to {out_path}")

    if args.json_out:
        jp = Path(args.json_out).resolve()
        jp.parent.mkdir(parents=True, exist_ok=True)
        jp.write_text(json.dumps(_json_dump(reports), indent=2, default=str), encoding="utf-8")
        print(f"scs: wrote JSON to {jp}")

    # Print short summary
    total_findings = sum(len(r.findings) for r in reports)
    sev_counts: dict[Severity, int] = {s: 0 for s in Severity}
    for r in reports:
        for f in r.findings:
            sev_counts[f.severity] += 1
    print(
        f"scs: {len(reports)} repo(s), {total_findings} finding(s) "
        f"(C:{sev_counts[Severity.CRITICAL]} H:{sev_counts[Severity.HIGH]} "
        f"M:{sev_counts[Severity.MEDIUM]} L:{sev_counts[Severity.LOW]} I:{sev_counts[Severity.INFO]})"
    )

    if threshold is None:
        return 0
    worst = max((max((f.severity for f in r.findings), default=Severity.INFO) for r in reports), default=Severity.INFO)
    if int(worst) >= int(threshold):
        return 1
    return 0


def _scan_repo(root: Path, include: Optional[set[str]], excludes: list[str], malware_db: Optional[MalwareDB], offline: bool) -> RepoReport:
    repo = make_repo(root)
    rep = RepoReport(name=root.name, path=str(root))

    # Filter excluded paths
    files = repo.tracked_files
    if excludes:
        from fnmatch import fnmatch
        files = [f for f in files if not any(fnmatch(repo.rel(f), pat) for pat in excludes)]
        repo.tracked_files = files

    # Dispatch by parser
    all_resolved: list[ResolvedDep] = []
    eco_seen: set[str] = set()
    for module in PARSERS:
        if include and module.__name__.split(".")[-1] not in include:
            continue
        ecosystem_files = [f for f in files if module.matches(repo.rel(f))]
        if not ecosystem_files:
            continue
        try:
            res = module.parse(repo, ecosystem_files)
        except Exception as e:
            rep.findings.append(Finding(
                severity=Severity.MEDIUM, code="PARSER_ERROR",
                title=f"{module.__name__} crashed", file="", detail=str(e),
            ))
            continue
        rep.findings.extend(res.findings)
        all_resolved.extend(res.resolved)
        rep.files_scanned += res.files_scanned
        rep.deps_total += res.deps_total
        rep.deps_unpinned += res.deps_unpinned
        # Track ecosystems
        for rd in res.resolved:
            eco_seen.add(rd.ecosystem)
        for f in res.findings:
            if f.ecosystem:
                eco_seen.add(f.ecosystem)

    # Add install-tree deps
    try:
        installed = collect_installed(repo)
        all_resolved.extend(installed)
        for rd in installed:
            eco_seen.add(rd.ecosystem)
    except Exception as e:
        rep.findings.append(Finding(
            severity=Severity.LOW, code="INSTALLED_SCAN_ERROR",
            title="Install-tree introspection failed", file="", detail=str(e),
        ))

    # Cross-reference malware DB
    if malware_db:
        seen_keys: set[tuple[str, str, str]] = set()
        for d in all_resolved:
            k = (d.ecosystem, d.name, d.version)
            if k in seen_keys:
                continue
            seen_keys.add(k)
            adv = malware_db.lookup_str(d.ecosystem, d.name, d.version)
            if adv:
                rep.findings.append(Finding(
                    severity=Severity.CRITICAL, code="MALWARE",
                    title=f"Known-malicious package: {adv.name}@{adv.version}",
                    file=d.source_file, ecosystem=d.ecosystem, package=d.name,
                    resolved_version=d.version, advisory_id=adv.advisory_id,
                    advisory_url=adv.url, aliases=adv.aliases, chain=d.chain,
                    detail=("OSSF malicious-packages match" + (f" (dep chain depth {len(d.chain)})" if d.chain else "")),
                ))

    # Live OSV enrichment
    if not offline and all_resolved:
        try:
            from scs.enrich import parallel_osv_lookup, vulns_to_findings
            vulns = parallel_osv_lookup(all_resolved)
            rep.findings.extend(vulns_to_findings(all_resolved, vulns))
        except Exception as e:
            rep.findings.append(Finding(
                severity=Severity.LOW, code="ENRICH_ERROR",
                title="OSV enrichment failed", file="", detail=str(e),
            ))

    rep.ecosystems = sorted(eco_seen)
    return rep


def _json_dump(reports: list[RepoReport]) -> dict:
    return {
        "repos": [
            {
                "name": r.name,
                "path": r.path,
                "ecosystems": r.ecosystems,
                "grade": r.grade,
                "deps_total": r.deps_total,
                "deps_unpinned": r.deps_unpinned,
                "files_scanned": r.files_scanned,
                "error": r.error,
                "findings": [
                    {
                        "severity": f.severity.name,
                        "code": f.code,
                        "title": f.title,
                        "file": f.file,
                        "line": f.line,
                        "ecosystem": f.ecosystem,
                        "package": f.package,
                        "spec": f.spec,
                        "resolved_version": f.resolved_version,
                        "advisory_id": f.advisory_id,
                        "advisory_url": f.advisory_url,
                        "aliases": list(f.aliases),
                        "chain": list(f.chain),
                        "detail": f.detail,
                    }
                    for f in sorted(r.findings, key=lambda x: x.sort_key())
                ],
            }
            for r in reports
        ],
    }
