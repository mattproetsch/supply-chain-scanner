"""Live enrichment — OSV vuln lookup + registry resolution.

Concurrency via ThreadPoolExecutor. HTTP cache lives in scs.http.
"""

from __future__ import annotations

import concurrent.futures
import re
from typing import Iterable

from scs.findings import Finding, ResolvedDep, Severity
from scs import http


OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
ECO_TO_OSV = {
    "npm": "npm",
    "pypi": "PyPI",
    "crates.io": "crates.io",
    "go": "Go",
    "nuget": "NuGet",
    "maven": "Maven",
    "rubygems": "RubyGems",
}


def osv_query_batch(deps: Iterable[ResolvedDep], chunk: int = 1000) -> dict[tuple[str, str, str], list[dict]]:
    """Return {(eco, name, version) → [osv vulns]}."""
    deps = list({(d.ecosystem, d.name, d.version): d for d in deps}.values())
    out: dict[tuple[str, str, str], list[dict]] = {}
    if not deps:
        return out
    for i in range(0, len(deps), chunk):
        batch = deps[i:i + chunk]
        queries = []
        for d in batch:
            eco_osv = ECO_TO_OSV.get(d.ecosystem)
            if not eco_osv or not d.version:
                continue
            queries.append({
                "package": {"name": d.name, "ecosystem": eco_osv},
                "version": d.version,
            })
        if not queries:
            continue
        resp = http.post_json(OSV_BATCH_URL, {"queries": queries})
        if not resp:
            continue
        results = resp.get("results") or []
        for d, r in zip(batch, results):
            vulns = r.get("vulns") or []
            if vulns:
                out[(d.ecosystem, d.name, d.version)] = vulns
    return out


def osv_vuln_details(vuln_id: str) -> dict | None:
    return http.get_json(OSV_VULN_URL.format(id=vuln_id))


def vulns_to_findings(deps: list[ResolvedDep], vulns_by_key: dict[tuple[str, str, str], list[dict]]) -> list[Finding]:
    out: list[Finding] = []
    by_key: dict[tuple[str, str, str], list[ResolvedDep]] = {}
    for d in deps:
        by_key.setdefault((d.ecosystem, d.name, d.version), []).append(d)
    for (eco, name, ver), vulns in vulns_by_key.items():
        sources = by_key.get((eco, name, ver), [])
        for v in vulns:
            vid = v.get("id") or ""
            summary = v.get("summary") or v.get("details", "")[:160]
            sev = _osv_severity(v)
            for src in sources or [None]:
                out.append(Finding(
                    severity=sev,
                    code="VULN_KNOWN",
                    title=f"{vid}: {name}@{ver} — {summary[:120]}",
                    file=src.source_file if src else "",
                    ecosystem=eco,
                    package=name,
                    resolved_version=ver,
                    advisory_id=vid,
                    advisory_url=f"https://osv.dev/vulnerability/{vid}",
                    aliases=tuple(v.get("aliases") or []),
                    chain=src.chain if src else (),
                    detail=summary,
                ))
    return out


def _osv_severity(vuln: dict) -> Severity:
    # Prefer CVSS-derived severity from `severity` array
    for s in vuln.get("severity") or []:
        score = s.get("score") or ""
        if isinstance(score, str) and score.upper().startswith("CVSS:"):
            # Extract base score if available — last group like "/AV:N/.../9.8"
            m = re.search(r"\b(\d+\.\d+)\b", score)
            if m:
                v = float(m.group(1))
                if v >= 9.0:
                    return Severity.CRITICAL
                if v >= 7.0:
                    return Severity.HIGH
                if v >= 4.0:
                    return Severity.MEDIUM
                return Severity.LOW
    # CWE-506 (malicious code) or MAL- prefix → CRITICAL
    if (vuln.get("id") or "").startswith("MAL-"):
        return Severity.CRITICAL
    db_spec = vuln.get("database_specific") or {}
    sev = db_spec.get("severity") or ""
    return {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}.get(str(sev).upper(), Severity.HIGH)


def parallel_osv_lookup(deps: Iterable[ResolvedDep], concurrency: int = 8) -> dict[tuple[str, str, str], list[dict]]:
    """Convenience wrapper that batches OSV queries; returns vuln results.
    OSV's batch endpoint already handles ≤1000 in one HTTP call so we typically
    only need 1–4 calls; we still parallelize for very large workloads."""
    deps = list(deps)
    if len(deps) <= 1000:
        return osv_query_batch(deps)
    chunks = [deps[i:i + 1000] for i in range(0, len(deps), 1000)]
    out: dict[tuple[str, str, str], list[dict]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        for r in pool.map(osv_query_batch, chunks):
            out.update(r)
    return out
