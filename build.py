#!/usr/bin/env python3
"""scs build helper — stdlib only, runs on the build host.

Subcommands:
  vendor              Fetch + verify pinned wheels into src/scs/_vendor/
  bundle              Concatenate src/scs/ into a single dist/scs.py
  compact-malware-db  Compact OSSF malicious-packages OSV files into a sidecar binary

All subcommands are intended to be called from the Makefile.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import os
import re
import shutil
import struct
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Iterable, Optional

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src" / "scs"
VENDOR_DIR = SRC / "_vendor"
DIST = ROOT / "dist"

PYPI_JSON = "https://pypi.org/pypi/{name}/{version}/json"
QUARANTINE_SECONDS = 7 * 24 * 3600
USER_AGENT = "scs-build/0.1"


# ──────────────────────────────────────────────────────────────────────────
# vendor
# ──────────────────────────────────────────────────────────────────────────

VENDOR_LINE_RE = re.compile(
    r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-+!]+)\s+--hash=sha256:([0-9a-fA-F]{64})\s*$"
)


def _read_vendor_file(path: Path) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = VENDOR_LINE_RE.match(line)
        if not m:
            sys.exit(f"vendor.txt: malformed line (need 'name==ver --hash=sha256:HEX'): {raw!r}")
        out.append((m.group(1), m.group(2), m.group(3).lower()))
    return out


def _fetch_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def _fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def _pick_wheel(meta: dict, name: str, version: str) -> dict:
    files = meta.get("urls") or []
    cands = [
        f for f in files
        if f.get("packagetype") == "bdist_wheel"
        and f.get("filename", "").endswith("-py3-none-any.whl")
    ]
    # Some distros use py2.py3 universal
    cands += [
        f for f in files
        if f.get("packagetype") == "bdist_wheel"
        and "-py2.py3-none-any" in f.get("filename", "")
        and f not in cands
    ]
    if not cands:
        sys.exit(f"vendor: no pure-Python wheel for {name}=={version}")
    # Prefer the lexicographically smallest filename (deterministic).
    cands.sort(key=lambda f: f["filename"])
    return cands[0]


def _verify_age(file_meta: dict, name: str, version: str) -> None:
    upload = file_meta.get("upload_time_iso_8601") or file_meta.get("upload_time")
    if not upload:
        sys.exit(f"vendor: {name}=={version} has no upload_time on PyPI")
    # Strip trailing Z if present, parse ISO.
    s = upload.rstrip("Z")
    try:
        ts = dt.datetime.fromisoformat(s)
    except ValueError:
        sys.exit(f"vendor: cannot parse upload time {upload!r} for {name}=={version}")
    age = time.time() - ts.replace(tzinfo=dt.timezone.utc).timestamp() if ts.tzinfo else time.time() - ts.timestamp()
    if age < QUARANTINE_SECONDS:
        days = age / 86400
        sys.exit(
            f"vendor: refusing {name}=={version} — uploaded {days:.1f} days ago "
            f"(quarantine: 7 days, mitigates fresh supply-chain compromises)"
        )


def _verify_pure_python(z: zipfile.ZipFile, name: str) -> None:
    bad = []
    for n in z.namelist():
        nl = n.lower()
        if nl.endswith(".so") or nl.endswith(".pyd") or nl.endswith(".dylib") or nl.endswith(".dll"):
            bad.append(n)
    if bad:
        sys.exit(f"vendor: {name} contains native code (refusing): {bad[:3]}")


def _extract_wheel(z: zipfile.ZipFile, name: str, dest_root: Path) -> None:
    """Extract the importable package(s) from the wheel into dest_root/<pkg>/.

    Wheels lay out top-level packages directly in the archive root (alongside
    a `<distname>-<ver>.dist-info/` dir). We copy each top-level dir that
    contains an `__init__.py` (or the namespace flat .py files belonging to
    a single-module distribution).
    """
    dist_info_re = re.compile(rf"^[^/]+\.dist-info/")
    data_re = re.compile(rf"^[^/]+\.data/")
    # Discover top-level package dirs and standalone modules
    top_dirs: set[str] = set()
    top_files: set[str] = set()
    for n in z.namelist():
        if dist_info_re.match(n) or data_re.match(n):
            continue
        first = n.split("/", 1)[0]
        if "/" in n:
            top_dirs.add(first)
        elif n.endswith(".py"):
            top_files.add(first)
    if not top_dirs and not top_files:
        sys.exit(f"vendor: could not find package contents in wheel for {name}")
    # Wipe any prior extraction of this name
    for candidate in list(top_dirs) + [Path(f).stem for f in top_files]:
        target = dest_root / candidate
        if target.exists():
            if target.is_dir():
                shutil.rmtree(target)
            else:
                target.unlink()
    for n in z.namelist():
        if dist_info_re.match(n) or data_re.match(n):
            continue
        if n.endswith("/"):
            continue
        out_path = dest_root / n
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with z.open(n) as src, open(out_path, "wb") as dst:
            shutil.copyfileobj(src, dst)
    # Save license info per dep for attribution (LICENSE / LICENSE.txt under .dist-info/)
    license_text = ""
    for n in z.namelist():
        if dist_info_re.match(n) and Path(n).name.upper().startswith("LICENSE"):
            with z.open(n) as f:
                license_text += f"--- {n} ---\n" + f.read().decode("utf-8", "replace") + "\n"
    if license_text:
        for d in top_dirs:
            lic_path = dest_root / d / "_LICENSE.txt"
            if not lic_path.exists():
                lic_path.write_text(license_text, encoding="utf-8")


def cmd_vendor(args) -> int:
    vendor_file = Path(args.vendor_file).resolve()
    out_root = Path(args.out).resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    deps = _read_vendor_file(vendor_file)
    if not deps:
        print("vendor: no entries in", vendor_file)
        return 0
    for name, version, expected_sha in deps:
        print(f"vendor: {name}=={version}")
        meta = _fetch_json(PYPI_JSON.format(name=name, version=version))
        file_meta = _pick_wheel(meta, name, version)
        _verify_age(file_meta, name, version)
        # Verify the hash on PyPI matches what we pinned
        registry_sha = (file_meta.get("digests") or {}).get("sha256", "").lower()
        if registry_sha and registry_sha != expected_sha:
            sys.exit(
                f"vendor: PyPI's recorded sha256 for {name}=={version} ({registry_sha}) "
                f"does not match vendor.txt ({expected_sha}) — refusing"
            )
        body = _fetch(file_meta["url"])
        got = hashlib.sha256(body).hexdigest()
        if got != expected_sha:
            sys.exit(
                f"vendor: download hash mismatch for {name}=={version} — "
                f"expected {expected_sha}, got {got}"
            )
        with zipfile.ZipFile(io.BytesIO(body)) as z:
            _verify_pure_python(z, name)
            _extract_wheel(z, name, out_root)
        print(f"  ok ({len(body)//1024} KiB, sha256 verified, pure-Python, {file_meta.get('upload_time')})")
    print("vendor: done")
    return 0


# ──────────────────────────────────────────────────────────────────────────
# compact-malware-db
# ──────────────────────────────────────────────────────────────────────────

ECO_CODES = {
    "npm": ord("n"),
    "pypi": ord("p"),
    "crates.io": ord("c"),
    "go": ord("g"),
    "nuget": ord("d"),
    "maven": ord("m"),
    "rubygems": ord("r"),
}
ECO_DIRS = {  # OSSF dir name → our eco code key
    "npm": "npm",
    "pypi": "pypi",
    "crates.io": "crates.io",
    "go": "go",
    "nuget": "nuget",
    "maven": "maven",
    "rubygems": "rubygems",
}


def _iter_osv_records(src: Path) -> Iterable[tuple[int, str, str, str, str]]:
    """Yield (eco_code, name, version, advisory_id, aliases_csv)."""
    for eco_dir, eco_key in ECO_DIRS.items():
        d = src / eco_dir
        if not d.exists():
            continue
        for path in d.rglob("*.json"):
            try:
                rec = json.loads(path.read_bytes())
            except Exception:
                continue
            adv_id = rec.get("id") or ""
            aliases = ",".join(rec.get("aliases") or [])
            for affected in rec.get("affected") or []:
                pkg = (affected.get("package") or {})
                name = pkg.get("name") or ""
                if not name:
                    continue
                eco_code = ECO_CODES.get(eco_key)
                if eco_code is None:
                    continue
                versions = affected.get("versions") or []
                # If no explicit versions, see if we can derive a few from ranges
                if not versions:
                    for r in affected.get("ranges") or []:
                        for ev in r.get("events") or []:
                            v = ev.get("introduced") or ev.get("fixed") or ev.get("last_affected")
                            if v and v != "0":
                                versions.append(v)
                seen: set[str] = set()
                for v in versions:
                    if not isinstance(v, str):
                        continue
                    if v in seen:
                        continue
                    seen.add(v)
                    yield (eco_code, name, v, adv_id, aliases)


# ── CHD-style perfect hash (small pure-Python implementation) ─────────────
#
#   bucket k: items with hash0(key) % B == k
#   for each bucket (sorted by size desc), find a per-bucket displacement d
#   such that hash1(key, d) % T is empty for every key in the bucket;
#   record d in displacements[k], assign slots in the table.
#
# Lookup: slot = hash1(key, displacements[hash0(key) % B]) % T
#
# We use blake2b for both hashes (different personals).

import hashlib as _hl


def _h0(key: bytes, seed: int, n_buckets: int) -> int:
    h = _hl.blake2b(digest_size=8, person=b"scs-h0", salt=struct.pack("<Q", seed)[:8])
    h.update(key)
    return int.from_bytes(h.digest(), "little") % n_buckets


def _h1(key: bytes, seed: int, displacement: int, table_size: int) -> int:
    h = _hl.blake2b(digest_size=8, person=b"scs-h1", salt=struct.pack("<Q", seed)[:8])
    h.update(key)
    h.update(struct.pack("<I", displacement))
    return int.from_bytes(h.digest(), "little") % table_size


def _chd_build(keys: list[bytes], seed: int) -> tuple[list[int], list[int], int]:
    """Return (slot_for_key_i, displacements_per_bucket, table_size).

    Raises RuntimeError if construction fails for the seed.
    """
    n = len(keys)
    table_size = 1
    while table_size < int(n * 1.3):
        table_size <<= 1
    n_buckets = max(1, n // 4)
    buckets: list[list[int]] = [[] for _ in range(n_buckets)]
    for i, k in enumerate(keys):
        buckets[_h0(k, seed, n_buckets)].append(i)

    order = sorted(range(n_buckets), key=lambda b: -len(buckets[b]))
    displacements = [0] * n_buckets
    occupied = [False] * table_size
    slot_for = [-1] * n

    for bidx in order:
        items = buckets[bidx]
        if not items:
            continue
        for d in range(0, 1 << 20):
            slots = []
            ok = True
            seen_local: set[int] = set()
            for ki in items:
                s = _h1(keys[ki], seed, d, table_size)
                if occupied[s] or s in seen_local:
                    ok = False
                    break
                seen_local.add(s)
                slots.append(s)
            if ok:
                displacements[bidx] = d
                for ki, s in zip(items, slots):
                    occupied[s] = True
                    slot_for[ki] = s
                break
        else:
            raise RuntimeError(f"CHD failed for bucket {bidx} of size {len(items)} (seed {seed})")
    return slot_for, displacements, table_size


def cmd_compact_malware_db(args) -> int:
    src = Path(args.src).resolve()
    out_path = Path(args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if not src.exists():
        sys.exit(f"compact-malware-db: source dir not found: {src}")

    print(f"compact-malware-db: scanning {src}")
    rows: list[tuple[int, bytes, bytes, bytes, bytes]] = []
    for eco_code, name, version, adv_id, aliases in _iter_osv_records(src):
        rows.append((eco_code, name.encode("utf-8"), version.encode("utf-8"), adv_id.encode("utf-8"), aliases.encode("utf-8")))
    if not rows:
        sys.exit("compact-malware-db: no records found")
    rows.sort(key=lambda r: (r[0], r[1], r[2]))
    print(f"compact-malware-db: {len(rows)} (eco, name, version) tuples")

    # Group by (eco, name)
    keys: list[tuple[int, bytes]] = []
    versions_grouped: list[list[tuple[bytes, bytes, bytes]]] = []
    last_key = None
    cur: list[tuple[bytes, bytes, bytes]] = []
    for eco, name, ver, adv, aliases in rows:
        k = (eco, name)
        if k != last_key:
            if last_key is not None:
                keys.append(last_key)
                versions_grouped.append(cur)
            cur = []
            last_key = k
        cur.append((ver, adv, aliases))
    if last_key is not None:
        keys.append(last_key)
        versions_grouped.append(cur)
    print(f"compact-malware-db: {len(keys)} unique (eco, name) keys")

    # Build NAMES table
    name_offsets: dict[bytes, int] = {}
    names_buf = bytearray()
    for _, n in keys:
        if n not in name_offsets:
            name_offsets[n] = len(names_buf)
            names_buf.extend(n)

    # Build VERSIONS table
    versions_offsets: list[int] = []
    versions_buf = bytearray()
    for grp in versions_grouped:
        versions_offsets.append(len(versions_buf))
        for ver, adv, aliases in grp:
            versions_buf.extend(struct.pack("<H", len(ver))); versions_buf.extend(ver)
            versions_buf.extend(struct.pack("<H", len(adv))); versions_buf.extend(adv)
            versions_buf.extend(struct.pack("<H", len(aliases))); versions_buf.extend(aliases)

    # Build CHD perfect hash. Try several seeds.
    chd_keys = [bytes([eco]) + name for eco, name in keys]
    last_err = None
    for seed in range(1, 200):
        try:
            slot_for, displacements, hash_table_size = _chd_build(chd_keys, seed)
            break
        except RuntimeError as e:
            last_err = e
    else:
        sys.exit(f"compact-malware-db: CHD construction failed after 200 seeds: {last_err}")
    print(f"compact-malware-db: CHD seed={seed}, table_size={hash_table_size}, n_buckets={max(1, len(keys)//4)}")

    # Build HASH TABLE: slot → key index (0xFFFFFFFF empty)
    hash_table = bytearray(hash_table_size * 4)
    for ki, slot in enumerate(slot_for):
        struct.pack_into("<I", hash_table, slot * 4, ki)
    # Fill empty slots
    EMPTY = 0xFFFFFFFF
    for s in range(hash_table_size):
        cur = struct.unpack_from("<I", hash_table, s * 4)[0]
        if cur == 0 and slot_for and s != slot_for[0]:
            # Distinguish "slot 0 stored" from "empty" by checking we wrote it.
            pass
    # Re-fill properly: start with EMPTY everywhere, then set occupied slots
    hash_table = bytearray(b"\xff" * (hash_table_size * 4))
    for ki, slot in enumerate(slot_for):
        struct.pack_into("<I", hash_table, slot * 4, ki)

    # Encode displacements (uint16 each — 64K max displacement should be plenty)
    displacements_buf = bytearray()
    for d in displacements:
        if d > 0xFFFF:
            sys.exit(f"compact-malware-db: displacement {d} exceeds uint16")
        displacements_buf.extend(struct.pack("<H", d))

    # Build KEY RECORDS (14 bytes each)
    key_records = bytearray()
    for ki, (eco, name) in enumerate(keys):
        no = name_offsets[name]
        nl = len(name)
        vo = versions_offsets[ki]
        vc = len(versions_grouped[ki])
        key_records.extend(struct.pack("<BIHIH", eco, no, nl, vo, vc))

    # Now assemble. Compute offsets.
    HEADER_SIZE = 96
    hash_offset = HEADER_SIZE
    disp_offset = hash_offset + len(hash_table)
    keys_offset = disp_offset + len(displacements_buf)
    names_offset = keys_offset + len(key_records)
    versions_offset = names_offset + len(names_buf)
    payload = bytes(hash_table) + bytes(displacements_buf) + bytes(key_records) + bytes(names_buf) + bytes(versions_buf)
    payload_sha256 = hashlib.sha256(payload).digest()

    header = bytearray(HEADER_SIZE)
    header[0:8] = b"SCSMALW3"
    struct.pack_into("<H", header, 8, 1)                            # format_version
    struct.pack_into("<I", header, 10, len(rows))                   # entry_count
    struct.pack_into("<I", header, 14, len(keys))                   # keys_count
    struct.pack_into("<Q", header, 18, int(time.time()))            # built_at_unix
    struct.pack_into("<Q", header, 26, seed)                        # hash_seed
    struct.pack_into("<I", header, 34, hash_table_size)             # hash_table_size
    struct.pack_into("<I", header, 38, hash_offset)                 # hash_offset
    struct.pack_into("<I", header, 42, disp_offset)                 # displacements_offset
    struct.pack_into("<I", header, 46, keys_offset)                 # keys_offset
    struct.pack_into("<I", header, 50, names_offset)                # names_offset
    struct.pack_into("<I", header, 54, versions_offset)             # versions_offset
    struct.pack_into("<I", header, 58, max(1, len(keys) // 4))      # n_buckets
    header[62:94] = payload_sha256                                   # 32-byte sha256
    # 94..95 reserved

    out_path.write_bytes(bytes(header) + payload)
    print(f"compact-malware-db: wrote {out_path} ({out_path.stat().st_size//1024} KiB)")

    # Quick benchmark
    sys.path.insert(0, str(SRC.parent))
    try:
        from scs.malware_db import open_db  # type: ignore
    except Exception as e:
        print(f"compact-malware-db: skipping benchmark (malware_db not yet importable: {e})")
        return 0
    db = open_db(out_path)
    import random
    random.seed(0)
    sample = random.sample(rows, min(10000, len(rows)))
    t0 = time.perf_counter()
    hits = 0
    for eco, name, ver, _, _ in sample:
        if db.lookup(eco, name, ver) is not None:
            hits += 1
    elapsed = (time.perf_counter() - t0) * 1000
    print(f"compact-malware-db: 10k lookups: {elapsed:.1f}ms, {hits} hits (expected ~10k)")
    if elapsed > 200:
        print("compact-malware-db: WARNING — lookup benchmark exceeded 200ms target")
    return 0


# ──────────────────────────────────────────────────────────────────────────
# bundle (textual single-file bundler)
# ──────────────────────────────────────────────────────────────────────────

# Topological order of modules — vendored first, then leaves, then aggregators.
BUNDLE_ORDER = [
    # Vendored packages — included as their own modules.
    # We gather them dynamically, but they go FIRST.
    None,  # placeholder filled by collect_vendored
    "scs/version.py",
    "scs/findings.py",
    "scs/yaml_lite.py",
    "scs/shellcmd.py",
    "scs/http.py",
    "scs/repo.py",
    "scs/malware_db.py",
    "scs/installed.py",
    "scs/enrich.py",
    "scs/parsers/npm.py",
    "scs/parsers/python.py",
    "scs/parsers/rust.py",
    "scs/parsers/golang.py",
    "scs/parsers/dotnet.py",
    "scs/parsers/gh_actions.py",
    "scs/parsers/gitlab_ci.py",
    "scs/parsers/dockerfile.py",
    "scs/parsers/__init__.py",
    "scs/report/assets.py",
    "scs/report/html.py",
    "scs/report/__init__.py",
    "scs/__init__.py",
    "scs/cli.py",
]


def _collect_vendored() -> list[Path]:
    """Return all .py files under src/scs/_vendor/ in dependency-friendly order."""
    out: list[Path] = []
    if not VENDOR_DIR.exists():
        return out
    # Each top-level vendored package
    for pkg in sorted(p for p in VENDOR_DIR.iterdir() if p.is_dir() and (p / "__init__.py").exists()):
        # __init__ first, then the rest sorted
        init = pkg / "__init__.py"
        out.append(init)
        for f in sorted(pkg.rglob("*.py")):
            if f != init:
                out.append(f)
    return out


# Match `from scs._vendor.<pkg>[.subpath] import …`  (rewrites scs._vendor → bare pkg)
_VENDOR_REF_RE = re.compile(r"^(\s*)from\s+scs\._vendor\.([A-Za-z0-9_]+)(\.[A-Za-z0-9_.]+)?\s+import\s+(.+?)\s*$")

# Match `from .[.[.]]foo[.bar] import …` — relative imports
_REL_IMPORT_RE = re.compile(r"^(\s*)from\s+(\.+)([A-Za-z0-9_.]*)\s+import\s+(.+?)\s*$")

# Match `from scs[.x[.y]] import …`
_SCS_ABS_IMPORT_RE = re.compile(r"^(\s*)from\s+scs(\.[A-Za-z0-9_.]+)?\s+import\s+(.+?)\s*$")


def _rewrite_module(text: str, mod_name: str, is_package: bool) -> str:
    """Rewrite intra-package imports to use the bundled module names.

    `mod_name` is the canonical name the bundle registers this module under
    (e.g. 'scs.cli' for our code, 'packaging._manylinux' for vendored).
    For __init__.py files, base for `.foo` is mod_name itself; otherwise it
    is the parent of mod_name.
    """
    base_initial = mod_name if is_package else ".".join(mod_name.split(".")[:-1])

    out_lines: list[str] = []
    for ln in text.splitlines():
        # `from scs._vendor.<pkg>` → `from <pkg>`
        m = _VENDOR_REF_RE.match(ln)
        if m:
            indent, pkg, rest, names = m.group(1), m.group(2), m.group(3) or "", m.group(4)
            out_lines.append(f"{indent}from {pkg}{rest} import {names}")
            continue

        # `from .X import Y` / `from .. import Y` (relative)
        m = _REL_IMPORT_RE.match(ln)
        if m:
            indent, dots, sub, names = m.group(1), m.group(2), m.group(3), m.group(4)
            up = len(dots) - 1
            base = base_initial
            for _ in range(up):
                base = ".".join(base.split(".")[:-1])
            if sub:
                target = f"{base}.{sub}" if base else sub
            else:
                target = base
            if not target:
                out_lines.append(f"{indent}# bundled relative import: {ln.strip()}")
                continue
            out_lines.append(f"{indent}from {target} import {names}")
            continue

        # `from scs[.x] import …` — keep as-is
        m = _SCS_ABS_IMPORT_RE.match(ln)
        if m:
            out_lines.append(ln)
            continue

        out_lines.append(ln)
    return "\n".join(out_lines)


def _module_name_for(rel: Path) -> str:
    """Compute the bundled module name for a source path under src/."""
    parts = list(rel.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    # Vendored packages: drop the `scs._vendor` prefix so `packaging`, `tomli`
    # are importable by their natural names.
    if len(parts) >= 2 and parts[0] == "scs" and parts[1] == "_vendor":
        parts = parts[2:]
    return ".".join(parts)


def cmd_bundle(args) -> int:
    out_path = Path(args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    vendored = _collect_vendored()
    file_list: list[Path] = []
    for entry in BUNDLE_ORDER:
        if entry is None:
            file_list.extend(vendored)
        else:
            p = SRC.parent / entry
            if not p.exists():
                sys.exit(f"bundle: missing source file {p}")
            file_list.append(p)

    # Build {module_name: (source_text, filename, is_package)}
    sources: dict[str, tuple[str, str, bool]] = {}
    package_names: set[str] = set()
    for p in file_list:
        rel = p.relative_to(SRC.parent)
        mod_name = _module_name_for(rel)
        if not mod_name:
            continue
        is_pkg = p.name == "__init__.py"
        text = _rewrite_module(p.read_text(encoding="utf-8"), mod_name, is_pkg)
        sources[mod_name] = (text, str(rel), is_pkg)
        if is_pkg:
            package_names.add(mod_name)
    # Synthesize empty packages for any intermediate paths missing __init__.py
    all_names = list(sources)
    for nm in all_names:
        chunks = nm.split(".")
        for i in range(1, len(chunks)):
            parent = ".".join(chunks[:i])
            if parent not in sources:
                sources[parent] = ("", f"<synthesized {parent}>", True)
                package_names.add(parent)

    parts: list[str] = []
    parts.append("#!/usr/bin/env python3\n")
    parts.append("# -*- coding: utf-8 -*-\n")
    parts.append('"""scs — bundled supply-chain scanner (single-file build).\n\n')
    parts.append(f"Built {dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}Z. All third-party deps are\n")
    parts.append("vendored, hash-pinned, pure-Python, and ≥7 days old per vendor.txt.\n\n")
    for p in vendored:
        if p.name == "__init__.py" and p.parent.parent.name == "_vendor":
            lic = p.parent / "_LICENSE.txt"
            if lic.exists():
                parts.append(f"Vendored: {p.parent.name} (license bundled in source).\n")
    parts.append('"""\n\n')
    parts.append("from __future__ import annotations\n")
    parts.append("import sys\n")
    parts.append("import importlib.abc\n")
    parts.append("import importlib.util\n\n")

    # Embed the source map.
    parts.append("# --- bundled module source map -------------------------------------------\n")
    parts.append("# {module_name: (source_text, filename, is_package)}\n")
    parts.append("_SCS_BUNDLED = ")
    parts.append(repr({k: v for k, v in sorted(sources.items())}))
    parts.append("\n\n")

    # Meta-path finder + loader.
    parts.append("class _SCSLoader(importlib.abc.Loader):\n")
    parts.append("    def __init__(self, name, source, filename, is_package):\n")
    parts.append("        self.name = name\n")
    parts.append("        self.source = source\n")
    parts.append("        self.filename = filename\n")
    parts.append("        self.is_package = is_package\n")
    parts.append("    def create_module(self, spec):\n")
    parts.append("        return None\n")
    parts.append("    def exec_module(self, module):\n")
    parts.append("        module.__file__ = '<bundled:' + self.filename + '>'\n")
    parts.append("        if self.is_package:\n")
    parts.append("            module.__path__ = []\n")
    parts.append("        exec(compile(self.source, self.filename, 'exec'), module.__dict__)\n")
    parts.append("\n")
    parts.append("class _SCSFinder(importlib.abc.MetaPathFinder):\n")
    parts.append("    def find_spec(self, name, path, target=None):\n")
    parts.append("        entry = _SCS_BUNDLED.get(name)\n")
    parts.append("        if entry is None:\n")
    parts.append("            return None\n")
    parts.append("        source, filename, is_package = entry\n")
    parts.append("        loader = _SCSLoader(name, source, filename, is_package)\n")
    parts.append("        spec = importlib.util.spec_from_loader(name, loader, is_package=is_package)\n")
    parts.append("        return spec\n")
    parts.append("\n")
    parts.append("if not any(isinstance(f, _SCSFinder) for f in sys.meta_path):\n")
    parts.append("    sys.meta_path.insert(0, _SCSFinder())\n")
    parts.append("\n")
    # Bake the build timestamp in so the report can show it.
    build_iso = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    parts.append("import scs.version as _scs_version\n")
    parts.append(f"_scs_version.BUILD_TS = {build_iso!r}\n")
    parts.append("\n")
    parts.append("if __name__ == '__main__':\n")
    parts.append("    from scs.cli import main as _main\n")
    parts.append("    sys.exit(_main())\n")

    out_path.write_text("".join(parts), encoding="utf-8")
    out_path.chmod(0o755)
    print(f"bundle: wrote {out_path} ({out_path.stat().st_size // 1024} KiB, {len(sources)} modules)")
    return 0


# ──────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────

def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="build.py")
    sub = p.add_subparsers(dest="cmd", required=True)

    pv = sub.add_parser("vendor", help="fetch + verify vendored wheels")
    pv.add_argument("--vendor-file", default="vendor.txt")
    pv.add_argument("--out", default=str(VENDOR_DIR))
    pv.set_defaults(func=cmd_vendor)

    pb = sub.add_parser("bundle", help="bundle src/scs/ into a single .py")
    pb.add_argument("--out", default=str(DIST / "scs.py"))
    pb.set_defaults(func=cmd_bundle)

    pm = sub.add_parser("compact-malware-db", help="compact OSSF dataset into sidecar binary")
    pm.add_argument("--src", required=True)
    pm.add_argument("--out", required=True)
    pm.set_defaults(func=cmd_compact_malware_db)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
