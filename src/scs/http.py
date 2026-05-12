from __future__ import annotations

import gzip
import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

DEFAULT_TTL = 24 * 3600
DEFAULT_TIMEOUT = 15
DEFAULT_UA = "scs/0.1 (+https://github.com/nightshift-codes/scs)"


def cache_dir() -> Path:
    p = Path(os.environ.get("SCS_CACHE_DIR", str(Path.home() / ".cache" / "scs")))
    p.mkdir(parents=True, exist_ok=True)
    return p


def _cache_path(url: str, suffix: str = ".json") -> Path:
    h = hashlib.sha256(url.encode()).hexdigest()[:32]
    return cache_dir() / f"{h}{suffix}"


def get_json(url: str, ttl: int = DEFAULT_TTL, no_cache: bool = False, timeout: int = DEFAULT_TIMEOUT) -> Optional[dict]:
    """GET a JSON URL with on-disk caching.

    Returns the decoded body, or None on 404 / network failure (callers decide).
    """
    cp = _cache_path(url, ".json.gz")
    if not no_cache and cp.exists() and (time.time() - cp.stat().st_mtime) < ttl:
        try:
            with gzip.open(cp, "rb") as f:
                return json.loads(f.read())
        except Exception:
            pass  # fall through to refetch
    req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        return None
    except Exception:
        return None
    try:
        data = json.loads(body)
    except Exception:
        return None
    if not no_cache:
        try:
            with gzip.open(cp, "wb") as f:
                f.write(json.dumps(data).encode())
        except Exception:
            pass
    return data


def post_json(url: str, payload: dict, timeout: int = DEFAULT_TIMEOUT) -> Optional[dict]:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "User-Agent": DEFAULT_UA,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except Exception:
        return None


def download(url: str, expected_sha256: Optional[str] = None, timeout: int = 60) -> bytes:
    """GET raw bytes; verify sha256 if provided. Raises on mismatch or fetch error."""
    req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read()
    if expected_sha256:
        got = hashlib.sha256(body).hexdigest()
        if got != expected_sha256.lower():
            raise ValueError(f"sha256 mismatch for {url}: expected {expected_sha256}, got {got}")
    return body
