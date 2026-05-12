# `scs` — Supply-Chain Scanner

Scans for unpinned dependencies and known-malicious packages across npm, PyPI,
Cargo, Go modules, NuGet, GitHub Actions, GitLab CI, and Dockerfiles. Produces
a self-contained styled HTML report.

## Quick start

```sh
make build         # vendor deps + bundle into dist/scs.py
make malware-db    # (optional) build offline malware-detection sidecar

./dist/scs.py scan /path/to/repo --out report.html
```

## Hard guarantees

- **Pure stdlib at runtime** once built — third-party deps are vendored, hash-pinned, pure-Python, and refused if uploaded <7 days before build (mitigates fresh supply-chain compromises).
- **Never executes install/build scripts** of scanned projects. Ecosystem CLIs only invoked with explicit no-script flags.
- **Self-contained HTML report** — no external network resources at view time.
- **Offline malware detection** via the OSSF `malicious-packages` dataset (sidecar binary, optional; auto-detected when present).
- **Perfect-hash O(1) malware lookups** so `m` scan targets cost `O(m)`, not `O(m·N)`.

Run `make help` for all targets.
