"""Reproducible benchmark harness for the repository-wide DSA transformation.

Every number quoted in ``docs/DSA_ENGINEERING_REPORT.md`` is produced by this
script on the host machine.  Nothing here is estimated.

Usage::

    python benchmarks/dsa_transformation_bench.py

Environment recorded in the report:
    Python 3.12.10, Windows, SQLite WAL.

The script measures, in order:

1. JavaScript secret scanner          (core.js_intelligence)
2. SQL error signature corpus          (core.signature_matching)
3. Database read paths                 (core.database)
4. Required-literal gate derivation    (core.pattern_gating)
"""

import os
import platform
import re
import sqlite3
import statistics
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def timeit(fn, repeat=20, warmup=2):
    """Return (best_ms, median_ms) for ``fn``."""
    for _ in range(warmup):
        fn()
    samples = []
    for _ in range(repeat):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)
    return min(samples), statistics.median(samples)


def banner(title):
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def env_line():
    print(f"Python {platform.python_version()} | {platform.system()} {platform.release()} "
          f"| {platform.machine()}")


# ---------------------------------------------------------------------------
# 1. JavaScript secret scanner
# ---------------------------------------------------------------------------
def bench_js_scanner():
    banner("1. JavaScript secret scanner (core.js_intelligence)")
    from core.js_intelligence import JavaScriptSecretScanner

    scanner = JavaScriptSecretScanner()
    for name in ("app.js", "map.js", "index.html"):
        path = os.path.join(REPO, "web", "static", name)
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
        best, med = timeit(lambda t=text: scanner.scan(t), repeat=3, warmup=1)
        print(f"  {name:12s} {len(text):>9,d} bytes   best {best:9.2f} ms   median {med:9.2f} ms")

    # Ungated baseline: the same scan without the required-literal gate.
    from core.js_intelligence import GHOSTJS_RAW_PATTERNS, ShannonEntropyFilter

    def ungated(text):
        findings = []
        if not text:
            return findings
        lines = text.splitlines()
        seen = set()
        for meta in GHOSTJS_RAW_PATTERNS:
            try:
                raw = meta["regex"].encode().decode("unicode_escape")
                flags = 0
                if "i" in meta["flags"]:
                    flags |= re.IGNORECASE
                if "s" in meta["flags"]:
                    flags |= re.DOTALL
                if "m" in meta["flags"]:
                    flags |= re.MULTILINE
                for m in re.compile(raw, flags).finditer(text):
                    v = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                    if not v:
                        continue
                    v = v.strip()
                    key = (meta["name"], v)
                    if key in seen:
                        continue
                    min_ent = 3.0 if meta["confidence"] < 85 else 0.0
                    if ShannonEntropyFilter.is_likely_false_positive(v, meta["name"], min_entropy=min_ent):
                        continue
                    seen.add(key)
                    sp = m.start()
                    ln = text.count("\n", 0, sp) + 1
                    lt = lines[ln - 1] if ln - 1 < len(lines) else ""
                    findings.append((meta["name"], v, ln, lt.strip()[:180]))
            except Exception:
                continue
        return findings

    path = os.path.join(REPO, "web", "static", "app.js")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
        best, _ = timeit(lambda: ungated(text), repeat=3, warmup=1)
        gated_best, _ = timeit(lambda: scanner.scan(text), repeat=3, warmup=1)
        print(f"  app.js ungated baseline    {best:9.2f} ms")
        print(f"  app.js with required-literal gate {gated_best:9.2f} ms   "
              f"({best / max(gated_best, 1e-9):.1f}x faster)")

    # Line index: O(log N) line lookup instead of an O(N) prefix scan.
    from core.js_intelligence import _build_line_offsets

    def old_line_lookup(text, positions):
        return [text.count("\n", 0, p) + 1 for p in positions]

    def new_line_lookup(text, positions):
        offsets = _build_line_offsets(text)
        from bisect import bisect_right
        return [bisect_right(offsets, p) for p in positions]

    positions = list(range(0, len(text), max(1, len(text) // 2000)))
    if positions:
        o_best, _ = timeit(lambda: old_line_lookup(text, positions), repeat=5, warmup=1)
        n_best, _ = timeit(lambda: new_line_lookup(text, positions), repeat=5, warmup=1)
        print(f"  line-number resolution ({len(positions):>5d} matches): "
              f"prefix-scan {o_best:8.2f} ms   line-index {n_best:8.2f} ms   "
              f"({o_best / max(n_best, 1e-9):.1f}x faster)")


# ---------------------------------------------------------------------------
# 2. SQL error signature corpus
# ---------------------------------------------------------------------------
def bench_signature_matching():
    banner("2. SQL error signature corpus (core.signature_matching)")
    from core.signature_matching import SignatureMatcher
    from core.sqli_engine import DB_ENGINE_SIGNATURES

    patterns = [p for pats in DB_ENGINE_SIGNATURES.values() for p in pats]
    matcher = SignatureMatcher(patterns)

    def naive(body):
        return any(re.search(p, body, re.IGNORECASE) for p in patterns)

    print("  ReDoS-class body ('Warning ' repeated, no 'mysql_' literal present):")
    for n in (2000, 4000, 8000):
        body = "Warning " * n
        n_best, _ = timeit(lambda: naive(body), repeat=1, warmup=0)
        m_best, _ = timeit(lambda: matcher.matches(body), repeat=3, warmup=1)
        print(f"    {len(body):>8,d} bytes   naive {n_best:10.1f} ms   gated {m_best:8.2f} ms"
              f"   ({n_best / max(m_best, 1e-9):.0f}x faster)")

    print("  Scaling of the gated matcher (must be linear):")
    for n in (2000, 8000, 32000):
        body = "Warning " * n
        m_best, _ = timeit(lambda: matcher.matches(body), repeat=3, warmup=1)
        print(f"    {len(body):>8,d} bytes   gated {m_best:8.2f} ms")


# ---------------------------------------------------------------------------
# 3. Database read paths
# ---------------------------------------------------------------------------
def bench_database():
    banner("3. Database read paths (core.database)")
    from core.database import db

    best, med = timeit(db.check_health, repeat=20)
    print(f"  check_health()               best {best:8.3f} ms   median {med:8.3f} ms")
    best, med = timeit(lambda: db.check_health(deep=True), repeat=3, warmup=1)
    print(f"  check_health(deep=True)      best {best:8.3f} ms   median {med:8.3f} ms"
          f"   (full PRAGMA quick_check)")
    best, med = timeit(db.count_findings, repeat=20)
    print(f"  count_findings()             best {best:8.3f} ms   median {med:8.3f} ms")
    best, med = timeit(db.finding_severity_counts, repeat=20)
    print(f"  finding_severity_counts()    best {best:8.3f} ms   median {med:8.3f} ms")
    best, med = timeit(lambda: db.list_findings(limit=50), repeat=20)
    print(f"  list_findings(limit=50)      best {best:8.3f} ms   median {med:8.3f} ms")
    best, med = timeit(lambda: db.list_findings(), repeat=3, warmup=1)
    print(f"  list_findings()  [all rows]  best {best:8.3f} ms   median {med:8.3f} ms")

    conn = sqlite3.connect(os.path.join(REPO, "swa_data.db"))
    try:
        n_idx = conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'"
        ).fetchone()[0]
        print(f"  idx_ indexes in database: {n_idx}")
        plan = conn.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM findings "
            "ORDER BY cvss_score DESC, created_at DESC LIMIT 50"
        ).fetchall()
        print(f"  findings list query plan: {plan}")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 4. Required-literal gate
# ---------------------------------------------------------------------------
def bench_gating():
    banner("4. Required-literal gate derivation (core.pattern_gating)")
    from core.js_intelligence import GHOSTJS_RAW_PATTERNS
    from core.pattern_gating import required_literal_groups

    effective = [m["regex"].encode().decode("unicode_escape") for m in GHOSTJS_RAW_PATTERNS]
    best, med = timeit(lambda: [required_literal_groups(p) for p in effective], repeat=20)
    gated = sum(1 for p in effective if required_literal_groups(p))
    print(f"  derivation for {len(effective)} patterns   best {best:8.3f} ms   median {med:8.3f} ms")
    print(f"  patterns with a usable gate: {gated}/{len(effective)}")


if __name__ == "__main__":
    env_line()
    bench_js_scanner()
    bench_signature_matching()
    bench_database()
    bench_gating()
    print()
    print("Done.")
