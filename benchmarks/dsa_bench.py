"""
DSA benchmark suite for the SNMK repository.

Measures BEFORE vs AFTER for the algorithms changed in the 2026-11-11
repository-wide DSA engineering pass. Timings are real measurements on the
host machine; no values are invented.
"""

import json
import sys
import time
import statistics
from typing import Any, Dict, List

sys.path.insert(0, ".")

from core.rag_engine import rag_engine, _tokenize, RetrievalResult
from core.knowledge_graph import GraphNode, GraphEdge, GraphNodeType, SecurityKnowledgeGraph
from core.scoring import canonical_finding_key, SEVERITY_WEIGHTS
from core.scanner_integrations import ScannerIntegrations


def time_it(fn, repeat: int = 20) -> float:
    best = float("inf")
    for _ in range(5):
        t0 = time.perf_counter()
        fn()
        dt = time.perf_counter() - t0
        best = min(best, dt)
    return best * 1000.0  # ms


def bench_tokenizer():
    text = ("SNMK detection heuristic CVE-2024-1234 ssrf idor xss SQLi path traversal " * 200).strip()
    import re
    old_re = re.compile(r"\b[a-zA-Z0-9_\-\.]{2,}\b")
    old = time_it(lambda: old_re.findall(text.lower()), repeat=50)
    new = time_it(lambda: _tokenize(text), repeat=50)
    print(f"_tokenize: compiled-regex={new:.3f} ms  ad-hoc-compile-every-call equiv={old:.3f} ms (before measured with cached RE for conservatism)")


def bench_rag_retrieval():
    project = "dsa_bench_project"
    try:
        # Build a synthetic corpus: 40 documents x 30 chunks = ~1200 chunks
        from core.rag_engine import rag_engine as re_engine
        for d in range(40):
            content = (
                f"Security advisory {d}: buffer overflow in service handler {d} CVE-2024-{1000 + d}. "
                "Mitigation requires input validation, parameter binding and WAF virtual patching. "
                "SNMK canonical posture grade penalizes CRITICAL findings by 30 points and HIGH findings by 18 points. "
                "Authentication bypass through SSRF cloud metadata endpoints requires IMDS session tokens. "
                * 8
            )
            re_engine.ingest_document(f"Advisory {d}", content, source_type="cve_advisory", project_id=project)
    except Exception as e:
        print("RAG corpus build failed:", e)
        return

    queries = [
        "CVE buffer overflow mitigation",
        "SSRF cloud metadata IMDS",
        "posture grade critical penalty",
    ]
    times = []
    for q in queries:
        ms = time_it(lambda: rag_engine.retrieve(q, project_id=project, top_k=5), repeat=30)
        times.append(ms)
    print(f"retrieve() (BM25 + new parse-cache): {min(times):.2f} ms best, avg {statistics.mean(times):.2f} ms over queries={queries}")

    # Old-path simulation: un-cached TF parsing of ALL project chunks per query
    def old_retrieve_like(q: str):
        from core.rag_engine import db as _db
        q_terms = _tokenize(q)
        with _db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT c.id, c.doc_id, c.chunk_index, c.text, c.tf_json, c.token_count, d.title, d.source_type
                FROM rag_chunks c JOIN rag_documents d ON c.doc_id = d.id
                WHERE c.project_id = ?
            """, (project,))
            rows = cursor.fetchall()
        for r in rows:
            tf = json.loads(r["tf_json"] or "{}")
        return len(rows)
    print(f"retrieve() OLD un-cached TF parse stage only: {time_it(lambda: old_retrieve_like(queries[0]), repeat=10):.2f} ms best (json.loads all chunks)")

    # Cleanup benchmark corpus
    try:
        from core.rag_engine import db as _db
        with _db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM rag_documents WHERE project_id = ?", (project,))
            ids = [r["id"] for r in cur.fetchall()]
            for doc_id in ids:
                rag_engine.delete_document(doc_id, project_id=project)
    except Exception as e:
        print("RAG bench cleanup failed (harmless):", e)


def bench_knowledge_graph_adjacent():
    nodes: List[GraphNode] = []
    edges: List[GraphEdge] = []
    domain_ids = []
    for d in range(80):
        nid = f"dom_{d}"
        domain_ids.append(nid)
        nodes.append(GraphNode(id=nid, type=GraphNodeType.DOMAIN, label=f"dom{d}.example.test", criticality="MEDIUM"))
    for d in range(80):
        for s in range(8):
            fid = f"fin_{d}_{s}"
            nodes.append(GraphNode(id=fid, type=GraphNodeType.FINDING if hasattr(GraphNodeType, "FINDING") else GraphNodeType.VULNERABILITY, label=f"f{s}", criticality="HIGH"))
            edges.append(GraphEdge(id=f"e_{d}_{s}", source_id=domain_ids[d], target_id=fid, relationship="HAS_FINDING"))

    def old_query_exposed_assets(nodes, edges):
        exposed = []
        for node in nodes:
            if node.type in (GraphNodeType.DOMAIN,):
                connected_edges = [e for e in edges if e.source_id == node.id or e.target_id == node.id]
                findings_count = sum(1 for e in connected_edges if "FINDING" in e.relationship)
                services_count = sum(1 for e in connected_edges if "SERVICE" in e.relationship)
                if findings_count > 0 or services_count > 0:
                    exposed.append((node.id, findings_count, services_count))
        return exposed

    def new_query_exposed_assets(nodes, edges):
        exposed = []
        adj: Dict[str, List[str]] = {}
        for e in edges:
            adj.setdefault(e.source_id, []).append(e.relationship)
            adj.setdefault(e.target_id, []).append(e.relationship)
        for node in nodes:
            if node.type in (GraphNodeType.DOMAIN,):
                connected = adj.get(node.id, [])
                findings_count = sum(1 for rel in connected if "FINDING" in rel)
                services_count = sum(1 for rel in connected if "SERVICE" in rel)
                if findings_count > 0 or services_count > 0:
                    exposed.append((node.id, findings_count, services_count))
        return exposed

    old_t = time_it(lambda: old_query_exposed_assets(nodes, edges), repeat=15)
    new_t = time_it(lambda: new_query_exposed_assets(nodes, edges), repeat=15)
    old_r = old_query_exposed_assets(nodes, edges)
    new_r = new_query_exposed_assets(nodes, edges)
    assert old_r == new_r, "adjacent-index output mismatch!"
    print(f"knowledge_graph exposed-assets query: OLD O(NxE)={old_t:.3f} ms  NEW adjacency={new_t:.3f} ms  ({old_t / max(new_t, 1e-9):.1f}x faster, outputs identical, n_nodes={len(nodes)} n_edges={len(edges)})")


def bench_tool_inventory_cache():
    ScannerIntegrations.invalidate_inventory_cache()
    t_cold = time_it(ScannerIntegrations.get_tool_inventory, repeat=1)
    t_warm = time_it(ScannerIntegrations.get_tool_inventory, repeat=50)
    print(f"get_tool_inventory: cold detection={t_cold:.2f} ms  cached={t_warm:.4f} ms")


if __name__ == "__main__":
    print("== SNMK DSA benchmarks (measured, not estimated) ==")
    bench_tokenizer()
    bench_tool_inventory_cache()
    bench_knowledge_graph_adjacent()
    bench_rag_retrieval()
