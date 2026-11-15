# SNMK Enterprise Platform Software Architecture Audit Report

**Audit Area:** System Architecture, Layered Decomposition & Component Boundaries  
**Target Repository:** `https://github.com/545e/snmk.git`  
**Architect:** Chief Software Architect & Enterprise Engineering Team  
**Status:** **HIGH ARCHITECTURAL INTEGRITY**

---

## 1. Architectural Overview & Tiered Decomposition

SNMK is structured as a resilient, modular, and event-driven cybersecurity intelligence platform. The architecture adheres to clean separation of concerns across five primary tiers:

```
+--------------------------------------------------------------------------------------------------+
|                                  TIER 1: PRESENTATION & UI                                       |
|  * Vanilla ES6 SOC Dashboard (web/static/app.js)     * Wireshark-Style Hex Viewer (map.js)      |
|  * Real-time WebSocket Live Feeds                     * 11 Navigational Security Views           |
+--------------------------------------------------------------------------------------------------+
                                               |
                                               v (HTTP/REST, WebSocket, GZip Encoded)
+--------------------------------------------------------------------------------------------------+
|                              TIER 2: API GATEWAY & SECURITY ENVELOPE                             |
|  * FastAPI / Starlette Core (web/server.py)           * Rate-Limiting & Correlation Middleware   |
|  * Scope Policy & SSRF Gate (core/scope_policy.py)   * Typed Exception Envelope Hierarchy       |
+--------------------------------------------------------------------------------------------------+
                                               |
                                               v
+--------------------------------------------------------------------------------------------------+
|                           TIER 3: CORE DOMAIN & ORCHESTRATION ENGINES                            |
|  * Multi-Agent Workforce (85 Agents, 17 Roles)       * CrewAI & LangChain Adapters              |
|  * Tool Dependency Manager (34 Registered Tools)     * DAG Automation Engine (core/automation)  |
|  * Deep Packet Inspection & Forensic Dissector       * Deterministic Remediation Engine         |
+--------------------------------------------------------------------------------------------------+
                                               |
                                               v
+--------------------------------------------------------------------------------------------------+
|                              TIER 4: PERSISTENCE & KNOWLEDGE STORAGE                             |
|  * SQLite WAL Relational Database (54 Tables)        * Hybrid BM25 / TF-IDF RAG Knowledge Engine |
|  * Finding Deduplication & Hash Vault                * Audit Logs with Credential Redaction      |
+--------------------------------------------------------------------------------------------------+
                                               |
                                               v
+--------------------------------------------------------------------------------------------------+
|                           TIER 5: OBSERVABILITY & PLATFORM TELEMETRY                             |
|  * Prometheus Metrics Engine (core/metrics.py)       * Structured JSON Logging (Loki-ready)      |
|  * Distributed Tracing (OpenTelemetry / Tempo)       * 15 Provisioned Grafana Dashboards         |
+--------------------------------------------------------------------------------------------------+
```

---

## 2. Component Boundaries & Design Patterns

1. **Dependency Injection & Inversion of Control:** FastAPI's route injection provides loose coupling between request contexts and backend services.
2. **Adapter Pattern:** Implemented in `core/crewai_adapter.py` and `core/langchain_adapter.py`, allowing the platform to interface with external AI frameworks while preserving native zero-dependency fallbacks.
3. **Template Method Pattern:** Implemented in `core/cyber_tools.py` for uniform security tool execution, input sanitization, timeout handling, and process teardown.
4. **State Machine Pattern:** Implemented in `core/automation_engine.py` for immutable workflow execution lifecycle tracking (`PENDING` -> `RUNNING` -> `COMPLETED`/`FAILED`/`CANCELLED`).
5. **Circuit Breaker / Mutex Pattern:** Implemented in `web/static/app.js` with `__swaPollInFlight` to eliminate client-side request stampedes.

---

## 3. Evaluation of Architectural Principles

- **Single Responsibility Principle (SRP):** Distinct modules encapsulate dedicated domains (`core/scope_policy.py` handles authorization; `core/database.py` handles persistence; `core/metrics.py` handles telemetry).
- **Open/Closed Principle (OCP):** New security tools register dynamically via `core/tool_registry.py` without modifying core server endpoints.
- **Liskov Substitution Principle (LSP):** All typed exceptions inherit from `SNMKError` and serialize cleanly via `StandardErrorEnvelope`.
- **Don't Repeat Yourself (DRY):** Common credential sanitization is centralized in `core/app_security.py` and `core/logging_config.py`.
- **Keep It Simple, Stupid (KISS):** Retained lightweight Vanilla JS and SQLite WAL instead of introducing unnecessary heavyweight stacks (e.g., Redis, Webpack, Postgres) that add operational fragility.
