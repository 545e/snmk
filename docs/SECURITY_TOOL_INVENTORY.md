# SECURITY TOOL INVENTORY & INTEGRATION MATRIX
## Audited 2026-11-07 — host detection + code review of adapters

Two classes of capability exist in SWA AI:

1. **Native engines** — pure Python/stdlib/httpx implementations, always available, no external binary required.
2. **External scanner adapters** — `core/scanner_integrations.py` detects binaries honestly via `shutil.which` (+ Windows hints), reports `installed: false` with an install guide when absent, and never claims a tool ran when it didn't.

## Host detection on this workstation (2026-11-07)

| Adapter | Detected installed | Detected version | Notes |
|---|---|---|---|
| swa_native | YES | 2.2.0-Enterprise | Always available |
| microsoft_defender | YES | 1.463.191.0 | Windows Defender via PowerShell query |
| nmap | **NO** | — | install guide provided at runtime |
| nuclei | **NO** | — | |
| owasp_zap | **NO** | — | |
| sqlmap | **NO** | — | Also lab-mode gated |
| nikto | **NO** | — | |
| tshark | **NO** | — | |
| semgrep | **NO** | — | |
| bandit | **NO** | — | |
| trivy | **NO** | — | |
| gitleaks | **NO** | — | |
| clamav | **NO** | — | |
| wazuh | **NO** | — | |
| rea (CLI) | **NO** | — | Built-in `ForensicsEngine` / native REA inspection fallback works without CLI |

No external scanner has been executed on this host. Any "run" of these tools will truthfully return `executed: false` with an install guide, not a fabricated result.

## Native engines (code-reviewed; executed by automated tests unless noted)

| Tool / Engine | Module | Type | Test status |
|---|---|---|---|
| DNS lookup | `core/cyber_tools.py::DNSLookupTool` | socket/rdap | PASS |
| Security headers evaluator | `core/cyber_tools.py::SecurityHeadersTool` | httpx | PASS |
| SSL certificate inspector | `core/cyber_tools.py::SSLCertificateTool` | ssl/socket | PASS |
| Port prober | `core/cyber_tools.py::PortProberTool` | async socket | PASS (local) |
| WHOIS / RDAP | `core/cyber_tools.py::WhoisIpTool` | httpx/rdap | PASS |
| Crypto encoder / hashes / JWT inspect | `core/cyber_tools.py::CryptoEncoderTool` | stdlib | PASS |
| Subnet calculator | `core/cyber_tools.py::SubnetCalculatorTool` | stdlib | PASS |
| Targeted vuln prober (SQLi/XSS/LFI/CORS/SSRF canaries) | `core/cyber_tools.py::TargetedVulnProberTool` | httpx | PASS |
| Reverse shell reference generator | `core/cyber_tools.py::ReverseShellGeneratorTool` | templates | PASS |
| Amass engine wrapper | `agents/amass_engine.py` | binary wrapper | NOT TESTED (no amass binary) |
| SQLi engine | `core/sqli_engine.py` | native prober | PASS |
| WAF bypass engine | `core/waf_bypass_engine.py` | detection heuristics | PASS |
| REA engine | `core/rea_engine.py` | native inspectors + optional CLI | PASS (native path) |
| Injection suite | `core/injection_suite.py` | native checks | PASS |
| Forensics engine | `core/forensics_engine.py` | log parsing | PASS |
| Kill chain engine | `core/kill_chain/` | correlator | PASS (20 tests) |
| Knowledge graph | `core/knowledge_graph.py` | SQLite graph | PASS |
| JS intelligence (GhostJS) | `core/js_intelligence.py` | async fetch+scan | PASS |
| OWASP Top 10 plugins (10) | `plugins/owasp_plugins.py` | prober plugins | PASS (8 tests) |
| Nessus report engine | `reports/nessus_report_engine.py` | exporter | PASS (16 tests) |
| Cyber export (SARIF/PDF/…) | `core/cyber_export.py` | exporter | PASS |
| Blue team rule generator | `core/blue_team_engine.py` | deterministic rules | PASS (via automation path now) |
| CVE intelligence | `core/intelligence_models.py`, threat-intel adapters | enrichment (configured creds) | PARTIAL — see below |

## Honesty notes
- `tool_registry` previously claimed Category-G adapters as `installed: true` unconditionally. Detection truth now comes from `ScannerIntegrations.get_tool_inventory()`; registry statuses are informational.
- `backend_handler` strings in `tool_registry` that pointed at nonexistent symbols were corrected (2026-11-07) to real symbols; these strings are metadata, not a dispatch mechanism.
- `/api/tools/{tool_id}/execute` for unimplemented tools returns an explicit not-executed response; it does NOT claim a scan occurred. The js-scan branch (previously HTTP 500 ImportError) now calls `GhostJsAnalyzer.scan_url` for real.
- External-tool scans run only when the binary exists, the target passes `scope_policy`, and (for intrusive actions) the caller opted into lab mode where required.
