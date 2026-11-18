# SNMK Dynamic Application Security Testing (DAST) & OWASP ZAP Report

**Audit Area:** Dynamic Application Security Testing, Spidering, Passive/Active Probes  
**Target Repository:** `https://github.com/545e/snmk.git`  
**Tool Integrations:** OWASP ZAP, Nuclei, Nikto, Standalone Fuzzers  
**Status:** **CONFIGURED & SCOPE GOVERNED**

---

## 1. Executive Summary

This report evaluates the Dynamic Application Security Testing (DAST) capabilities of SNMK. The platform interfaces with OWASP ZAP, Nuclei, and internal crawler engines to discover runtime vulnerabilities, misconfigured HTTP headers, exposed administrative endpoints, and injection flaws in staging and lab environments.

---

## 2. DAST Execution Architecture

1. **OpenAPI Schema Ingestion:** The DAST subsystem ingests the live OpenAPI 3.1 specification directly from `/openapi.json`, mapping all endpoints, parameter types, and HTTP methods automatically.
2. **Passive Scanning Profile:** Inspects response headers, cookies, and DOM payloads for passive issues (missing CSP, missing HSTS, cacheable sensitive endpoints, technology banner disclosure) without dispatching intrusive attack payloads.
3. **Active Scanning Profile:** Dispatches non-destructive injection probes (SQLi, XSS, SSRF, path traversal) strictly within the boundaries of the authorized target allowlist.
4. **Scope Governance:** Every DAST target is pre-validated by `core/scope_policy.py`. Attempts to target cloud metadata, loopback, or unauthorized IP addresses abort immediately with exit code 1.

---

## 3. Findings Comparison (SAST vs. DAST)

- **Header Hardening:** Verified dynamically that `Server: SWA-Secured`, `X-Content-Type-Options: nosniff`, and `X-Frame-Options: SAMEORIGIN` are returned on all endpoints.
- **SSRF Immunity:** Dynamic injection tests against target input fields confirmed that requests to `http://169.254.169.254/latest/meta-data/` are rejected with HTTP 403 `SecurityScopeError`.
