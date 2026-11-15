# SNMK SAST, SCA & Secret Detection Audit Report

**Audit Area:** Static Application Security Testing, Dependency Auditing & Secret Scanning  
**Target Repository:** `https://github.com/545e/snmk.git`  
**Tools Evaluated:** Bandit, Semgrep, pip-audit, TruffleHog / Gitleaks Patterns  
**Status:** **CLEAN / ZERO EXPOSED SECRETS**

---

## 1. Executive Summary

This report synthesizes findings from multi-engine Static Application Security Testing (SAST), Software Composition Analysis (SCA), and automated secret scanning across the SNMK codebase and Git history.

---

## 2. SAST Findings & Remediations (Bandit & Semgrep)

| Vulnerability Code | Severity | Affected Module | Root Cause | Remediation Applied |
| :--- | :--- | :--- | :--- | :--- |
| **B608 (SQL Injection)** | High | `core/database.py` | Dynamic column concatenation in `UPDATE` query | Enforced strict `allowed_cols` filter and bound variables via parameterized `?` placeholders. |
| **B303 / B324 (Weak Hash)** | Medium | `core/data_management.py` | Unannotated MD5 usage for finding deduplication | Annotated with `usedforsecurity=False` to indicate non-cryptographic cache hashing. |
| **B303 / B324 (Weak Hash)** | Medium | `core/cyber_tools.py` | Unannotated MD4/MD5 usage in tool indexing | Annotated with `usedforsecurity=False`. |
| **B104 (Hardcoded Bind)** | Low | `web/server.py` | Bind to `0.0.0.0` in container mode | Configured configurable host binding via `SWA_HOST` (defaulting to `127.0.0.1` locally). |

**Current SAST Status:** **0 Active High / 0 Active Critical Vulnerabilities.**

---

## 3. Secret Detection & Credential Hygiene

Automated regex pattern scanning matching TruffleHog and Gitleaks rules was executed across all repository commits:
1. **`.env` Exclusion:** Verified that `.env` is listed in `.gitignore` and `.dockerignore`. No production credentials exist in version control.
2. **`.env.example` Hygiene:** Contains placeholder markers exclusively (e.g., `your_api_key_here`, `127.0.0.1`).
3. **Frontend Bundle Hygiene:** Scanned `web/static/app.js` and `web/static/map.js` for accidental private keys or API tokens. Zero hardcoded secrets detected.
4. **Credential Masking in Logging:** Verified that `core/logging_config.py` intercepts and redacts Bearer tokens, private keys, and API keys before output.
