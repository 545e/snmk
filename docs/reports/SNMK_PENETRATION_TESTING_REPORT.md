# SNMK Automated Penetration Testing & Scanner Operations Report

**Audit Area:** Controlled Security Probing, Vulnerability Verification & Scope Controls  
**Target Repository:** `https://github.com/545e/snmk.git`  
**Tool Integrations:** Nmap, Nuclei, OWASP ZAP, SQLMap, Nikto, FFUF, Subfinder  
**Status:** **OPERATIONAL & ETHICALLY BOUNDED**

---

## 1. Executive Summary

SNMK incorporates an automated penetration testing and active vulnerability assessment subsystem designed to discover attack surface vulnerabilities in authorized web applications, APIs, and network perimeters. This report audits the execution controls, scope boundaries, evidence capture mechanisms, and safety guardrails governing these tools.

---

## 2. Integrated Penetration Testing Tooling (23 Tools / 34 Adapters)

- **Reconnaissance & Asset Discovery:** Amass, Subfinder, CRT.sh, Async DNS Probes.
- **Port & Service Enumeration:** Nmap, Masscan, HTTPX.
- **Web Application Vulnerability Probers:** Nuclei (OWASP Top 10 template suites), OWASP ZAP Dynamic Prober, Nikto, WPSCan.
- **Injection Probers:** Deterministic SQL Injection Engine, SQLMap pentest lab adapter, 27-category injection prober.
- **Fuzzing & Content Discovery:** FFUF, Gobuster, Wfuzz, Anomaly-Filtered Path Fuzzer.
- **Reverse Engineering & Disassembly:** Pure-Python REA Engine (ELF/PE/SQLite/JS AST).

---

## 3. Strict Scope & Ethical Boundary Controls

1. **Mandatory Scope Allowlisting (`core/scope_policy.py`):** Probes cannot be dispatched without a pre-validated target hostname or IP address.
2. **Hardcoded SSRF & IMDS Blacklist:** Any target resolving to `169.254.169.254`, `127.0.0.0/8`, or unapproved private ranges is blocked immediately with HTTP 403 `SecurityScopeError`.
3. **Execution Timeouts:** Subprocess commands are bounded by enforceable timeouts (30s to 300s) to prevent persistent network hanging.
4. **Non-Destructive Payloads:** Default probe profiles execute non-destructive canary payloads (e.g., boolean SQL conditions `AND 1=1`, passive header analysis) rather than data-modifying or disruptive exploits.
5. **Human-in-the-Loop Interlocks:** Exploitation verification and remediation rule generation require analyst approval through the Human-in-the-Loop engine before virtual patches are applied to production WAFs.
