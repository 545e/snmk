# Python / C++ Subsystem Integration & Interoperability Report

**Document ID:** SNMK-AUDIT-PYTHON_CPP_INTEGRATION_REPORT  
**Classification:** Enterprise Confidential / Security Audit  
**Date:** 2026-11-15 20:53:15 UTC  
**Platform Version:** SNMK v2.4.0-enterprise (Build 2026.11)  
**Target Repository:** `https://github.com/545e/snmk.git`  
**Active Branch:** `enterprise/platform-master-pass`  
**Audit Category:** Hybrid Systems Integration  
**Audit Status:** `[IMPLEMENTED] [TESTED]`  

---

## 1. Integration Design
The C++ scanner is integrated into Python via `core/scanner_integrations.py` and `core/tool_dependency_manager.py`.

## 2. Interoperability Mechanics
- **Invocation Protocol:** Python executes `tools/bin/snmk_fast_scan.exe` via `asyncio.create_subprocess_exec()` with structured CLI flags (`--target`, `--ports`, `--threads`, `--timeout`).
- **Data Exchange Format:** High-performance JSON stdout stream parsed via Python's native `json.loads()`.
- **Fault-Tolerant Fallback:**
  ```python
  if not cpp_binary_available():
      logger.warning("C++ engine not found; falling back to asynchronous Python sockets")
      return await python_async_socket_scan(target, ports)
  ```
- **Process Isolation:** Memory faults or abnormal termination in native code cannot crash the parent Python FastAPI server process.
