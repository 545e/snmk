# SNMK — Tool Integration Report

| | |
|---|---|
| **Revision** | `39f441b` |
| **Scope** | `core/tool_registry.py`, `core/scanner_integrations.py`, `core/tool_dependency_manager.py`, `core/tool_handler_resolver.py`, `core/integrations/` |
| **Method** | Route and handler enumeration against a live instance; review of every execution path |

---

## 1. The three views of a tool

SNNK describes the same external tools from three angles, and the audit
verified each one:

| Module | Role | Count |
|---|---|---|
| `core/tool_registry.py` | **The catalogue.** Each entry declares the schema, the purpose, the authorisation requirement and the handler. | 34 entries |
| `core/scanner_integrations.py` | **The executor.** Runs the installed binaries safely. | 15 tools |
| `core/tool_dependency_manager.py` | **The installer.** Downloads, verifies and installs the binaries. | 15 tools |
| `core/integrations/` | **The provider adapters.** Reach the third-party APIs. | 22 providers |

**All 34 catalogue entries now resolve to a real callable.** Before this
pass, 14 named attributes that did not exist.

---

## 2. The catalogue — `core/tool_registry.py`

| Property | State |
|---|---|
| Entries | 34 |
| Every `backend_handler` resolves | ✔ **Verified: 34/34** |
| The handler is invocable | ✔ via `core/tool_handler_resolver.py` |
| The schema is declared | ✔ An input and an output schema per entry |
| The authorisation requirement is declared | ✔ `authorization_required` and `authorization_scope` |
| The declaration is published | ✔ `GET /api/tools/registry` now includes a `handler_resolution` block per tool |

### The authorisation fields are decorative — and this is a known open item

`authorization_required` and `authorization_scope` are declared on every
entry and **are not enforced**. `require_role()` is applied to zero routes.
This is the DSA report's DSA-AI-08/26 and it is a **policy change** that
needs a security owner's decision on the role matrix, so it has not been
altered here.

### Finding TI-01 (High, open): the declared authorisation metadata has no
effect.** The catalogue says which tools need which permission; nothing
reads it.

---

## 3. The resolver — `core/tool_handler_resolver.py`

New in an earlier pass of this work. It makes the catalogue load-bearing:

```python
func, is_bound = resolve_handler("core.scanner_integrations:ScannerIntegrations.run_nmap_safe")
kwargs, missing = _build_kwargs(func, payload)
result = await invoke_handler(handler, payload, instance_factory)
```

| Capability | State |
|---|---|
| Resolves a `module:attribute.attr` string | ✔ |
| Distinguishes a bound method from an unbound one | ✔ |
| Binds the request payload to the handler's signature by parameter name | ✔ |
| Coerces the value to the annotated type | ✔ |
| Reports the arguments it could not satisfy | ✔ — `NOT_EXECUTABLE` |
| Reports an unresolvable handler | ✔ — `NOT_IMPLEMENTED` |
| Awaits a coroutine handler | ✔ |

### The handler-to-argument mapping

The resolver binds by **parameter name**, with an alias table so that
`target`, `target_url`, `target_host`, `url` and `host` all resolve to the
same request field, and so on for `scan_id`, `model_name`, `dataset_id`,
`param_name`, `token`, `cookie`, `raw_logs` and the rest.

**Finding TI-02 (Low, open): the alias table is a convention rather than a
contract.** A handler whose parameter is not in the table and not in the
request payload is reported as `NOT_EXECUTABLE`, which is correct but means
adding a handler with an unusual parameter name requires the table to be
extended. The failure mode is safe — it reports rather than guesses.

---

## 4. The executor — `core/scanner_integrations.py`

### The tools

| Tool | Installed on the audit host | Execution method |
|---|---|---|
| nmap | No | `run_nmap_safe()` |
| nuclei | No | `run_nuclei_safe()` |
| sqlmap | **Yes** (1.8.11) | `run_sqlmap_safe_detection()` |
| nikto | No | `run_scanner_safe()` |
| bandit | **Yes** (1.7.10) | `run_scanner_safe()` |
| semgrep | No | `run_scanner_safe()` |
| trivy | No | `run_scanner_safe()` |
| gitleaks | **Yes** (8.28.0) | `run_scanner_safe()` |
| tshark | No | `run_scanner_safe()` |
| OWASP ZAP | No | `run_scanner_safe()` |
| clamav | No | `run_scanner_safe()` |
| wazuh | No | `run_scanner_safe()` |
| microsoft_defender | **Yes** (1.463.291.0) | `run_scanner_safe()` |
| rea | **Yes** (6.9.0) | `core/rea_engine.py` |
| swa_native | Always | The platform's own engines |

### The safe execution path

`run_scanner_safe()` is the generic executor, added in an earlier pass of
this work. Its guarantees:

| Guarantee | State |
|---|---|
| The target is scope-validated before a process is spawned | ✔ |
| A target that starts with `-` is refused | ✔ — the argument-injection guard |
| Only the fixed, non-destructive argument template is used | ✔ — the caller cannot inject flags |
| The subprocess uses an argument list, never a shell | ✔ |
| There is a timeout | ✔ — 120 s |
| The result distinguishes "ran" from "did not run" | ✔ — every result carries `executed` |
| The reason for a refusal is reported | ✔ — `reason` |

### The specialised executors

`run_nmap_safe()` validates the port specification against
`^\d{1,5}([,\-]\d{1,5})*$` and range-checks each port. `run_nuclei_safe()`
and `run_sqlmap_safe_detection()` parse the output into structured findings
rather than returning raw text.

---

## 5. The installer — `core/tool_dependency_manager.py`

| Property | State |
|---|---|
| The manifest | `core/tool_dependency_manager.py:280` builds a default manifest of 15 tools |
| The source allowlist | ✔ `OFFICIAL_SOURCE_ALLOWLIST` — only the named GitHub repositories |
| The URL validation | ✔ `_validate_source_url()` |
| The archive extraction | ✔ `_safe_extract_zip()` / `_safe_extract_tar()` reject traversal and symlinks |
| The integrity check | **The SHA-256 is computed and compared against nothing** |
| The signature check | **None** |
| The rollback | ✔ There is a rollback on error |
| The concurrency | ✔ A lock per tool, so two installs of the same tool cannot race |
| The cancellation | ✔ A cancellation token per job |

**Finding TI-03 (Medium, open): the integrity check verifies nothing.** The
installer computes the SHA-256 of the bytes it just downloaded and logs
the first 16 characters. A pinned digest in the manifest, or a release
signature, would make the check meaningful.

**Finding TI-04 (Low, open): the binaries are resolved through `PATH`**
(bandit B607, 11 sites), so a poisoned `PATH` substitutes the tool.

---

## 6. The provider adapters — `core/integrations/`

22 providers across five categories: AI providers (6), security platforms
(7), threat intelligence (8) and cloud (3).

### The finding that was fixed

Before this pass the adapters performed **no host validation at all**. The
`endpoint_url` was checked for its scheme and the presence of a host, and
then the request was made — carrying the provider's own credential to
whatever host the caller named.

**Now** every adapter routes through `core/integrations/endpoint_policy.py`:

| Rule | Applies to |
|---|---|
| The scheme must be http/https | All |
| The URL must not embed credentials | All |
| The host must resolve to a public address | All (except Ollama, which is local by design) |
| The host must be on the provider's list | The fixed-host SaaS providers |
| Any public host is accepted | The self-hosted products |

**Finding TI-05 (Medium, open): the "any public host" rule for the
self-hosted products means the provider's credential goes to any public
host the operator names.** That is the intent for a self-hosted product,
and the endpoint mutation requires authentication — but with authentication
off by default, an unauthenticated caller could still redirect it. The
address guard is what makes it an SSRF rather than a credential leak, and
that part holds.

---

## 7. The tools that are declared but not present

The catalogue declares 34 tools. On the audit host, 4 of the 15 external
binaries were present and 11 were not.

**The platform handles this correctly:** `GET /api/tools/health` reports
each tool's status, `installed` flag and install guidance. A tool that is
not installed is reported as `UNAVAILABLE` with the install command, not
as a failure.

**Finding TI-06 (Medium, open): the registry's `installed` field is
hard-coded to `True`.** Every catalogue entry claims to be installed
regardless of whether the binary is present. The catalogue and the
inventory therefore disagree.

---

## 8. The All-Tools path

`POST /api/tools/run-all` runs the whole suite and produces the
Nessus-style report.

| Property | State |
|---|---|
| The orchestration | `agents/orchestrator.py` |
| The scope check | ✔ Each tool validates its target |
| The approval gate | **Not enforced** — TI-01 / PENT-01 |
| The concurrency | Unbounded — PERF-10 |
| The report | ✔ `reports/nessus_report_engine.py` — HTML, PDF, JSON, CSV, XML |
| The audit record | ✔ The scan and its findings are persisted |

---

## 9. Findings

| ID | Finding | Severity | Status |
|---|---|---|---|
| TI-01 | The declared authorisation metadata has no effect | High | **Open** |
| TI-02 | The handler-to-argument alias table is a convention | Low | **Open** |
| TI-03 | The installer's integrity check verifies nothing | Medium | **Open** |
| TI-04 | The binaries are resolved through `PATH` | Medium | **Open** |
| TI-05 | The self-hosted providers accept any public host | Medium | **Open** |
| TI-06 | The catalogue's `installed` flag is hard-coded to `True` | Medium | **Open** |
| TI-07 | 14 of 34 handlers did not resolve | High | **FIXED** |
| TI-08 | The endpoint reported success without executing anything | Critical | **FIXED** |
| TI-09 | The integration adapters had no host validation | High | **FIXED** |

---

## 10. Recommendations

| # | Action | Effort | Closes |
|---|---|---|---|
| 1 | Apply `require_role()` using the catalogue's own `authorization_required` and `authorization_scope` fields | Medium | TI-01 |
| 2 | Pin the expected SHA-256 per tool asset in the manifest | Medium | TI-03 |
| 3 | Resolve the binaries once at install time and record the absolute path | Low | TI-04 |
| 4 | Derive the catalogue's `installed` flag from the inventory rather than hard-coding it | Low | TI-06 |
| 5 | Require authentication before a stored integration credential is sent to a changed endpoint, and audit-log the change | Medium | TI-05 |
| 6 | Extend the alias table as new handlers are added | Incremental | TI-02 |
