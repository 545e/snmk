# SNMK — Automated Penetration Testing Report

| | |
|---|
| **Revision** | `39f441b` |
| **Method** | Review of the platform's own penetration-testing machinery; no external scan was performed |
| **Rule** | No external host was scanned. No exploit was attempted. No intrusive test was run. |

---

## 1. The platform's penetration-testing capability

SNNK *is* a penetration-testing platform. This report audits **its**
capability, not its use against someone else's target.

### The tool adapters

`core/scanner_integrations.py` (1 458 lines) and
`core/tool_dependency_manager.py` (1 522 lines) manage the external
binaries.

| Tool | Managed | Execution path | Safe profile |
|---|---|---|---|
| **nmap** | Yes | `run_nmap_safe()` — `run_scanner_safe()` | `-sV -T3 -Pn --open --version-light` — service detection at a moderate timing, not a stealth or a DoS profile |
| **nuclei** | Yes | `run_nuclei_safe()` | `-tags cve,misconfig -severity low,medium,high -exclude-tags dos,fuzz` — the destructive template tags are excluded |
| **sqlmap** | Yes | `run_sqlmap_safe_detection()` | `--batch --level=1 --risk=1 --technique=BEUST` — the minimum probe volume, non-destructive detection |
| **nikto** | Yes | `run_scanner_safe()` | `-nointeractive -Tuning 123457890` |
| **bandit** | Yes | `run_scanner_safe()` | `-r <path> -f json` — static analysis |
| **semgrep** | Yes | `run_scanner_safe()` | `--config=auto --json --quiet` |
| **trivy** | Yes | `run_scanner_safe()` | `fs --scanners vuln,misconfig` |
| **gitleaks** | Yes | `run_scanner_safe()` | `detect --redact` |
| **tshark** | Yes | `run_scanner_safe()` | `-r <pcap> -q -z conv,tcp` |
| **OWASP ZAP** | Managed | `run_scanner_safe()` | `-cmd -quickurl` — a baseline pass |
| **sqlmap / bandit** | Present on the audit host | — | — |
| **nmap / nuclei / nikto / semgrep / trivy / gitleaks / ZAP** | Not installed on the audit host | — | — |

---

## 2. The safety controls

### Target allowlisting and scope validation
**This is the strongest part of the design.** `core/scope_policy.py` is a
single chokepoint that every network-touching adapter is supposed to route
through, and the adapters that do (`run_nmap_safe`, `run_nuclei_safe`,
`run_sqlmap_safe_detection`) call `validate_tool_target` before spawning a
process.

The audit found **four adapters that did not** route through it:
`/api/notifications/test`, `/api/tools/dependency-check`, the integration
"test connection" endpoints and the AI agent's `base_url`. **All four are
fixed in this pass.**

### Argument-injection defence
The scanner adapters explicitly refuse a target that could be read as a
flag:

```python
# scanner_integrations.py:930
if not target_host or target_host.strip().startswith("-"):
    return {"tool": "nmap", "executed": False, "reason": "Invalid target host."}

# scanner_integrations.py:963 — the port specification is validated
if not re.fullmatch(r"[0-9]{1,5}(?:[,\-][0-9]{1,5})*", ports.strip()):
    return {... "reason": "Invalid ports specification ..."}
```

### No shell
**Every** subprocess uses an argument list. There is no `shell=True` and no
`os.system` anywhere in `core/` or `agents/`.

### Timeouts
Every adapter has one: nmap 45 s, nuclei 60 s, sqlmap 40 s, the health
check 4 s.

### Process cleanup
`asyncio.create_subprocess_exec` with `wait_for`. A timeout ends the wait;
the event loop's child watcher reaps the process.

### Rate limiting
Not per-scan. The platform-wide limiter governs the HTTP surface, not the
spawned processes.

### Scope policy summary

| Rule | State |
|---|---|
| The scheme must be http/https | Yes |
| The hostname is parsed, not the prefix | Yes — `urlparse(...).hostname` |
| Every resolved address is checked | **Fixed in this pass** |
| A hostname is resolved once per validation | **Fixed in this pass** |
| Private / loopback / link-local / metadata are refused | Yes |
| The allowlist must contain the host | Yes, but `SWA_ENFORCE_ALLOWLIST` defaults **off** |
| Lab mode must be explicitly granted | **Partly** — a loopback target is auto-classified as a lab target |

---

## 3. Findings

| ID | Finding | Severity | Status |
|---|---|---|---|
| PENT-01 | **The approval gate is not enforced.** `ApprovalEngine.requires_approval()` is never called, so aggressive scanning, exploit validation and destructive testing run without the human sign-off the platform advertises. | High | **Open** |
| PENT-02 | **`SWA_ENFORCE_ALLOWLIST` defaults off**, so the scope allowlist does not contain by default. | High | **Open** |
| PENT-03 | **A loopback target is auto-classified as a lab target**, so local SSRF needs no lab-mode grant. | Medium | **Open** |
| PENT-04 | **The four adapters that bypassed the scope policy** | High | **FIXED** |
| PENT-05 | **The tool binaries are downloaded without a pinned digest or a signature.** The SHA-256 is computed and compared against nothing. A compromised release asset becomes code execution as the server user. | Medium | **Open** |
| PENT-06 | **The external binaries are resolved through `PATH`** (bandit B607), so a poisoned `PATH` substitutes the binary. | Medium | **Open** |
| PENT-07 | **The nmap safe profile still uses `-sV`**, which sends version-probe packets. It is the correct profile for an assessment, but it is not passive. | Info | Documented |
| PENT-08 | **The nuclei safe profile excludes `dos,fuzz`**, which is correct, but the exclusion list is in the code rather than in a per-scan policy the operator can review. | Low | **Open** |
| PENT-09 | **There is no rate limit on the spawned scanners.** A scan of a large target runs many probes concurrently. | Medium | **Open** |
| PENT-10 | **The exploit validator has no lab-mode check and no approval check.** | High | **Open** — part of PENT-01 |

---

## 4. What was *not* done, and why

| Action | Why not |
|---|---|
| No external target was scanned | There is no authorisation for any third-party host. The scope policy would refuse one anyway — which is the point. |
| No active exploitation | Out of scope and unsafe. |
| No DoS, persistence, lateral movement or exfiltration test | Explicitly excluded by the audit's safety rules and by the platform's own design. |
| The scanners were not run against a lab target | No lab fixture exists in the repository. The platform has a `config/targets.json` and a lab-mode concept, but no ready-made vulnerable target to scan. |
| The exploit validator was not exercised | It requires a real exploit payload against a real vulnerable service. |

**No penetration test was performed against anything.** The findings above
come from reading the platform's own safety machinery.

---

## 5. Recommendations

| # | Action | Effort | Closes |
|---|---|---|---|
| 1 | Enforce `ApprovalEngine.requires_approval()` in the orchestrator and in every offensive adapter; fail closed when lab mode is not explicitly confirmed | Medium | PENT-01, PENT-10 |
| 2 | Default `SWA_ENFORCE_ALLOWLIST=1` | Low | PENT-02 |
| 3 | Require an explicit lab grant rather than inferring it from the target string | Medium | PENT-03 |
| 4 | Pin the expected SHA-256 of each tool release asset in the manifest and verify it before installing | Medium | PENT-05 |
| 5 | Resolve the external binaries once and record their absolute path | Low | PENT-06 |
| 6 | Add a concurrency cap to the scanner dispatch | Medium | PENT-09 |
| 7 | Move the nuclei tag exclusions into a reviewed, per-scan policy file | Low | PENT-08 |
| 8 | Provide a deliberately vulnerable lab fixture (a DVWA or Juice Shop compose service) so the penetration path can be exercised in CI without touching anything external | Medium | — |

---

## 6. Assessment

The platform's penetration-testing machinery is **well designed on the
safety side and under-enforced on the authorisation side**.

The scope policy, the argument-injection defence, the ban on the shell and
the per-tool safe profiles are all genuinely good. The gap is that the
*approval* concept exists and is never applied, and that the allowlist
defaults to off. Those two defaults together mean the platform's careful
safety machinery is mostly inert in a default installation.

Fixing them is a small, well-scoped change: turn on the allowlist, and
call the approval function that already exists.
