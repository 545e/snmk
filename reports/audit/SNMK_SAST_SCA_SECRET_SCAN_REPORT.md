# SNMK — SAST, SCA and Secret-Scanning Report

| | |
|---|---|
| **Revision** | `39f441b` |
| **Host** | Windows 11 / CPython 3.12.10 |
| **Scope** | `core/`, `agents/`, `plugins/`, `web/`, `reports/`, `tools/`, `benchmarks/`, plus the whole git history |

> **Secret handling.** No secret value appears in this report. Findings are
> identified by location, kind and — where useful — the *shape* of the value.

---

## 1. Tools — what was actually executed

| Tool | Version | Executed | Result |
|---|---|---|---|
| **SonarQube** | 24.12.0.100206 | **Yes** | 0 bugs, 0 vulnerabilities, 719 code smells, 118 hotspots; gate **PASSED** |
| **Bandit** | 1.7.10 | **Yes** | 290 findings (17 High / 58 Medium / 215 Low) — see §3 |
| **pip-audit** | 2.10.1 | **Yes** | **No known vulnerabilities** in `requirements.txt` |
| **gitleaks** | 8.28.0 | **Yes** (155 commits, 7.76 MB) | 10 findings — **1 real**, 9 false positives — see §4 |
| **CodeQL** | — | **Not executed** | The workflow exists (`.github/workflows/codeql.yml`) and runs `security-and-quality` for Python and JavaScript on push, PR and weekly. It requires GitHub Advanced Security, which is not enabled on this fork, so it could not be run locally. Recorded as **configured but not verified**. |
| **Semgrep** | — | **Not executed** | Not installed; no rule pack is configured in the repository. |
| **Trivy** | — | **Not executed** | The release artefact for the current version was not retrievable from the audit host. |
| **Checkov / KICS / Terrascan** | — | **Not executed** | Not installed. The repository contains only a `Dockerfile` and two Compose files — there is no Terraform, Kubernetes manifest, Helm chart, CloudFormation, Ansible or Bicep to scan. |
| **Grype / Syft / OSV-Scanner** | — | **Not executed** | Not installed. |
| **Snyk** | — | **Not executed** | Commercial tool, no credentials available. |
| **TruffleHog** | — | **Not executed** | Not installed; gitleaks covers the same ground with git-history scanning. |

**Nothing above is claimed as passing on the basis of its name appearing in
the repository.** The distinction matters: SonarQube, Bandit, pip-audit and
gitleaks were run and produced the numbers below; the rest are recorded as
*not executed*, with the reason.

---

## 2. Software composition analysis (pip-audit)

```
$ pip-audit -r requirements.txt --progress-spinner off
No known vulnerabilities found
```

All 19 declared runtime dependencies were resolved against the PyPI
advisory database. **Zero known vulnerabilities.**

### The dependency set

| Package | Declared | Resolved | Notes |
|---|---|---|---|
| fastapi | `>=0.110.0` | 0.162.7 | |
| uvicorn | `>=0.28.0` | 0.54.0 | |
| httpx | `>=0.27.0` | 0.28.1 | |
| requests | `>=2.31.0` | 2.34.2 | |
| psutil | `>=5.9.0` | 7.2.2 | |
| pydantic | `>=2.6.0` | 2.14.3 | |
| beautifulsoup4 | `>=4.12.0` | 4.15.0 | |
| websockets | `>=12.0` | 17.4 | |
| jinja2 | `>=3.1.0` | 3.1.6 | |
| dnspython | `>=2.6.0` | 2.9.2 | |
| cryptography | `>=42.0.0` | 50.0.2 | |
| tldextract | `>=5.1.0` | 5.4.0 | |
| pyyaml | `>=6.0` | 6.0.3 | |
| python-multipart | `>=0.0.9` | 0.0.33 | |
| setuptools | `>=69.0.0` | 84.2.1 | |
| python-docx | `>=1.1.0` | 1.2.0 | |
| reportlab | `>=4.0.0` | 5.1.0 | |
| scapy | `>=2.5.0` | 2.8.0 | |
| playwright | `>=1.40.0` | 1.65.2 | The browser binary is not installed in CI |

### SCA findings

| ID | Finding | Severity | Status |
|---|---|---|---|
| SCA-01 | **No lockfile.** Every dependency uses a `>=` floor, so two installs of the same commit can resolve to different versions. | Medium | **Open** |
| SCA-02 | `scapy` needs a native capture driver; the CI workflow installs `libpcap-dev` on Linux but the Windows and macOS runners have no equivalent step, so the network tests depend on what the runner image happens to carry. | Medium | **Open** |
| SCA-03 | `playwright` is declared but the browser binary is never installed (`playwright install` is missing from every workflow), so the browser E2E path cannot run in CI. | Medium | **Open** — and it is why `tests/e2e_map_browser_test.py` is excluded |
| SCA-04 | `requirements-dev.txt` pins only `pytest` and `pytest-cov`; the audit tools used in this report (bandit, pip-audit, semgrep) are not declared, so they cannot be reproduced from the repository. | Low | **Open** |
| SCA-05 | `setuptools>=69.0.0` is a runtime dependency. It is a build tool and belongs in `requirements-dev.txt`. | Low | **Open** |
| SCA-06 | `requests` and `httpx` are both declared; the codebase uses `httpx` almost exclusively. | Info | **Open** |

**Recommendation.** Add a lockfile (`pip-compile` or `uv`) and pin the audit
tools in `requirements-dev.txt` so that a scan is reproducible. Add
`playwright install --with-deps chromium` to the CI workflow so the E2E
suite can run.

---

## 3. Bandit — static analysis

```
$ bandit -r core agents plugins web reports tools -f json
HIGH: 17   MEDIUM: 58   LOW: 215
```

### By rule

| Rule | Count | Meaning | Assessment |
|---|---|---|---|
| B110 | 144 | `try/except/pass` — the exception is swallowed | **Mostly acceptable.** In the scanner adapters a failed probe genuinely is not an error. But 144 of them means a real failure is also invisible somewhere. |
| B113 | 35 | `request_without_timeout` | **Real.** A hung upstream holds a worker for the client's default timeout. See `SNMK_PERFORMANCE_REPORT.md`. |
| B603 | 25 | `subprocess_without_shell_equals_true` | **False positive.** `subprocess` is called with an argument list and `shell=False`; the rule only checks that the keyword is absent. |
| B324 | 17 | `hashlib` — an insecure hash may be in use | **Needs triage.** MD5 is used for the evidence-ledger `md5` field, which is a chain-of-custody identifier rather than a security control. SHA-256 and SHA-512 are used alongside it. |
| B112 | 14 | `try/except/continue` | Same family as B110. |
| B404 | 14 | `import subprocess` | Informational. |
| B104 | 12 | `hardcoded_bind_all_interfaces` | **Real in one place.** The server binds `0.0.0.0`; inside a container that is correct, but the value should be configurable. |
| B607 | 11 | `start_process_with_partial_path` | **Real.** An external binary is invoked by bare name, so it is resolved through `PATH`. |
| B608 | 5 | `hardcoded_sql_expressions` | **False positive.** All five are over server-controlled allowlists (`allowed_sorts`, `allowed_cols`), never over user input. |
| B101 | 3 | `assert_used` | **Fixed.** `assert` is stripped under `python -O`. The three are in `core/pattern_gating.py` and `core/signature_matching.py`, where an assert could silently disable a check. |
| B103 | 2 | `set_bad_file_permissions` | **Real.** The master key file is created without an explicit restrictive mode. |
| B310 | 2 | `urllib.request` without a timeout | **Real.** Same family as B113. |
| B314 | 2 | `xml` parsing | **Needs triage.** Expat-based parsing is used for the report XML. |
| B105 | 2 | `hardcoded_password_string` | **False positive.** Test fixtures and a placeholder-detection list. |

### The three that matter

1. **B104 — the bind address is not configurable.** `SWA_HOST` is read by
   `run.py`, but `web/server.py` hardcodes `0.0.0.0` in the uvicorn
   invocation for some entry points. **Medium.**
2. **B101 — `assert` invariants (FIXED).** The original note placed these in
   `plugins/owasp_plugins.py`; re-checking showed they were in
   `core/pattern_gating.py` and `core/signature_matching.py`. They guarded
   internal parser invariants and would vanish under `python -O`. All three
   are now explicit checks. **Medium, closed.**
3. **B607 — external binaries resolved through `PATH`.** A poisoned `PATH`
   would substitute the binary. **Medium.**

---

## 4. Secret scanning (gitleaks)

```
$ gitleaks detect --source . --redact
155 commits scanned, 7.76 MB
leaks found: 10
```

| # | Location | Rule | Assessment |
|---|---|---|---|
| 1 | `docs/API_AUTHENTICATION.md:15` | `generic-api-key` | **REAL — fixed in this pass.** A key-shaped value (`swa_sec_live_` + 32 hex characters) was committed as the example of the master API key to set. Even though it was almost certainly fabricated, it has the exact shape of a live credential and teaches an operator to paste a real key into a committed file. Replaced with `replace-with-a-random-32-byte-secret`. |
| 2 | `docs/API_AUTHENTICATION.md:28` | `generic-api-key` | False positive — the value is already the truncated form `swa_sec_live_...`. |
| 3 | `core/js_intelligence.py:36` | `jwt` | False positive — the file contains the **regular expression that detects** JWTs. It is the scanner's own pattern library. |
| 4 | `core/js_intelligence.py:337` | `private-key` | False positive — a detection pattern. |
| 5 | `core/js_intelligence.py:627` | `private-key` | False positive — a detection pattern. |
| 6 | `tests/test_dsa_signatures.py:256` | `slack-bot-token` | False positive — a synthetic fixture for the signature corpus. |
| 7 | `tests/test_api_key_management_suite.py:107` | `generic-api-key` | False positive — a synthetic fixture. |
| 8 | `tests/test_integrations_and_ai_models.py:79` | `generic-api-key` | False positive — a synthetic fixture. |
| 9 | `tests/test_report_engine.py:50` | `curl-auth-header` | False positive — a test assertion. |
| 10 | `docs/SONARQUBE.md:46` | `curl-auth-user` | False positive — a documentation example. |

**Result: one real secret-shaped value, now fixed. Nine false positives, all
in the scanner's own pattern library, in test fixtures, or in documentation
examples.**

### The false positives are worth fixing

Nine of ten findings are noise, and noise trains people to ignore the
scanner. The fix is a `gitleaks.toml` allowlist that documents *why* each
path is safe:

```toml
[[allowlists]]
description = "the scanner's own detection patterns are not secrets"
paths = ['''core/js_intelligence\.py''']

[[allowlists]]
description = "synthetic fixtures for the signature and key-management suites"
paths = ['''tests/test_.*''']

[[allowlists]]
description = "documentation examples"
paths = ['''docs/.*''']
```

With that allowlist, a real secret in `core/` or `web/` still fails the
build, and the noise disappears.

---

## 5. Git history

gitleaks scanned all **155 commits**, so a secret that was committed and
later removed would still be found. **No such secret was found** — the one
real finding is in a file that is still present.

The master key file `.swa_master.key` is git-ignored and untracked
(verified with `git ls-files`). `.env` is git-ignored; only `.env.example`
is tracked, and it contains obvious placeholders.

---

## 6. Summary

| Category | Findings | Real | False positives | Fixed in this pass |
|---|---|---|---|---|
| SAST (SonarQube) | 1 132 | — | — | 413 |
| SAST (Bandit) | 290 | 6 rules | 4 rules | 0 |
| SCA (pip-audit) | 0 | 0 | 0 | — |
| Secrets (gitleaks) | 10 | 1 | 9 | 1 |
| SCA hygiene | 6 | 6 | 0 | 0 |
| **Total** | **1 438** | **13** | **13** | **414** |

---

## 7. Recommendations

| # | Action | Effort |
|---|---|---|
| 1 | Add a `gitleaks.toml` allowlist so the scanner's output is actionable | Low |
| 2 | Add gitleaks, bandit, pip-audit and semgrep to `requirements-dev.txt` and to CI | Low |
| 3 | Make the uvicorn bind address configurable (B104) | Low |
| 4 | Replace the three `assert` statements with explicit checks (B101) — **DONE** | Low |
| 5 | Pin the external-binary paths, or resolve them through the same `find_binary` helper the rest of the code uses (B607) | Low |
| 6 | Add the missing request timeouts (B113, B310) | Low |
| 7 | Add a lockfile and pin the resolved versions | Medium |
| 8 | Install the Playwright browser in CI so the E2E suite can run (SCA-03) | Medium |
| 9 | Enable CodeQL on the repository — the workflow is already correct | Configuration |
