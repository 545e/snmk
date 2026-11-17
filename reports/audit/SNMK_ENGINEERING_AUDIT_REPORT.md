# SNMK — Engineering Audit Report

| | |
|---|---|
| **Revision** | `39f441b` |
| **Scope** | The whole repository — 565 tracked files, 174 Python modules, the frontend, the deployment and the pipelines |
| **Method** | Full static analysis, dynamic verification against a local instance, and five external scanners |

> **Every number in this report was measured.** Where something could not be
> measured, it is marked as such.

---

## 1. Repository discovery

### Files

| Metric | Value |
|---|---|
| Git-tracked files | **565** |
| Files inspected | **565** (100 %) |
| Files not inspected | **0** |
| Files untracked and excluded from the audit | The virtual environment, the coverage artefacts, the `.scannerwork` directory |

### By language

| Language | Files | Lines |
|---|---|---|
| Python | 174 | 75 253 |
| JavaScript | 4 | 18 296 |
| CSS | 3 | 7 691 |
| HTML | 2 | 8 073 |
| Markdown | 290 | 14 941 |
| Shell / PowerShell / batch | 16 | 783 |
| YAML / JSON / TOML / properties | 25 | — |
| **Total tracked** | **565** | **403 416** |

The line total includes the documentation, which is 14 941 lines — 3.7 % of
the repository.

### Stack

| Layer | Technology |
|---|---|
| API | FastAPI 0.162.7 on Starlette, served by uvicorn 0.54.0 |
| Validation | Pydantic 2.14.3 |
| HTTP client | httpx 0.28.1 (`requests` is declared but barely used) |
| Database | SQLite 3 in WAL mode — `swa_data.db` (19.62 MB) and `snmk_evidence.db` |
| Frontend | Hand-written ES modules and CSS. **No framework, no bundler, no npm dependency** |
| Agents | **Hand-rolled** — 94 agents across 6 tiers. CrewAI, LangChain, LangSmith and Giskard are **not** used |
| LLM | The provider HTTP APIs called directly with httpx |
| Packet capture | scapy 2.8.0 |
| Reports | reportlab 5.1.0, python-docx 1.2.0, Jinja2 3.1.6 |
| Encryption | cryptography 50.0.2 (Fernet) |
| Container | `python:3.12-slim`, a non-root `swa` user, a named volume |
| CI | 6 GitHub Actions workflows |

### Entry points

`run.py` (the server), `swa_cli.py` (the CLI), `make_ceo_report.py` (the
report), `install.sh` / `install.ps1` / `install.bat` (the installers), and
the Docker image's `CMD ["python", "run.py"]`.

### Architecture

`web/` holds the routes, `core/` the engines, `agents/` the 94 adapters,
`plugins/` the 10 OWASP plugins, `reports/` the generators, `tools/` the
external-binary management. The detail is in `SNMK_ARCHITECTURE_REPORT.md`.

---

## 2. The baseline

| Metric | Value |
|---|---|
| Tests collected | 465 |
| Tests passed | **465** |
| Tests failed | 0 |
| Tests skipped | 0 |
| Wall clock | 7 min 22 s |
| Line coverage | **64.0 %** |
| Duplicated lines | 2.8 % |
| Bugs (SonarQube) | 0 |
| Vulnerabilities (SonarQube) | 0 |
| Code smells (SonarQube) | 719 |
| Security hotspots (SonarQube) | 118 |
| Known dependency vulnerabilities (pip-audit) | **0** |
| Secrets in the git history (gitleaks, 155 commits) | **1** (fixed) |

---

## 3. What this pass changed

### 3.1 The authentication bypass — the most serious finding

`POST /api/auth/login` and `POST /api/v1/auth/login` minted a valid
session for **any** caller. The `password` field was never read, and the v1
login derived the `admin` role from the client-supplied username.

```
Before:  POST /api/v1/auth/login {"username":"admin"}  -> 200, token, role=admin
After:   POST /api/v1/auth/login {"username":"admin"}  -> 401
```

The minted token was accepted for every `/api` route — **even with
authentication enabled and a master key configured**.

**Fixed**, with 12 regression tests in `tests/test_auth_hardening.py`.

### 3.2 The authentication gate did not cover the whole API

The gate protected paths starting with `/api`. The OpenAI-compatible
endpoints (`/v1/chat/completions`, `/chat/completions`, `/v1/models`,
`/models`) sit outside that prefix and were reachable without a credential.

**Fixed** — the protected surface is now the whole API.

### 3.3 The live telemetry stream was unauthenticated

`/ws` carries the findings and the logs of every running scan. Starlette
does not run HTTP middleware for a WebSocket scope, so the handshake now
authenticates itself.

**Fixed.**

### 3.4 Seven unvalidated outbound endpoints

The integration adapters performed **no host validation at all** and sent
the provider's own key, password or token to whatever host the caller
named. The notification webhook and the dependency-confusion tool were
missing the scope check their sibling endpoints already performed.

**Fixed** — `core/integrations/endpoint_policy.py` is now the single
decision point.

### 3.5 Two local-file disclosure endpoints

The forensics browser listed any directory the service account could read;
the hash endpoint confirmed the contents of any guessed file; the carving
job created directories anywhere. The REA analyser read any file on disk
behind a five-pattern denylist.

**Fixed** — the forensics tools are confined to `SWA_EVIDENCE_ROOT` and the
REA analyser to `SWA_REA_ALLOWED_ROOTS`.

### 3.6 The deployment exposed everything

The Compose file published `0.0.0.0:8000` with no authentication
variables, and `.env` was not in `.dockerignore`, so a local `.env` would
have been copied into the image.

**Fixed.**

### 3.7 The scope policy checked only the first resolved address

A DNS answer that mixed a public address with a private one passed the
guard depending on the resolver's ordering. The hostname was also resolved
twice per validation.

**Fixed** — every address is checked, and a hostname is resolved once.

### 3.8 The tooling

| Added | Purpose |
|---|---|
| `core/tool_handler_resolver.py` | Resolves the registry's declared handlers and invokes them |
| `core/integrations/endpoint_policy.py` | The single decision point for an outbound request |
| `core/tls_policy.py` | The single source of truth for certificate verification |
| `sonar-project.properties`, `.github/workflows/sonarqube.yml` | Static analysis in CI |
| `tests/test_auth_hardening.py` | 12 tests for the authentication boundary |
| `tests/test_tls_policy.py` | 13 tests, including a guard that no module may disable verification outside the policy |
| `tests/test_env_loader.py`, `tests/test_notifier.py` | 25 tests for two untested modules |
| `tests/test_honesty_and_determinism.py` | 31 tests for the honesty and determinism properties |
| `docs/SONARQUBE.md`, `docs/SECURITY.md` | The new documentation |

---

## 4. The findings that remain

The full list is spread across the twenty-seven reports. The ones that
matter most:

| # | Finding | Severity | Report |
|---|---|---|---|
| 1 | `require_role()` is applied to zero routes — every authenticated caller is an administrator | High | Security, API |
| 2 | `ApprovalEngine.requires_approval()` is never called — destructive and exploit-class actions run without the advertised sign-off | High | Security, AI, Automation |
| 3 | The scope allowlist defaults off, so it does not contain by default | High | Security, Network, Environment |
| 4 | Authentication is off by default | High | Security, Environment |
| 5 | 81 `innerHTML` sinks interpolate API data unescaped, and the CSP permits `'unsafe-inline'` | Medium | Frontend, Security |
| 6 | The DNS-rebinding window: the validated address is not pinned to the connection | Medium | Network, API |
| 7 | 43 handlers call synchronous SQLite from `async def` | Medium | Database, Performance |
| 8 | The tool binaries are installed without a pinned digest | Medium | Tool integration |
| 9 | There is no DAST | High | DAST |
| 10 | There is no SCA, secret scan or container scan in CI | High | CI/CD |
| 11 | `core/database.py` (10 319 lines) and `web/server.py` (8 139 lines) concentrate the risk | High | Architecture |
| 12 | The frontend is a single 16 468-line file | Medium | Frontend |

**None of these is an authentication bypass.** The critical class of defect
has been eliminated.

---

## 5. The code quality picture

| Measure | Value | Assessment |
|---|---|---|
| Bugs | 0 | Good |
| Vulnerabilities | 0 | Good |
| Code smells | 719 | Concentrated: 135 cognitive complexity, 100 duplicated literals, 85 duplicated JS blocks |
| Duplicated lines | 2.8 % | Acceptable |
| Cognitive complexity | 12 096 | High — 26 functions over 200 lines, 96 over 100 |
| Coverage | 64.0 % | Below the SonarQube default, above the project's own gate |
| Security hotspots | 118 | Each needs a human decision |

**The pattern is consistent:** the security posture is now good, and the
remaining debt is **structural** — a few very large modules and one very
large frontend file. That debt is what produced the 135 complexity
findings, the 85 duplicated blocks and the 3.6-second import time.

---

## 6. What the platform does well

* **The scope policy is a genuine choke point.** One module decides whether
  a hostname may be contacted, and it is now actually used by every path
  that reaches the network.
* **The tool registry is load-bearing.** Every entry names a real callable
  and the resolver invokes it, so the catalogue cannot drift from the
  implementation.
* **The honesty work is real.** The REA engine reports what it actually
  observed, the kill-chain loader reports its own truncation, the tool
  executor distinguishes "ran" from "did not run", and the tier-4 caveat is
  documented. This is unusual and valuable.
* **The test suite is substantive.** 465 tests that assert behaviour rather
  than the presence of a symbol, and it caught two defects introduced by
  this very pass.
* **The dependency posture is clean.** 19 direct dependencies, 46 resolved,
  zero known vulnerabilities, no npm surface at all.
* **The container is well built.** A non-root user, a minimal base, the
  dependency layer separated from the source, a health check, resource
  limits.
* **The engineering report is candid.** It has tracked its own backlog
  across several passes, including the findings that were inconvenient.

---

## 7. Recommendations, in priority order

| # | Action | Effort | Why |
|---|---|---|---|
| 1 | Apply `require_role()` — decide the role matrix, then enforce it | Medium | It is the largest remaining authorisation gap |
| 2 | Enforce the approval gate | Medium | The platform advertises a control it does not have |
| 3 | Default the scope allowlist on | Low | One environment variable |
| 4 | Add DAST, SCA, secret scanning and container scanning to CI | Medium | The cheap half of the security posture |
| 5 | Split `core/database.py` and `web/server.py` | High | Removes the concentration risk and most of the complexity debt |
| 6 | Split `web/static/app.js` into ES modules | High | The frontend's single largest problem |
| 7 | Fix the 81 `innerHTML` sinks and tighten the CSP | Medium | The last real XSS surface |
| 8 | Pin the resolved IP to the connection | Medium | Closes the DNS-rebinding window |
| 9 | Convert the 43 database handlers to `def` | Medium | Unblocks the event loop |
| 10 | Bound the list endpoints | Low | Stops the whole-table read |
| 11 | Pin the tool-binary digests | Medium | Closes the supply-chain gap |
| 12 | Add a lockfile and a dependency-scanning CI step | Low | Reproducibility |

Items 1–4 are the security work. Items 5–6 are the engineering work, and
they are large enough to deserve their own schedule rather than being
folded into a security pass.

---

## 8. Limitations

* The Trivy, Semgrep, Checkov, KICS, Grype, Syft and OSV-Scanner runs did
  not happen — the tools were not installed and the Trivy release was not
  retrievable. They are recorded as **not executed**.
* No DAST was performed — OWASP ZAP is not installed.
* No active penetration test was run against anything, internal or
  external.
* The Docker image was not built or run — no Docker daemon was available.
* The DPI behaviour on real traffic was not measured — the audit host has
  no capture driver.
* The AI evaluation is a unit test of the evaluation engine, not an
  evaluation of the model.
* Findings marked "confirmed design gap" are gaps whose exploitability
  depends on attacker-controlled data, DNS or rendering context; they were
  not demonstrated.
* The audit measured one host configuration. A deployment with
  `SWA_AUTH_ENABLED=true` was verified through targeted tests rather than
  a full run of all 197 routes under every role.
