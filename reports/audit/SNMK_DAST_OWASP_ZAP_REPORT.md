# SNMK — DAST / OWASP ZAP Report

| | |
|---|---|
| **Revision** | `39f441b` |
| **Method** | Review of every DAST-relevant artefact in the repository |

---

## 1. The position

**No dynamic application security testing is configured, and no DAST run was
performed.**

| Artefact | Present | Notes |
|---|---|---|
| OWASP ZAP | **No** | Not installed on the audit host; not declared; no ZAP container; no baseline script |
| A DAST workflow in CI | **No** | None of the six workflows performs a dynamic scan |
| A ZAP baseline configuration | **No** | |
| A ZAP API scan configuration | **No** | |
| An OpenAPI export for a scanner | **No** | The application *exposes* `/openapi.json`, but nothing imports it into a scanner |
| A replayable HTTP collection (Postman/Newman) | **No** | No `package.json`, so no Newman |
| A recorded request corpus | **No** | `tests/e2e/rt_harness.mjs` (514 lines) drives a browser, not a scanner |

**This is recorded as a gap, not as a pass.** Nothing in this report claims
that a dynamic scan was run or that the application passed one.

---

## 2. What DAST would have found here

The audit's manual review found the same class of defect a DAST run would
have surfaced — and found it by reading the code, because no scanner was
available:

| Class | Found by the manual review |
|---|---|
| **Authentication bypass** | The login endpoints minted a session for any caller. A DAST scan with a "login with a wrong password and continue" scenario would have found this immediately. **Fixed in this pass.** |
| **Missing authentication** | The OpenAI-compatible endpoints sat outside the `/api` prefix the gate protected. A scanner hitting `/v1/chat/completions` would have found it. **Fixed in this pass.** |
| **Unauthenticated WebSocket** | The `/ws` telemetry stream. A scanner does not test WebSockets by default — this one needed a manual look. **Fixed in this pass.** |
| **SSRF** | Seven endpoints fetched an operator-supplied URL. A scanner with a metadata-endpoint payload would have found the integration ones. **Fixed in this pass.** |
| **Path traversal** | The kill-chain report download. **Open.** |

**The honest observation:** a DAST pipeline would have caught the
authentication bypass and the missing-authentication findings without any
of this work. The absence of DAST is a real gap in the security posture,
and it is the cheapest of the gaps to close.

---

## 3. Why no DAST is currently configured — and what it would take

### The obstacle

The platform is a **single-user, locally-running security console**. A DAST
scan needs a running instance and a scanner that can reach it. The pieces
are all present; the wiring is not:

| Requirement | Available? |
|---|---|
| A running instance | Yes — `run.py` / the container |
| An API description for the scanner | **Yes** — `/openapi.json` exposes 360 paths |
| A scanner | **No** — ZAP is not installed and no container is configured |
| An authentication story for the scanner | **Partly** — after this pass the API can require a bearer token, so a scanner could be given one |
| A scope restriction | **Available** — the platform has its own scope policy, but a scanner needs its own |

### The concrete plan

**Step 1 — a ZAP baseline in CI.** The simplest form:

```yaml
- name: DAST (OWASP ZAP baseline)
  run: |
    docker run --rm -v "$PWD:/zap/wrk" \
      ghcr.io/zaproxy/zaproxy:stable \
      zap-baseline.py -t http://host.docker.internal:8000 \
                      -r zap-baseline.html -I
```

The baseline scan is **passive** by default. It crawls the application and
reports what it finds without sending an attack. That is the right first
step: it produces an inventory of the API surface and the security headers
without changing the application's behaviour.

**Step 2 — an API scan from the OpenAPI document.** The application already
publishes the description, which is exactly what an API scan consumes:

```yaml
- name: DAST (OWASP ZAP API scan)
  run: |
    curl -fsS http://localhost:8000/openapi.json -o openapi.json
    docker run --rm -v "$PWD:/zap/wrk" \
      ghcr.io/zaproxy/zaproxy:stable \
      zap-api-scan.py -t http://host.docker.internal:8000 \
                      -f openapi.json -r zap-api.html -I
```

**Step 3 — an authenticated scan.** The API now accepts a bearer token, so
the scan can be given one through a `replacer` configuration:

```yaml
      zap-api-scan.py ... \
        -c zap-auth-replace.json
```
```json
[{ "description": "Bearer", "enabled": true, "matcher": ".*",
   "replacement": "{{API_TOKEN}}" }]
```

**Step 4 — active scanning, in a lab only.** The active rules can send
real attack payloads. That is only appropriate against a deliberately
vulnerable lab instance, never against a target the operator is assessing.
The repository already has `config/targets.json` and a lab-mode concept;
a DAST lab would be the same discipline.

### The rules this audit would impose

| Rule | Reason |
|---|---|
| The DAST job runs against a **local instance only** | Never against an external target |
| The baseline (passive) scan runs on every PR | Cheap, safe, and it is the one that would have caught the auth bypass |
| The active scan runs only on a schedule, against a lab fixture | It sends real attack payloads |
| A ZAP finding does **not** block the pipeline on its own | ZAP's fingerprints have a high false-positive rate; a blocking gate needs a reviewed baseline |
| The HTML and JSON reports are uploaded as artefacts | The findings have to be reviewable |
| An allowlist file is committed | So the false positives are documented rather than re-discovered every run |

---

## 4. Passive findings that a baseline scan would report

These were identified by reading the application's own response headers and
routes, and are exactly what a passive scan reports:

| Finding | Location | State |
|---|---|---|
| The Content-Security-Policy contains `'unsafe-inline'` and `'unsafe-eval'` in `default-src` | `web/server.py:303` | **Open** — it also blocks the 81 unescaped `innerHTML` sinks from being a real XSS vector |
| `X-XSS-Protection: 1; mode=block` is set | `web/server.py:293` | Obsolete — the header has been deprecated in every browser for years and does nothing |
| The OpenAPI schema and `/docs` are public | `core/app_security.py:29` | **Open** — by design for a local tool |
| `/api/auth/status` discloses the authentication configuration | `web/server.py:477` | **Open** |
| `X-Frame-Options: SAMEORIGIN` is set | `web/server.py:291` | Good |
| `Referrer-Policy: strict-origin-when-cross-origin` is set | `web/server.py:295` | Good |
| `Permissions-Policy` restricts six browser capabilities | `web/server.py:297` | Good |
| `X-Content-Type-Options: nosniff` is set | `web/server.py:289` | Good |
| `Strict-Transport-Security` | Only when `SWA_FORCE_HSTS=1` | Off by default — correct for a local HTTP tool, required behind TLS |

---

## 5. What the DAST gap would have cost

The two Critical authentication findings in this audit would have been
caught by a **passive baseline scan with a login flow**, in minutes, without
reading a single line of source.

That is the strongest argument for adding DAST to this project: not because
DAST finds things SAST cannot, but because it exercises the *running*
application, which is where authentication and authorisation actually live.

---

## 6. Findings

| ID | Finding | Severity | Status |
|---|---|---|---|
| DAST-01 | **No DAST is configured at all.** | High | **Open** |
| DAST-02 | The CSP permits `'unsafe-inline'` and `'unsafe-eval'` | Medium | **Open** |
| DAST-03 | The obsolete `X-XSS-Protection` header is sent | Low | **Open** — remove it |
| DAST-04 | The OpenAPI schema is public | Low | **Open** — by design, disable in production |
| DAST-05 | `/api/auth/status` discloses the authentication configuration | Low | **Open** |
| DAST-06 | The path traversal in the kill-chain report download would have been found by a scanner | High | **Open** |

---

## 7. Recommendations

| # | Action | Effort | Closes |
|---|---|---|---|
| 1 | Add a passive ZAP baseline scan to the CI workflow, against a local instance only | Low | DAST-01 |
| 2 | Add a ZAP API scan from the published `openapi.json` | Medium | DAST-01, DAST-06 |
| 3 | Commit a ZAP allowlist file so the false positives are documented | Low | DAST-01 |
| 4 | Upload the ZAP reports as workflow artefacts | Low | DAST-01 |
| 5 | Remove the obsolete `X-XSS-Protection` header | Low | DAST-03 |
| 6 | Tighten the CSP: remove `'unsafe-inline'` and `'unsafe-eval'`, use nonces | Medium | DAST-02 |
| 7 | Fix the path traversal in the report download | Low | DAST-06 |
| 8 | Gate `/docs` and `/openapi.json` behind the authentication middleware in production | Low | DAST-04 |
