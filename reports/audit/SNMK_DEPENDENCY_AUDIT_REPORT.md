# SNMK — Dependency Audit Report

| | |
|---|---|
| **Revision** | `39f441b` |
| **Manifests** | `requirements.txt` (19 runtime), `requirements-dev.txt` (2), `setup.py` |
| **Lockfile** | **None** |
| **JavaScript manifests** | **None** — the project has no `package.json` |

---

## 1. Inventory

### Python runtime dependencies (`requirements.txt`)

| Package | Constraint | Resolved | Role | Licence |
|---|---|---|---|---|
| fastapi | `>=0.110.0` | 0.162.7 | The API framework | MIT |
| uvicorn | `>=0.28.0` | 0.54.0 | ASGI server | BSD |
| httpx | `>=0.27.0` | 0.28.1 | The HTTP client used by every adapter | BSD |
| requests | `>=2.31.0` | 2.34.2 | Legacy HTTP client | Apache-2.0 |
| psutil | `>=5.9.0` | 7.2.2 | Process and system introspection | BSD |
| pydantic | `>=2.6.0` | 2.14.3 | Request/response models | MIT |
| beautifulsoup4 | `>=4.12.0` | 4.15.0 | HTML parsing for the JS analyser | MIT |
| websockets | `>=12.0` | 17.4 | The live telemetry channel | BSD |
| jinja2 | `>=3.1.0` | 3.1.6 | Report templating | BSD |
| dnspython | `>=2.6.0` | 2.9.2 | DNS resolution | ISC |
| cryptography | `>=42.0.0` | 50.0.2 | The credential store's AEAD | Apache/BSD |
| tldextract | `>=5.1.0` | 5.4.0 | Public-suffix handling | BSD |
| pyyaml | `>=6.0` | 6.0.3 | Configuration | MIT |
| python-multipart | `>=0.0.9` | 0.0.33 | Multipart upload parsing | Apache-2.0 |
| setuptools | `>=69.0.0` | 84.2.1 | **Build tool, wrongly a runtime dependency** | MIT |
| python-docx | `>=1.1.0` | 1.2.0 | DOCX report export | MIT |
| reportlab | `>=4.0.0` | 5.1.0 | PDF report export | BSD |
| scapy | `>=2.5.0` | 2.8.0 | Packet capture for the DPI engine | GPL-2.0 |
| playwright | `>=1.40.0` | 1.65.2 | Browser automation | Apache-2.0 |

**All licences are permissive except scapy (GPL-2.0).** See §4.

### Development dependencies (`requirements-dev.txt`)

| Package | Constraint |
|---|---|
| pytest | `>=8.0.0` |
| pytest-cov | `>=5.0.0` |

### JavaScript

**There is no `package.json`, no lockfile, and no `node_modules`.** The
frontend is four hand-written static files served directly by FastAPI:
`web/static/index.html`, `app.js`, `styles.css`, `map.css`, `map.js`,
`digital_forensics.js`.

Consequences, all of which are advantages here:

* **No npm supply-chain surface.** Nothing from the npm registry enters the
  build or the image.
* **No bundler, no build step.** The container builds a Python image and
  nothing else.
* **No dependency updates to manage.** The frontend cannot break because a
  transitive dependency changed.

The cost is the single-file frontend (`app.js` is 16 468 lines), which
`SNMK_FRONTEND_BUILD_AUDIT_REPORT.md` covers.

---

## 2. Vulnerability status

```
$ pip-audit -r requirements.txt --progress-spinner off
No known vulnerabilities found
```

**Zero known vulnerabilities across all 19 runtime dependencies.**

`npm audit` is not applicable: there is no npm manifest.

---

## 3. Findings

| ID | Finding | Severity | Status |
|---|---|---|---|
| DEP-01 | **No lockfile.** Every constraint is a `>=` floor, so two installs of the same commit can resolve to different versions. For a security product that means the audited dependency set is not the deployed one. | High | **Open** |
| DEP-02 | **The audit tooling is not declared.** Bandit, pip-audit, semgrep and gitleaks are used in this audit but live in neither manifest, so a scan cannot be reproduced from the repository. | Medium | **Open** |
| DEP-03 | **`setuptools` is a runtime dependency.** It is a build tool; it belongs in `requirements-dev.txt`. | Low | **Open** |
| DEP-04 | **`requests` is declared but barely used.** The codebase uses `httpx` throughout. | Low | **Open** |
| DEP-05 | **`scapy` is GPL-2.0.** It is used for packet capture in `core/network/packet_engine.py`. GPL-2.0 is a strong copyleft licence: distributing a container image that links scapy carries obligations that the MIT-licensed project does not currently acknowledge. | Medium | **Open** — needs a licence review before public distribution |
| DEP-06 | **The transitive surface is unpinned.** 46 packages are resolved from the 19 declared ones (Starlette, Uvicorn's server stack, `anyio`, `h11`, `httpcore`, `certifi`, `idna`, `charset-normalizer`, `reportlab`'s tree, `playwright`'s tree). | Medium | **Open** |
| DEP-07 | **`playwright` is declared but its browser is never installed.** No workflow runs `playwright install`, so the browser E2E path cannot run in CI — which is why `tests/e2e_map_browser_test.py` is excluded from the pipeline. | Medium | **Open** |
| DEP-08 | **`scapy` needs a native capture driver.** The CI workflow installs `libpcap-dev` on Linux only; the Windows and macOS runners have no equivalent step, so the network tests depend on the runner image. | Medium | **Open** |
| DEP-09 | **The audit tools are not run in CI.** The `ci.yml` workflow runs flake8 and pytest; it runs no SCA, no SAST and no secret scan. | High | **Open** |
| DEP-10 | **No `pip-audit` result is recorded anywhere.** The dependency audit is not reproducible without this report. | Medium | **Open** |

---

## 4. Licence compatibility

| Component | Licence | Compatibility with MIT |
|---|---|---|
| Everything except scapy | MIT / BSD / ISC / Apache-2.0 | Compatible |
| **scapy** | **GPL-2.0** | **Copyleft.** Linking GPL-2.0 code into an MIT project makes the combined work subject to GPL-2.0 on distribution. |

`scapy` is imported by `core/network/packet_engine.py` for live capture and
by `core/network/pcap_forensics.py` for offline PCAP/PCAPNG analysis. The
offline analysis could be done with a permissively licensed parser instead.

**This is not a defect in the code — it is a distribution decision.** It
matters if the container image or the wheel is redistributed. The
recommendation is to obtain a licence review before publishing an image,
and to consider isolating the scapy dependency behind a subprocess
boundary (which the platform already does for the external binaries) so that
the licence obligations do not propagate.

---

## 5. Recommendation

The dependency posture is **good on vulnerabilities and weak on
reproducibility**. The fix is small:

```bash
# a lockfile
pip install pip-tools
pip-compile requirements.txt -o requirements.lock
pip-compile requirements-dev.txt -o requirements-dev.lock
```

and a CI step:

```yaml
- name: Software Composition Analysis
  run: |
    pip install pip-audit bandit
    pip-audit -r requirements.txt
    bandit -r core agents plugins web reports tools -f json -o bandit.json
```

`pip-audit` exits non-zero on a finding, so the pipeline blocks on a
newly disclosed vulnerability — which is the point of running it.

---

## 6. Summary

| Metric | Value |
|---|---|
| Direct runtime dependencies | 19 |
| Development dependencies | 2 |
| Transitive dependencies resolved | 46 |
| JavaScript dependencies | 0 |
| Known vulnerabilities | **0** |
| Licence conflicts | 1 (scapy, GPL-2.0) |
| Lockfile | **None** |
| Dependency scanning in CI | **None** |

**Verdict.** The dependency set is small, modern, permissively licensed and
free of known vulnerabilities. The gap is process, not content: there is no
lockfile, no SCA in CI and no recorded audit result. All three are cheap to
add and should be.
