# SNMK — CI/CD and DevSecOps Audit Report

| | |
|---|---|
| **Revision** | `39f441b` |
| **Pipelines** | 6 GitHub Actions workflows |
| **Method** | Workflow-by-workflow review; the SonarQube and CodeQL workflows were inspected against their own documentation |

---

## 1. Inventory

| Workflow | Trigger | Purpose |
|---|---|---|
| `ci.yml` | push, PR to `main` / `generation-2-complete-modernization` | The gate: lint + test on Windows, Linux and macOS |
| `codeql.yml` | push, PR, weekly | GitHub CodeQL SAST for Python and JavaScript |
| `sonarqube.yml` | push, PR, weekly | Tests with coverage → SonarQube scan → quality gate |
| `docker-build.yml` | push / PR | Build the image and check its health |
| `release.yml` | tag | Build the wheel, the sdist and the image, then publish |
| `autonomous-audit.yml` | schedule / manual | Run the platform's own audit and upload the SARIF |

---

## 2. The test pipeline — `ci.yml`

### What it does

| Step | Detail |
|---|---|
| Matrix | `ubuntu-latest`, `windows-latest`, `macos-latest` on Python 3.12; plus 3.10 and 3.11 on Linux |
| System deps | `libpcap-dev` on Linux only |
| Install | `requirements.txt` |
| Lint | `flake8 --select=E9,F63,F7,F82` (the fatal errors), then a non-blocking full run with `--exit-zero` |
| Test | `pytest tests/ --ignore=tests/e2e_map_browser_test.py` |
| Artifacts | The pytest report is uploaded, and the failures are turned into workflow annotations |
| Smoke | The core modules are imported, and the CLI's `--help`, `--hash` and `--cidr` subcommands are run |

### Findings

| ID | Finding | Severity | Status |
|---|---|---|---|
| CICD-01 | **The E2E browser suite is excluded from the pipeline.** `tests/e2e_map_browser_test.py` is ignored, and `playwright install` is never run, so the browser path is never exercised in CI. | Medium | **Open** |
| CICD-02 | **`libpcap-dev` is installed on Linux only.** The Windows and macOS runners have no equivalent step, so the network tests depend on what the runner image happens to carry. | Medium | **Open** |
| CICD-03 | **The full flake8 run is `--exit-zero`.** The fatal-error selection gates the build; everything else is advisory. 2 345 lines exceed 120 characters and there is no formatter. | Low | **Open** — deliberate, but it means style is not enforced |
| CICD-04 | **No dependency scanning.** No `pip-audit`, no `safety`, no OSV. A newly disclosed vulnerability in a transitive dependency does not fail the build. | High | **Open** |
| CICD-05 | **No secret scanning.** gitleaks is not run in CI. | High | **Open** |
| CICD-06 | **No SAST beyond CodeQL and SonarQube.** Semgrep and Bandit are not run. | Medium | **Open** |
| CICD-07 | **No container scan.** `docker-build.yml` builds and health-checks the image but never scans it with Trivy or Grype. | Medium | **Open** |
| CICD-08 | **No coverage gate.** The test step produces no coverage report and no threshold is enforced. | Medium | **Open** — the SonarQube workflow does the coverage, but it does not fail the build on a coverage drop on its own |
| CICD-09 | **The pipeline runs on `push` as well as `pull_request`**, so a branch push runs the whole matrix twice. | Low | **Open** — a cost and a latency trade-off |
| CICD-10 | **The workflow permissions are not declared** on `ci.yml`, `docker-build.yml` or `sonarqube.yml`. The default `GITHUB_TOKEN` permission applies. | Medium | **Open** |
| CICD-11 | **There is no `concurrency` group** on `ci.yml`, so a rapid series of pushes runs overlapping matrices. | Low | **Open** |

### Permissions

Only `codeql.yml` and `release.yml` declare `permissions:` explicitly.
`sonarqube.yml` declares `actions: read`, `contents: read`,
`pull-requests: read` and `checks: write` — the minimum it needs to
annotate a pull request.

**CICD-10 is the finding:** the three workflows that do not declare
permissions inherit whatever the repository default is, which may be
write-all.

---

## 3. The SonarQube workflow — `sonarqube.yml`

### What it does

1. Checkout with `fetch-depth: 0` — full history, so the new-code period can
   be computed from the blame.
2. Python 3.12, the dependencies, `libpcap-dev`.
3. The tests with `--cov` over `core`, `agents`, `plugins`, `reports` and
   `web`, producing `coverage.xml` and `htmlcov/`.
4. The scanner, with `continue-on-error: true` so a red test run still
   produces a report.
5. A separate step that fails the job when the scanner reports a gate
   failure.

### Findings

| ID | Finding | Severity | Status |
|---|---|---|---|
| CICD-12 | **The workflow needs two secrets that are not configured by default**: `SONAR_TOKEN` and `SONAR_HOST_URL`. Without them the scan step skips itself and the workflow passes without analysing anything. | Medium | **Open** — the skip is deliberate (a fork should not fail for want of secrets), but it must be documented so a green badge is not mistaken for a clean scan |
| CICD-13 | **The quality gate is not a hard block on the test job.** The gate failure fails the *SonarQube* job, not the overall pipeline. A branch protection rule is needed for the gate to prevent a merge. | Medium | **Open** |

---

## 4. The CodeQL workflow — `codeql.yml`

```yaml
permissions:
  actions: read
  contents: read
  security-events: write
matrix:
  language: ['python', 'javascript-typescript']
steps:
  - uses: github/codeql-action/init@v3
    with:
      languages: ${{ matrix.language }}
      queries: +security-and-quality
  - uses: github/codeql-action/analyze@v3
```

**Correct.** Least privilege, both languages covered, the
`security-and-quality` suite enabled, results uploaded to code scanning.

**Not verified by this audit:** CodeQL requires GitHub Advanced Security,
which is not enabled on this fork, so the workflow could not be executed
locally. It is recorded as **configured correctly but not verified to run**.

---

## 5. The container workflow — `docker-build.yml`

Builds the image with buildx and runs a health check against it.

**Finding CICD-14 (Medium, open):** the image is built and health-checked but
**never scanned**. Trivy or Grype should run against the built image before
it is published. The `release.yml` workflow *does* publish the image — so an
unscanned image reaches a registry.

---

## 6. The release workflow — `release.yml`

Builds a wheel and an sdist, creates a GitHub release, and builds and pushes
the container image to the GitHub Container Registry.

**Finding CICD-15 (Medium, open):** the release is driven by a tag and
publishes an image that has never been scanned. There is no provenance
attestation, no signature and no SBOM.

**Finding CICD-16 (Low, open):** `permissions:` is declared for the release
job, but the image-push job's permissions should be verified separately.

---

## 7. The autonomous audit workflow — `autonomous-audit.yml`

Runs the platform's own subdomain and attack-surface discovery, then its
security audit and PoC verification, then uploads the SARIF to code scanning.

**This is the platform auditing itself.** It is an unusual and valuable
arrangement: the tool is exercised against a real target in CI, so the
tooling is continuously validated rather than only being unit-tested.

**Finding CICD-17 (Medium, open):** the workflow makes outbound requests
to targets named in a configuration file. It must be confirmed that those
targets are owned by the project and that the workflow cannot be pointed at
a third party by a pull request. A workflow that runs attacker-supplied
scan configuration from a fork is a request-forgery primitive.

---

## 8. Deployment approval and rollback

| Concern | State |
|---|---|
| Deployment approval | The `release.yml` workflow publishes on a tag. **There is no environment with a required reviewer.** |
| Rollback | **None.** A published container image can be re-pushed, but there is no documented rollback procedure. |
| Artifact integrity | The wheel and the image are built from the tagged commit. **No provenance, no signature, no SBOM.** |
| Branch protection | Not verifiable from the repository. |

**Finding CICD-18 (High, open):** a tag push publishes an unscanned image
and an unsigned release to a public registry, with no environment gate and
no rollback procedure.

---

## 9. Recommendations

| # | Action | Effort | Closes |
|---|---|---|---|
| 1 | Add `pip-audit` and `gitleaks` to the CI workflow | Low | CICD-04, CICD-05 |
| 2 | Add Trivy to the container workflow, before the image is published | Low | CICD-07, CICD-14 |
| 3 | Declare explicit `permissions:` on every workflow | Low | CICD-10 |
| 4 | Add `concurrency` groups to the test workflows | Low | CICD-11 |
| 5 | Install the Playwright browser and run the E2E suite | Medium | CICD-01 |
| 6 | Add a coverage threshold to the test step | Low | CICD-08 |
| 7 | Add a GitHub environment with a required reviewer to the release job | Low | CICD-18 |
| 8 | Generate an SBOM and sign the release artefacts | Medium | CICD-15 |
| 9 | Confirm that the autonomous audit workflow cannot be pointed at a third party from a fork | Low | CICD-17 |
| 10 | Add a `libpcap` equivalent step for the Windows and macOS runners, or skip the network tests there explicitly | Low | CICD-02 |
| 11 | Configure the branch protection rule so the SonarQube gate blocks a merge | Low | CICD-13 |
| 12 | Document a rollback procedure for a published release | Low | CICD-18 |
