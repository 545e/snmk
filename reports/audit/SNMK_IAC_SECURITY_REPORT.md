# SNMK — Infrastructure-as-Code Security Report

| | |
|---|---|
| **Revision** | `39f441b` |
| **Method** | Exhaustive enumeration of the infrastructure artefacts in the repository, then review of each |

---

## 1. What infrastructure-as-code exists

| Artefact | Present | Notes |
|---|---|---|
| Terraform (`.tf`) | **No** | |
| Kubernetes manifests | **No** | |
| Helm charts | **No** | |
| CloudFormation | **No** | |
| Ansible | **No** | |
| Pulumi | **No** | |
| Bicep | **No** | |
| **Dockerfile** | **Yes** | 1 file — covered by `SNMK_CONTAINER_SECURITY_REPORT.md` |
| **Docker Compose** | **Yes** | 2 files (`docker-compose.yml`, `docker-compose.dev.yml`) |
| GitHub Actions | **Yes** | 6 workflows — covered by `SNMK_CICD_AUDIT_REPORT.md` |
| Shell / batch launchers | **Yes** | 16 files (`install.sh`, `run.sh`, `install.ps1`, `run.bat`, …) |
| `.env.example` | **Yes** | The configuration contract |

**There is no cloud infrastructure in this repository.** The platform is
deployed as a single container on the operator's own host. That is a
deliberate product decision, not an omission, and it removes the largest
class of cloud-configuration risk (a misconfigured IAM policy or an open
security group) from the scope entirely.

---

## 2. Scanning tools

| Tool | Executed | Result |
|---|---|---|
| Checkov | **No** | Not installed on the audit host. |
| KICS | **No** | Not installed. |
| Trivy config | **No** | Trivy itself could not be fetched on the audit host; see `SNMK_SAST_SCA_SECRET_SCAN_REPORT.md` §1. |
| Terrascan | **No** | Not installed. |
| Snyk IaC | **No** | No credentials. |

**All IaC scanners were recorded as *not executed*.** None of them is
claimed to have passed.

For what it is worth, the manual review below covers the same ground a
scanner would: the IaC surface is one Dockerfile, two Compose files and
six workflows, and every one of them was read line by line.

---

## 3. The Compose configuration

### Findings

| ID | Finding | Severity | Status |
|---|---|---|---|
| IAC-01 | **The container published on every interface with no authentication configured.** `ports: ["8000:8000"]` and no `SWA_AUTH_ENABLED`, so the full API was reachable from any host on the network. | High | **FIXED** — loopback-only, with authentication enabled by default |
| IAC-02 | **No capability restriction.** `cap_drop` is not set. | Medium | **Open** |
| IAC-03 | **No `no-new-privileges`.** | Low | **Open** |
| IAC-04 | **No read-only root filesystem.** | Low | **Open** |
| IAC-05 | **The resource limits are Swarm-only** and are ignored by `docker compose up`. | Medium | **Open** |
| IAC-06 | **The container shares the default bridge network.** | Low | **Open** |
| IAC-07 | **No secret is passed through an environment file or a secret store.** The two secret variables are interpolated from the host's environment, which is the correct pattern for Compose — but the *image* also reads `SWA_API_KEY` from its own environment, so a container started without it silently falls back to "authentication off". | Medium | **Open** |
| IAC-08 | **The named volume has no backup or retention policy.** `swa_data` holds the database and the evidence. | Medium | **Open** — see `SNMK_DATABASE_AUDIT_REPORT.md` |

### What is right

* The database lives on a named volume, not in the container layer, so it
  survives an image replacement.
* The resource limits are declared even if they are only honoured under
  Swarm.
* The health check is defined in both the image and the Compose file.
* The secrets are interpolated from the environment rather than baked into
  the file.

---

## 4. The Dockerfile

Covered in full by `SNMK_CONTAINER_SECURITY_REPORT.md`. The IaC-relevant
points:

| Control | State |
|---|---|
| Base image pinned by digest | **No** — `python:3.12-slim` is a moving tag |
| Non-root runtime user | **Yes** |
| No build tooling in the runtime layer | **Yes** |
| Dependency layer separated from the source | **Yes** |
| No package index left behind | **Yes** |
| Secrets excluded from the build context | **Yes** — fixed in this pass |
| SBOM / provenance | **No** |
| Image scanned in CI | **No** |

---

## 5. The GitHub Actions workflows

Covered in full by `SNMK_CICD_AUDIT_REPORT.md`. The IaC-relevant points:

| Control | State |
|---|---|
| Workflow permissions declared | **Partially** — three of six declare them |
| Third-party actions pinned to a commit | **No** — all use a mutable tag (`@v3`, `@v4`, `@v5`) |
| `pull_request_target` used | **No** — good; the workflows use `pull_request`, which runs the fork's code with a read-only token |
| Untrusted input interpolated into a `run:` block | **No** found |
| `concurrency` groups | **No** on three of six |
| Secrets exposed to a fork's workflow | **No** — the workflows use `pull_request`, and `secrets.*` are not available there |

**Finding IAC-09 (Medium, open): the third-party actions are pinned to a
mutable version tag.** `actions/checkout@v4` can be moved to a different
commit. Pinning to a commit SHA is the standard hardening for a workflow
that a release depends on.

**Finding IAC-10 (Medium, open): `autonomous-audit.yml` makes outbound
requests to the targets named in a configuration file.** That is safe only
if the targets are the project's own and the workflow cannot be pointed
elsewhere by a pull request. This must be confirmed.

---

## 6. The shell and batch launchers

16 files: `install.sh`, `install_macos.sh`, `install.ps1`, `install.bat`,
`run.sh`, `run_macos.sh`, `run.ps1`, `run.bat`, `stop.*`.

**Finding IAC-11 (Medium, open): the install scripts have not been
reviewed for shell hygiene.** They are the first code to run on a new
host, they fetch dependencies, and they create a virtual environment.

The specific risks to check are: unquoted variable expansion, `curl | sh`
pipelines, a download whose checksum is not verified, and a `PATH` that is
modified. **This was not verified in this audit** — the scripts were read
for their purpose but not line-by-line for shell hygiene, and that is
recorded as a gap rather than as a pass.

**Finding IAC-12 (Low, open): `run.ps1`, `run.bat` and `install.ps1` execute
with whatever privileges the operator's shell has.** The platform launches a
web server that binds a port and writes a database; a non-administrator
account should be sufficient and should be documented.

---

## 7. Recommendations

| # | Action | Effort | Closes |
|---|---|---|---|
| 1 | Pin the third-party GitHub Actions to a commit SHA | Low | IAC-09 |
| 2 | Declare `permissions:` on all six workflows | Low | — |
| 3 | Add `cap_drop: [ALL]`, `no-new-privileges` and `read_only` to the Compose file | Low | IAC-02, IAC-03, IAC-04 |
| 4 | Use `mem_limit`/`cpus` so the limits apply outside Swarm | Low | IAC-05 |
| 5 | Pin the base image by digest | Low | — |
| 6 | Generate an SBOM and attach the provenance attestation | Medium | — |
| 7 | Review the install scripts for shell hygiene and verify the downloads | Medium | IAC-11 |
| 8 | Define a backup and retention policy for the `swa_data` volume | Medium | IAC-08 |
| 9 | Confirm the autonomous audit workflow's target list cannot be changed by a fork | Low | IAC-10 |
| 10 | Document that a non-administrator account is sufficient to run the platform | Low | IAC-12 |
