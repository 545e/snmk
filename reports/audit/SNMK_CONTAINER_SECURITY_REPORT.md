# SNMK — Container Security Report

| | |
|---|---|
| **Revision** | `39f441b` |
| **Artefacts** | `Dockerfile`, `docker-compose.yml`, `docker-compose.dev.yml`, `.dockerignore` |
| **Method** | Static review of every instruction; no image was built or run on the audit host (no Docker daemon available) |

> **Not verified by execution.** Docker was not installed on the audit host,
> so the image was not built, not run and not scanned. Everything below is
> derived from the build files. It is recorded as such.

---

## 1. The image

```dockerfile
FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl git dnsutils && rm -rf /var/lib/apt/lists/*
RUN groupadd -r swa && useradd -r -g swa -d /app -s /sbin/nologin -c "SWA System User" swa
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /data && chown -R swa:swa /app /data
ENV SWA_DB_PATH=/data/swa_data.db
ENV SWA_HOST=0.0.0.0
ENV SWA_PORT=8000
ENV DOCKER_CONTAINER=1
USER swa
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=8s --retries=3 \
  CMD curl -f http://127.0.0.1:8000/health || exit 1
CMD ["python", "run.py"]
```

---

## 2. What is right

| Control | State |
|---|---|
| **Non-root execution** | ✔ A dedicated `swa` system user is created and the container runs as it. `USER swa` is set before the entrypoint. |
| **Minimal base image** | ✔ `python:3.12-slim`, not the full image. |
| **`--no-install-recommends`** | ✔ The apt layer does not pull recommended packages. |
| **No package manager in the runtime layer** | ✔ `apt-get update` and the index removal are in the same layer as the install. |
| **No build tools retained** | ✔ Only `curl`, `git` and `dnsutils` are installed; no compiler. |
| **Dependency layer separated** | ✔ `requirements.txt` is copied and installed **before** `COPY . .`, so a source change does not invalidate the dependency layer. |
| **No `pip` cache in the image** | ✔ `--no-cache-dir` on both pip invocations. |
| **Persistent storage is a volume** | ✔ `/data` is a named volume, and the database path points at it. |
| **Health check** | ✔ Present, with an interval, a timeout, a start period and retries. |
| **Restart policy** | ✔ `unless-stopped` in Compose. |
| **Resource limits** | ✔ 2 CPUs and 3 GiB of memory, with reservations of 0.5 CPU and 512 MiB. |
| **Explicit `EXPOSE`** | ✔ Only 8000. |

---

## 3. Findings

| ID | Finding | Severity | Status |
|---|---|---|---|
| CONT-01 | **`.env` was not in `.dockerignore`.** The build context is the *working directory*, not the git tree, so a local `.env` — with the operator's real API keys — would have been copied into the image by `COPY . .` and would be present in the image layer. | High | **FIXED** — `.env`, `.env.*`, `.swa_master.key`, `*.pem`, `*.key` and `secrets/` are now excluded. |
| CONT-02 | **`COPY . .` copies the whole working tree**, including `reports/` (209 files), `docs/` (118 files) and the audit artefacts. The image is far larger than it needs to be, and the documentation is shipped to production. | Medium | **Open** — narrow the copy to the directories the runtime needs. |
| CONT-03 | **The image is not scanned.** Trivy, Grype and Docker Scout are not run against it in CI, and the release workflow publishes it. | Medium | **Open** |
| CONT-04 | **No SBOM, no provenance, no signature.** | Medium | **Open** |
| CONT-05 | **The base image is not pinned by digest.** `python:3.12-slim` is a moving tag; two builds a week apart can differ by hundreds of megabytes of security patches. | Medium | **Open** |
| CONT-06 | **The `swa` user is created without an explicit `--uid`.** The UID is whatever the build assigns, which is deterministic for a given base image but is not stated. A fixed UID makes the ownership of a mounted volume predictable. | Low | **Open** |
| CONT-07 | **`git` is installed in the runtime layer.** It is needed by the tool-dependency manager to fetch release assets, but it also brings a large surface. | Low | **Open** — consider a minimal HTTP fetch instead |
| CONT-08 | **No `HEALTHCHECK` start-period tuning for a cold database.** The 8-second start period is short for a first-run schema creation. | Low | **Open** |
| CONT-09 | **The image has no `LABEL`, `org.opencontainers.*` metadata or a version stamp.** | Info | **Open** |
| CONT-10 | **No `.dockerignore` entry for the audit output**, so a locally generated report would be copied into the image. | Low | **Open** — `reports/audit/` should be excluded |

---

## 4. The Compose file

```yaml
services:
  swa-ai:
    build: .
    container_name: swa-ai-cyber-hub
    ports:
      - "127.0.0.1:8000:8000"          # was "8000:8000"
    environment:
      - PYTHONUNBUFFERED=1
      - SWA_HOST=0.0.0.0
      - SWA_PORT=8000
      - DOCKER_CONTAINER=1
      - SWA_DB_PATH=/data/swa_data.db
      - SWA_AUTH_ENABLED=true            # added
      - SWA_API_KEY=${SWA_API_KEY:-}
      - SWA_OPERATOR_PASSWORD=${SWA_OPERATOR_PASSWORD:-}
    volumes:
      - swa_data:/data
    restart: unless-stopped
    deploy:
      resources:
        limits:   { cpus: '2.0', memory: 3072M }
        reservations: { cpus: '0.5', memory: 512M }
    healthcheck:
      test: ["CMD", "curl", "-f", "http://127.0.0.1:8000/health"]
```

### What changed in this pass

| Before | After | Why |
|---|---|---|
| `ports: ["8000:8000"]` — published on every interface | `ports: ["127.0.0.1:8000:8000"]` | The API can launch scans, read findings and reach the platform's own integrations. It must not be on the network by default. |
| No `SWA_AUTH_ENABLED` | `SWA_AUTH_ENABLED=true` | The default is authentication off, and the container was inheriting that. |
| No `SWA_API_KEY` | `SWA_API_KEY=${SWA_API_KEY:-}` | Makes the requirement explicit; the operator supplies it. |

**The compose file now publishes on loopback and requires an operator to
deliberately widen it.** The comment in the file states exactly how, and
says that authentication must be enabled when it is widened.

### Findings

| ID | Finding | Severity | Status |
|---|---|---|---|
| CONT-11 | **The container runs with no capability restriction.** `cap_drop` is not set, so the container keeps the default capability set. | Medium | **Open** — `cap_drop: [ALL]` with `cap_add: [NET_BIND_SERVICE, NET_RAW, SYS_CHROOT]` would be tighter, though `NET_RAW` is needed for packet capture |
| CONT-12 | **No `read_only` root filesystem.** The container can write anywhere in its filesystem. | Low | **Open** |
| CONT-13 | **No `no-new-privileges`.** | Low | **Open** |
| CONT-14 | **No `security_opt` hardening.** `no-new-privileges:true` and the seccomp profile would be the baseline. | Low | **Open** |
| CONT-15 | **The container is not on a restricted network.** It shares the default bridge with everything else on the host. | Low | **Open** |
| CONT-16 | **`SWA_API_KEY=${SWA_API_KEY:-}` expands to an empty string** when the variable is unset, and the platform treats an empty key as "no key configured" — which in the default configuration means authentication is off. The compose file sets `SWA_AUTH_ENABLED=true`, so the gate still engages, but every request is then refused, which is a confusing failure rather than a clear one. | Medium | **Open** — the entrypoint should refuse to start when authentication is enabled and no key is set |
| CONT-17 | **`docker-compose.dev.yml` was not reviewed against the same standard.** | Low | **Open** |
| CONT-18 | **The `deploy.resources` limits are a Swarm feature.** In plain `docker compose up` they are ignored, so the container is effectively unlimited. | Medium | **Open** — `mem_limit` and `cpus` are the non-Swarm equivalents |

---

## 5. The `.dockerignore`

Now covers:

* version control and CI configuration;
* Python caches and the virtual environment;
* the local database and its WAL sidecars;
* **secrets** — `.env`, `.env.*` (except `.env.example`), `.swa_master.key`,
  `*.pem`, `*.key`, `secrets/`;
* logs, runtime outputs and the generated reports;
* IDE and OS metadata.

**The gap:** `reports/` is not excluded, so 209 files — including the audit
reports themselves — are copied into the image.

---

## 6. Recommendations

| # | Action | Effort | Closes |
|---|---|---|---|
| 1 | Narrow `COPY . .` to the runtime directories, or use a multi-stage build | Medium | CONT-02 |
| 2 | Exclude `reports/` and `docs/` from the build context | Low | CONT-02, CONT-10 |
| 3 | Pin the base image by digest | Low | CONT-05 |
| 4 | Add Trivy to the container workflow, before the publish | Low | CONT-03 |
| 5 | Generate an SBOM and attach the provenance attestation | Medium | CONT-04 |
| 6 | Set `cap_drop`, `no-new-privileges` and `read_only` | Low | CONT-11..CONT-14 |
| 7 | Use `mem_limit`/`cpus` so the limits apply outside Swarm | Low | CONT-18 |
| 8 | Make the entrypoint refuse to start when authentication is enabled and no key is configured | Low | CONT-16 |
| 9 | Give the `swa` user an explicit UID | Low | CONT-06 |
| 10 | Add the OCI image metadata labels | Low | CONT-09 |
