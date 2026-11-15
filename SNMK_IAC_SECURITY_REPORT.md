# SNMK Infrastructure-as-Code (IaC) Security Audit Report

**Audit Area:** Infrastructure as Code, Docker Compose, Container Orchestration & CI/CD Configs  
**Target Repository:** `https://github.com/545e/snmk.git`  
**IaC Artifacts:** `Dockerfile`, `docker-compose.yml`, `docker-compose.monitoring.yml`, `.github/workflows/`  
**Status:** **SECURE CONFIGURATION**

---

## 1. Executive Summary

This report evaluates the Infrastructure-as-Code (IaC) configurations of SNMK against CIS Benchmarks, NIST SP 800-190 (Application Container Security Guide), and container security best practices.

---

## 2. Docker Compose IaC Audit

### 2.1 Core Application Compose (`docker-compose.yml`)
- **Port Exposure:** Exposes only application port `8000:8000`. No database ports or administrative debug sockets are exposed to the host network.
- **Persistent Volumes:** Uses Docker named volume `swa_data` mapped to `/data` to isolate persistent SQLite storage from container destruction.
- **Resource Limits:**
  - CPU Limits: `cpus: '2.0'`
  - Memory Limits: `memory: 3072M`
  - Reservations: `cpus: '0.5'`, `memory: 512M`
- **Health Checks:** Native health check polling `http://127.0.0.1:8000/health` every 30 seconds with 3 retries.

### 2.2 Monitoring Stack Compose (`docker-compose.monitoring.yml`)
- **Network Isolation:** Defined custom bridge network `snmk-monitoring-net`. Monitoring services (Prometheus, Loki, Tempo, Node Exporter, cAdvisor) communicate over an internal network without exposing internal database interfaces.
- **Security Constraints:** Grafana runs with anonymous authentication disabled and enforced admin credentials passed via environment variables.

---

## 3. GitHub Actions Workflows IaC Audit

- **Permissions:** GitHub Actions workflows in `.github/workflows/` declare minimal explicit permissions.
- **Secret Handling:** Secrets (`DOCKER_PASSWORD`, `GITHUB_TOKEN`) use GitHub repository secret references; zero plaintext tokens are committed.
- **Multi-OS Matrix:** Builds and tests cross-platform compatibility on Ubuntu, Windows, and macOS without granting unconstrained sudo privileges.
