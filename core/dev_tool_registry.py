"""
SWA AI — Centralized Development & Security Tool Registry.

Every tool the platform depends on is declared once here, with a *measured*
status. Nothing is marked OPERATIONAL unless its version probe actually ran
successfully on this host.

The six statuses are the ones the platform reports:

    NOT_AVAILABLE   the tool is not present
    INSTALLED       present, but no version probe / configuration check ran
    CONFIGURED      its configuration is present and syntactically valid
    OPERATIONAL     a real probe executed successfully (version captured)
    FAILED          a probe was attempted and failed, with the reason recorded
    DISABLED        deliberately disabled by configuration

Design rules
------------
* Detection is read-only. The registry never installs anything.
* Every probe has a timeout, so a hung binary cannot block a request.
* Secrets are never included in the report -- only whether a required
  environment variable is set.
* A tool present in a non-PATH location can be declared with ``extra_paths``.
* Python packages are detected through ``importlib.metadata``; executables
  through ``shutil.which``.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import os
import shutil
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ToolStatus(str, Enum):
    NOT_AVAILABLE = "Not Available"
    INSTALLED = "Installed"
    CONFIGURED = "Configured"
    OPERATIONAL = "Operational"
    FAILED = "Failed"
    DISABLED = "Disabled"


@dataclass(frozen=True)
class ToolSpec:
    """A tool the platform may use."""

    id: str
    name: str
    category: str
    kind: str = "executable"           # executable | python_package | service | runtime
    executable: str | None = None
    package: str | None = None
    version_args: Sequence[str] = ("--version",)
    extra_paths: Sequence[str] = ()
    required_env: Sequence[str] = ()   # names only -- values are never reported
    install_hint: str = ""
    enabled_by_default: bool = True


@dataclass
class ToolStatusRecord:
    """A measured status for a tool."""

    id: str
    name: str
    category: str
    status: ToolStatus
    version: str | None = None
    path: str | None = None
    reason: str = ""
    missing_env: list[str] = field(default_factory=list)
    checked_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "status": self.status.value,
            "version": self.version,
            "path": self.path,
            "reason": self.reason,
            "missing_env": self.missing_env,
            "checked_at": self.checked_at,
        }


# ---------------------------------------------------------------------------
# The registry. Add a tool here, not in a dashboard label.
# ---------------------------------------------------------------------------
SPECS: list[ToolSpec] = [
    # --- runtime -----------------------------------------------------------
    ToolSpec("python", "Python runtime", "runtime", kind="runtime",
             executable="python", version_args=("--version",),
             install_hint="Install CPython 3.10-3.12"),
    ToolSpec("node", "Node.js", "runtime", executable="node",
             install_hint="Install Node.js 20+"),
    ToolSpec("npm", "npm", "runtime", executable="npm"),

    # --- python development ------------------------------------------------
    ToolSpec("pytest", "Pytest", "development", kind="python_package", package="pytest"),
    ToolSpec("coverage", "pytest-cov", "development", kind="python_package", package="pytest_cov"),
    ToolSpec("ruff", "Ruff", "development", executable="ruff", package="ruff"),
    ToolSpec("black", "Black", "development", executable="black", package="black"),
    ToolSpec("mypy", "Mypy", "development", executable="mypy", package="mypy"),
    ToolSpec("bandit", "Bandit", "security", executable="bandit", package="bandit"),
    ToolSpec("pip-audit", "pip-audit", "security", executable="pip-audit", package="pip_audit"),

    # --- security ----------------------------------------------------------
    ToolSpec("sonarqube", "SonarQube scanner", "security", executable="sonar-scanner",
             extra_paths=(os.path.join(os.environ.get("TEMP", ""), "opencode", "tools",
                                       "sonar-scanner-7.0.2.4839-windows-x64", "bin", "sonar-scanner.bat"),),
             required_env=("SONAR_HOST_URL",),
             install_hint="Download sonar-scanner-cli and set SONAR_HOST_URL"),
    ToolSpec("gitleaks", "Gitleaks", "security", executable="gitleaks",
             extra_paths=(os.path.join(os.environ.get("TEMP", ""), "opencode", "tools",
                                       "gitleaks", "gitleaks.exe"),),
             install_hint="Download gitleaks from github.com/gitleaks/gitleaks"),
    ToolSpec("trivy", "Trivy", "security", executable="trivy",
             extra_paths=(os.path.join(os.environ.get("TEMP", ""), "opencode", "tools",
                                       "trivy", "trivy.exe"),),
             install_hint="Download trivy from github.com/aquasecurity/trivy"),
    # Semgrep pins OpenTelemetry ~=1.37, which conflicts with FastAPI's
    # >=1.44. It is therefore installed in its own venv; declare that path
    # so detection reports what is actually runnable.
    ToolSpec("semgrep", "Semgrep", "security", executable="semgrep", package="semgrep",
             extra_paths=(os.path.join(os.environ.get("TEMP", ""), "opencode",
                                       "semgrep-venv", "Scripts", "semgrep.exe"),),
             install_hint="Semgrep is isolated in its own venv (OTel conflict with FastAPI)"),
    ToolSpec("zap", "OWASP ZAP", "security", executable="zaproxy",
             install_hint="Install OWASP ZAP"),
    ToolSpec("nmap", "Nmap", "security", executable="nmap"),
    ToolSpec("sqlmap", "SQLmap", "security", executable="sqlmap"),
    ToolSpec("tshark", "TShark", "network", executable="tshark"),

    # --- AI / orchestration ------------------------------------------------
    ToolSpec("crewai", "CrewAI", "ai", kind="python_package", package="crewai"),
    ToolSpec("langchain", "LangChain", "ai", kind="python_package", package="langchain"),
    ToolSpec("langsmith", "LangSmith", "ai", kind="python_package", package="langsmith",
             required_env=("LANGCHAIN_API_KEY",)),
    ToolSpec("giskard", "Giskard", "ai", kind="python_package", package="giskard"),

    # --- database ----------------------------------------------------------
    ToolSpec("mysql", "MySQL server", "database", executable="mysqld",
             install_hint="Install MySQL 8 / MariaDB 10+"),
    ToolSpec("sqlalchemy", "SQLAlchemy", "database", kind="python_package", package="sqlalchemy"),
    ToolSpec("alembic", "Alembic", "database", executable="alembic", package="alembic"),
    ToolSpec("pymysql", "PyMySQL", "database", kind="python_package", package="pymysql"),

    # --- observability -----------------------------------------------------
    ToolSpec("prometheus-client", "Prometheus client", "observability",
             kind="python_package", package="prometheus_client"),
    ToolSpec("otel", "OpenTelemetry SDK", "observability",
             kind="python_package", package="opentelemetry.sdk"),
]


class ToolRegistry:
    """Detects and reports the status of every declared tool."""

    # A full snapshot executes one subprocess per executable tool (up to ~8s
    # on Windows). Cache the measured result briefly so repeated dashboard and
    # health requests do not re-probe every binary.
    _SNAPSHOT_TTL_SEC = 60.0

    def __init__(self, specs: Sequence[ToolSpec] | None = None):
        self.specs = list(specs if specs is not None else SPECS)
        self._last: list[ToolStatusRecord] = []
        self._snapshot_cache: list[dict[str, Any]] | None = None
        self._snapshot_ts = 0.0

    def invalidate_cache(self) -> None:
        """Discard the cached snapshot so the next call re-probes every tool."""
        self._snapshot_cache = None
        self._snapshot_ts = 0.0

    # -- detection ----------------------------------------------------------
    @staticmethod
    def _find_executable(spec: ToolSpec) -> str | None:
        found = shutil.which(spec.executable or "") if spec.executable else None
        if found:
            return found
        for candidate in spec.extra_paths:
            if candidate and os.path.isfile(candidate):
                return candidate
        return None

    @staticmethod
    def _probe_version(spec: ToolSpec, path: str) -> str | None:
        """Runs the version command; returns None when it fails or is empty."""
        args = [path] + list(spec.version_args)
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0:
            return None
        output = (result.stdout or result.stderr or "").strip().splitlines()
        return output[0].strip()[:160] if output else None

    def check(self, spec: ToolSpec) -> ToolStatusRecord:
        import datetime

        record = ToolStatusRecord(
            id=spec.id,
            name=spec.name,
            category=spec.category,
            status=ToolStatus.NOT_AVAILABLE,
            checked_at=datetime.datetime.now(datetime.UTC).isoformat(),
        )

        env_name = f"SWA_TOOL_{spec.id.upper().replace('-', '_')}_DISABLED"
        if os.environ.get(env_name, "").lower() in ("1", "true", "yes", "on"):
            record.status = ToolStatus.DISABLED
            record.reason = f"Disabled by {env_name}."
            return record

        record.missing_env = [name for name in spec.required_env if not os.environ.get(name)]

        if spec.kind == "python_package":
            try:
                version = importlib.metadata.version(spec.package or spec.id)
            except importlib.metadata.PackageNotFoundError:
                record.reason = f"Python package '{spec.package or spec.id}' not installed."
                return record
            record.version = version
            record.path = spec.package
            record.status = ToolStatus.INSTALLED
            # A package that imports is configured; a version alone is enough
            # evidence to call it configured, but not operational.
            try:
                importlib.import_module((spec.package or spec.id).replace("-", "_"))
                record.status = ToolStatus.CONFIGURED
            except Exception as exc:  # noqa: BLE001 - any import error means not configured
                record.reason = f"Package installed but import failed: {type(exc).__name__}."
                record.status = ToolStatus.FAILED
            return record

        if spec.kind in ("executable", "runtime", "service"):
            path = self._find_executable(spec)
            if not path:
                record.reason = f"Executable '{spec.executable}' not found on PATH."
                if spec.install_hint:
                    record.reason += f" {spec.install_hint}"
                return record
            record.path = path
            version = self._probe_version(spec, path)
            if version:
                record.version = version
                record.status = ToolStatus.OPERATIONAL
                if record.missing_env:
                    record.status = ToolStatus.CONFIGURED
                    record.reason = "Operational but required configuration is missing."
            else:
                record.status = ToolStatus.FAILED
                record.reason = "Version probe failed or timed out."
            return record

        record.reason = f"Unknown tool kind: {spec.kind}."
        return record

    def snapshot(self, force_refresh: bool = False) -> list[dict[str, Any]]:
        """Return a serializable status list for every declared tool.

        Probes are cached for ``_SNAPSHOT_TTL_SEC``; pass ``force_refresh=True``
        to measure again (used by the explicit "re-check" UI action).
        """
        if (
            not force_refresh
            and self._snapshot_cache is not None
            and (time.time() - self._snapshot_ts) < self._SNAPSHOT_TTL_SEC
        ):
            return [dict(item) for item in self._snapshot_cache]
        self._last = [self.check(spec) for spec in self.specs]
        self._snapshot_cache = [record.to_dict() for record in self._last]
        self._snapshot_ts = time.time()
        return [dict(item) for item in self._snapshot_cache]

    def get(self, tool_id: str) -> ToolStatusRecord | None:
        for record in self._last:
            if record.id == tool_id:
                return record
        return None


registry = ToolRegistry()


def snapshot(force_refresh: bool = False) -> list[dict[str, Any]]:
    """Module-level convenience for the API layer."""
    return registry.snapshot(force_refresh=force_refresh)
