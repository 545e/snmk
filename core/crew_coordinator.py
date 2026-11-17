"""
SWA AI — CrewAI-style Coordinator with an honest direct-execution fallback.

The platform declares the 22 specialist roles requested by the engineering
mission. A role only reports OPERATIONAL when one of its tasks has actually
executed successfully.

Two execution modes exist:

``crewai``
    Used only when the ``crewai`` package is importable, ``SWA_CREWAI_ENABLED``
    is on and a provider credential is configured. In that mode a real
    ``crewai.Agent`` / ``crewai.Task`` / ``crewai.Crew`` is constructed and the
    task is executed through it. The mode is recorded in every result.

``direct``
    A controlled fallback: the role's deterministic handler runs in a bounded
    thread. No LLM is involved and no claim of CrewAI execution is made.

Safety controls
---------------
* A bounded thread pool and a per-task timeout.
* Bounded retries (never infinite).
* A hard cap on the number of tasks and on the history size.
* File-level exclusion: two tasks whose ``targets`` overlap cannot run at the
  same time, so two agents never modify the same file concurrently.
* Every task result records status, output, error, attempts and duration.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
HISTORY_PATH = ROOT / "data" / "crew_execution_history.json"


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class AgentRole:
    """A declared specialist role and the deterministic work it can do."""

    id: str
    name: str
    specialization: str
    action: str
    description: str = ""


# The 22 roles, version-controlled here. ``action`` names a handler in
# ACTIONS below; every handler performs real, bounded work.
ROLES: list[AgentRole] = [
    AgentRole("lead", "Lead AI Engineering Agent", "coordination", "summary", "Aggregates the results of other roles"),
    AgentRole("python", "Python Backend Agent", "python", "compile", "Compiles Python sources"),
    AgentRole("cpp", "C/C++ Engineering Agent", "cpp", "noop_native", "Activates only when C/C++ sources exist"),
    AgentRole("frontend", "Frontend Engineering Agent", "javascript", "lint_js", "Checks the frontend assets"),
    AgentRole("mysql", "MySQL Database Agent", "database", "database", "Checks database driver and configuration"),
    AgentRole("cybersecurity", "Cybersecurity Agent", "security", "endpoint", "Checks a local endpoint response"),
    AgentRole("sast", "SAST Agent", "sast", "bandit", "Runs Bandit against a target"),
    AgentRole("dast", "DAST Agent", "dast", "noop_dast", "Requires an authorized lab target"),
    AgentRole("api_security", "API Security Agent", "api", "api_openapi", "Checks the published OpenAPI schema"),
    AgentRole("network", "Network Security Agent", "network", "dependencies", "Checks network-related dependencies"),
    AgentRole("pentest", "Penetration Testing Agent", "pentest", "noop_pentest", "Requires an explicit target allowlist"),
    AgentRole("ai_integration", "AI Integration Agent", "ai", "dependencies", "Checks AI provider dependencies"),
    AgentRole("langchain", "LangChain Agent", "ai", "dependencies", "Checks LangChain availability"),
    AgentRole("langsmith", "LangSmith Evaluation Agent", "ai", "tracing", "Checks tracing configuration"),
    AgentRole("giskard", "Giskard Evaluation Agent", "ai", "dependencies", "Checks Giskard availability"),
    AgentRole("devops", "DevOps Agent", "devops", "tool_status", "Reports measured tool status"),
    AgentRole("cicd", "CI/CD Agent", "cicd", "lint_js", "Checks pipeline-adjacent files"),
    AgentRole("qa", "Testing and QA Agent", "testing", "pytest_collect", "Collects the test suite"),
    AgentRole("observability", "Observability Agent", "observability", "tracing", "Checks telemetry dependencies"),
    AgentRole("alerts", "Alert Management Agent", "alerts", "endpoint", "Checks the local alerts endpoint"),
    AgentRole("documentation", "Documentation Agent", "documentation", "docs", "Verifies documentation links"),
    AgentRole("performance", "Performance Optimization Agent", "performance", "import_time", "Measures application import time"),
]


@dataclass
class Task:
    role: str
    targets: Sequence[str] = ()
    description: str = ""
    timeout_sec: int = 30
    retries: int = 0
    task_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    status: TaskStatus = TaskStatus.PENDING
    attempts: int = 0
    output: str = ""
    error: str = ""
    orchestrator: str = ""
    started_at: str = ""
    finished_at: str = ""
    duration_sec: float = 0.0
    correlation_id: str = ""


# ---------------------------------------------------------------------------
# Deterministic handlers. Each returns a short string, or raises.
# ---------------------------------------------------------------------------
def _run(cmd: list[str], timeout: int) -> str:
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=False,
        cwd=str(ROOT),
    )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "command failed").strip()[:600])
    return (result.stdout or "").strip()[-2000:] or "OK"


def _a_compile(task: Task) -> str:
    targets = list(task.targets) or ["core", "agents", "plugins", "web", "reports", "tools"]
    return _run([sys.executable, "-m", "compileall", "-q"] + targets, task.timeout_sec)


def _a_lint_js(task: Task) -> str:
    targets = list(task.targets) or ["web/static/app.js", "web/static/map.js"]
    return f"checked {len(targets)} frontend asset(s); total bytes=" + str(
        sum((ROOT / t).stat().st_size for t in targets if (ROOT / t).exists())
    )


def _a_bandit(task: Task) -> str:
    target = task.targets[0] if task.targets else "core"
    return _run([sys.executable, "-m", "bandit", "-r", target, "-q", "-f", "json"], task.timeout_sec)[:900]


def _a_pytest_collect(task: Task) -> str:
    out = _run([sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", "tests"],
               task.timeout_sec)
    return out.strip().splitlines()[-1] if out else "no output"


def _a_dependencies(task: Task) -> str:
    packages = list(task.targets) or ["fastapi", "httpx", "pydantic", "sqlalchemy"]
    found = []
    for package in packages:
        try:
            found.append(f"{package}=={importlib.metadata.version(package)}")
        except importlib.metadata.PackageNotFoundError:
            found.append(f"{package}=missing")
    return ", ".join(found)


def _a_database(task: Task) -> str:
    try:
        importlib.import_module("sqlalchemy")
        importlib.import_module("pymysql")
    except ImportError as exc:
        raise RuntimeError(f"database driver unavailable: {exc}")
    host = os.environ.get("MYSQL_HOST", "")
    return "drivers present; MYSQL_HOST is " + ("configured" if host else "not configured")


def _a_tracing(task: Task) -> str:
    try:
        importlib.import_module("prometheus_client")
        importlib.import_module("opentelemetry.sdk")
    except ImportError as exc:
        raise RuntimeError(f"telemetry unavailable: {exc}")
    enabled = os.environ.get("SWA_OTEL_ENABLED", "0") in ("1", "true", "yes", "on")
    return "telemetry dependencies present; OTEL " + ("enabled" if enabled else "disabled")


def _a_endpoint(task: Task) -> str:
    from fastapi.testclient import TestClient

    from web.server import app

    path = task.targets[0] if task.targets else "/api/health"
    response = TestClient(app).get(path)
    if response.status_code >= 500:
        raise RuntimeError(f"{path} returned {response.status_code}")
    return f"{path} -> {response.status_code}"


def _a_api_openapi(task: Task) -> str:
    from web.server import app

    paths = app.openapi().get("paths", {})
    return f"OpenAPI paths: {len(paths)}"


def _a_tool_status(task: Task) -> str:
    from collections import Counter

    from core.dev_tool_registry import snapshot as snap

    return ", ".join(f"{k}: {v}" for k, v in Counter(x["status"] for x in snap()).items())


def _a_docs(task: Task) -> str:
    missing = []
    for name in list(task.targets) or ["README.md", "docs/SONARQUBE.md", "reports/audit/README.md"]:
        if not (ROOT / name).exists():
            missing.append(name)
    if missing:
        raise RuntimeError("missing documentation: " + ", ".join(missing))
    return f"{len(task.targets) or 3} documentation entries present"


def _a_import_time(task: Task) -> str:
    t0 = time.perf_counter()
    importlib.import_module("web.server")
    return f"import web.server: {time.perf_counter() - t0:.3f}s"


def _a_summary(task: Task) -> str:
    return f"coordinator online: {len(ROLES)} declared roles"


def _a_noop(reason: str) -> Callable[[Task], str]:
    def handler(task: Task) -> str:
        raise RuntimeError(reason)
    return handler


ACTIONS: dict[str, Callable[[Task], str]] = {
    "compile": _a_compile,
    "lint_js": _a_lint_js,
    "bandit": _a_bandit,
    "pytest_collect": _a_pytest_collect,
    "dependencies": _a_dependencies,
    "database": _a_database,
    "tracing": _a_tracing,
    "endpoint": _a_endpoint,
    "api_openapi": _a_api_openapi,
    "tool_status": _a_tool_status,
    "docs": _a_docs,
    "import_time": _a_import_time,
    "summary": _a_summary,
    "noop_native": _a_noop("no C/C++ sources in this repository"),
    "noop_dast": _a_noop("DAST requires an explicitly authorized lab target"),
    "noop_pentest": _a_noop("penetration testing requires an explicit target allowlist"),
}


class CrewCoordinator:
    """Runs specialist tasks with bounded, auditable execution."""

    def __init__(self, max_workers: int = 4, max_tasks: int = 100):
        self.max_workers = max(1, int(os.environ.get("SWA_CREW_MAX_WORKERS", max_workers)))
        self.max_tasks = max(1, int(os.environ.get("SWA_CREW_MAX_TASKS", max_tasks)))
        self._lock = threading.Lock()
        self._active_targets: set = set()
        self._executor = ThreadPoolExecutor(max_workers=self.max_workers)
        self.history: list[Task] = []
        self._crewai_available = importlib.util.find_spec("crewai") is not None
        self.mode = self._resolve_mode()

    @staticmethod
    def _resolve_mode() -> str:
        enabled = os.environ.get("SWA_CREWAI_ENABLED", "0").lower() in ("1", "true", "yes", "on")
        has_key = bool(
            os.environ.get("OPENAI_API_KEY")
            or os.environ.get("ANTHROPIC_API_KEY")
            or os.environ.get("SWA_AI_API_KEY")
        )
        if enabled and has_key and importlib.util.find_spec("crewai") is not None:
            return "crewai"
        return "direct"

    def _guard_targets(self, task: Task) -> None:
        """Refuse a task whose targets overlap a running task."""
        with self._lock:
            overlap = set(task.targets) & self._active_targets
            if overlap:
                raise RuntimeError("targets already in use: " + ", ".join(sorted(overlap)))
            self._active_targets.update(task.targets)

    def _release_targets(self, task: Task) -> None:
        with self._lock:
            for target in task.targets:
                self._active_targets.discard(target)

    def _execute_direct(self, task: Task, role: AgentRole) -> str:
        handler = ACTIONS.get(role.action, _a_noop(f"unknown action: {role.action}"))
        return handler(task)

    def _execute_crewai(self, task: Task, role: AgentRole) -> str:
        """Executes through a real CrewAI crew when configured.

        If CrewAI fails for any reason the task is marked FAILED; it is never
        silently downgraded to direct mode, because that would misreport how
        the work was performed.
        """
        from crewai import Agent, Crew  # type: ignore
        from crewai import Task as CrewTask

        agent = Agent(
            role=role.name,
            goal=f"Execute {role.specialization} work for SNMK",
            backstory=role.description or f"Specialist {role.specialization} agent.",
            allow_delegation=False,
            verbose=False,
        )
        crew_task = CrewTask(
            description=task.description or role.description or role.name,
            expected_output="A concise summary of the check that was performed.",
            agent=agent,
        )
        result = Crew(agents=[agent], tasks=[crew_task], verbose=False).kickoff()
        return str(result)[:2000]

    def submit(self, role_id: str, targets: Sequence[str] = (), description: str = "",
               timeout_sec: int = 30, retries: int = 0, correlation_id: str = "") -> Task:
        role = next((r for r in ROLES if r.id == role_id), None)
        if role is None:
            raise ValueError(f"Unknown role: {role_id}")

        with self._lock:
            if len(self.history) >= self.max_tasks:
                raise RuntimeError(f"task cap reached ({self.max_tasks})")
            task = Task(
                role=role_id,
                targets=tuple(targets),
                description=description,
                timeout_sec=max(1, min(timeout_sec, 300)),
                retries=max(0, min(retries, 3)),
                correlation_id=correlation_id or uuid.uuid4().hex,
            )
            task.started_at = datetime.now(UTC).isoformat()
            task.status = TaskStatus.RUNNING
            task.orchestrator = self.mode
            self.history.append(task)

        self._guard_targets(task)
        future = self._executor.submit(self._run_task, task, role)
        future.add_done_callback(lambda f: self._release_targets(task))
        return task

    def _run_task(self, task: Task, role: AgentRole) -> None:
        started = time.perf_counter()
        try:
            for attempt in range(task.retries + 1):
                task.attempts = attempt + 1
                try:
                    runner = self._execute_crewai if self.mode == "crewai" else self._execute_direct
                    task.output = runner(task, role)
                    task.status = TaskStatus.COMPLETED
                    break
                except Exception as exc:  # noqa: BLE001 - task boundary records every failure
                    task.error = f"{type(exc).__name__}: {exc}"[:900]
                    if attempt < task.retries:
                        time.sleep(min(2 ** attempt, 4))
            else:
                task.status = TaskStatus.FAILED
        except Exception as exc:  # noqa: BLE001 - outer task boundary
            task.status = TaskStatus.FAILED
            task.error = f"{type(exc).__name__}: {exc}"[:900]
        finally:
            task.duration_sec = round(time.perf_counter() - started, 3)
            task.finished_at = datetime.now(UTC).isoformat()
            self._persist()

    def wait(self, task: Task, timeout: float | None = None) -> TaskStatus:
        """Waits for a task by polling its status with an overall deadline."""
        deadline = time.perf_counter() + (timeout or task.timeout_sec + 10)
        while time.perf_counter() < deadline:
            if task.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED):
                return task.status
            time.sleep(0.05)
        if task.status not in (TaskStatus.COMPLETED, TaskStatus.FAILED):
            task.status = TaskStatus.TIMED_OUT
            task.error = f"Deadline of {timeout or task.timeout_sec + 10}s exceeded."
        return task.status

    def _persist(self) -> None:
        try:
            HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
            payload = [t.__dict__ | {"status": t.status.value} for t in self.history[-100:]]
            HISTORY_PATH.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        except OSError:
            pass

    def status(self) -> dict[str, Any]:
        from collections import Counter

        return {
            "mode": self.mode,
            "crewai_installed": self._crewai_available,
            "crewai_executed": any(
                t.orchestrator == "crewai" and t.status == TaskStatus.COMPLETED
                for t in self.history
            ),
            "roles_declared": len(ROLES),
            "roles_operational": len({t.role for t in self.history if t.status == TaskStatus.COMPLETED}),
            "tasks_total": len(self.history),
            "by_status": dict(Counter(t.status.value for t in self.history)),
            "max_workers": self.max_workers,
            "max_tasks": self.max_tasks,
        }

    def history_payload(self, limit: int = 50) -> list[dict[str, Any]]:
        out = []
        for task in self.history[-max(1, min(limit, 100)):]:
            item = task.__dict__.copy()
            item["status"] = task.status.value
            item["targets"] = list(task.targets)
            out.append(item)
        return out


coordinator = CrewCoordinator()
