"""
Tests for the platform-engineering modules added in this pass:

* the centralized development/security tool registry (Phase 3)
* CrewAI-style orchestration with a controlled fallback (Phase 2)
* the optional MySQL adapter (Phase 4)
* centralized alert management (Phase 8)

Every test asserts observed behaviour. Nothing is marked operational because
a name appears in a configuration file.
"""

import json
import os
import unittest
from unittest.mock import patch

import core.dev_tool_registry as dtr
import core.mysql_adapter as mysql
from core.alert_manager import AlertManager, AlertStatus, DeliveryStatus, Severity
from core.crew_coordinator import ROLES, CrewCoordinator, TaskStatus


class TestToolRegistry(unittest.TestCase):
    def test_01_six_statuses_are_declared(self):
        self.assertEqual(
            {s.value for s in dtr.ToolStatus},
            {"Not Available", "Installed", "Configured", "Operational", "Failed", "Disabled"},
        )

    def test_02_snapshot_uses_real_measurement(self):
        snapshot = dtr.registry.snapshot()
        self.assertGreater(len(snapshot), 10)
        for record in snapshot:
            self.assertIn(record["status"], [s.value for s in dtr.ToolStatus])
            if record["status"] == "Operational":
                # Operational requires a real probe result.
                self.assertTrue(record["version"] or record["path"])

    def test_03_disabled_tool_is_reported_as_disabled(self):
        spec = dtr.ToolSpec("probe_disabled", "Probe", "test", executable="definitely-not-a-tool-xyz")
        with patch.dict(os.environ, {"SWA_TOOL_PROBE_DISABLED_DISABLED": "1"}):
            record = dtr.ToolRegistry([spec]).check(spec)
        self.assertEqual(record.status, dtr.ToolStatus.DISABLED)

    def test_04_missing_executable_is_not_available(self):
        spec = dtr.ToolSpec("probe_missing", "Probe", "test", executable="definitely-not-a-tool-xyz")
        record = dtr.ToolRegistry([spec]).check(spec)
        self.assertEqual(record.status, dtr.ToolStatus.NOT_AVAILABLE)
        self.assertTrue(record.reason)

    def test_05_required_env_is_reported_by_name_only(self):
        spec = dtr.ToolSpec("probe_env", "Probe", "test",
                            kind="runtime", executable="python",
                            required_env=("SWA_TEST_SECRET_NAME_ONLY",))
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SWA_TEST_SECRET_NAME_ONLY", None)
            record = dtr.ToolRegistry([spec]).check(spec)
        self.assertEqual(record.status, dtr.ToolStatus.CONFIGURED)
        self.assertEqual(record.missing_env, ["SWA_TEST_SECRET_NAME_ONLY"])
        self.assertNotIn("password", json.dumps(record.to_dict()).lower())


class TestCrewCoordinator(unittest.TestCase):
    def test_06_twenty_two_roles_declared(self):
        self.assertEqual(len(ROLES), 22)
        self.assertEqual(len({r.id for r in ROLES}), 22)

    def test_07_direct_mode_is_honest_when_crewai_not_configured(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SWA_CREWAI_ENABLED", None)
            coordinator = CrewCoordinator()
            self.assertEqual(coordinator.mode, "direct")
            self.assertFalse(coordinator.status()["crewai_executed"])

    def test_08_task_executes_and_records_duration(self):
        coordinator = CrewCoordinator()
        task = coordinator.submit("lead", description="self check", timeout_sec=10)
        status = coordinator.wait(task, 20)
        self.assertEqual(status, TaskStatus.COMPLETED)
        self.assertGreaterEqual(task.attempts, 1)
        self.assertGreaterEqual(task.duration_sec, 0)
        self.assertTrue(task.started_at and task.finished_at)

    def test_09_overlapping_targets_are_refused(self):
        coordinator = CrewCoordinator()
        first = coordinator.submit("qa", targets=["tests/test_tool_registry.py"], timeout_sec=60)
        with self.assertRaises(RuntimeError):
            coordinator.submit("qa", targets=["tests/test_tool_registry.py"], timeout_sec=60)
        coordinator.wait(first, 70)

    def test_10_bounded_retries(self):
        coordinator = CrewCoordinator()
        task = coordinator.submit("dast", retries=10, timeout_sec=5)
        status = coordinator.wait(task, 20)
        self.assertEqual(status, TaskStatus.FAILED)
        self.assertLessEqual(task.attempts, 4)  # 1 + max 3 retries

    def test_11_unknown_role_is_rejected(self):
        coordinator = CrewCoordinator()
        with self.assertRaises(ValueError):
            coordinator.submit("not_a_role")


class TestMySQLAdapter(unittest.TestCase):
    def test_12_sqlite_default_reports_not_available(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SWA_DB_BACKEND", None)
            status = mysql.mysql_status()
        self.assertEqual(status["status"], "Not Available")
        self.assertEqual(status["backend"], "sqlite")

    def test_13_metrics_never_fabricate_values(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SWA_DB_BACKEND", None)
            metrics = mysql.mysql_metrics()
        self.assertFalse(metrics["available"])
        self.assertIn("reason", metrics)
        self.assertNotIn("active_connections", metrics)

    def test_14_config_requires_credentials(self):
        with patch.dict(os.environ, {
            "SWA_DB_BACKEND": "mysql",
            "MYSQL_HOST": "db.internal",
            "MYSQL_USER": "snmk",
        }, clear=False):
            os.environ.pop("MYSQL_PASSWORD", None)
            with self.assertRaises(mysql.MySQLUnavailable):
                mysql.MySQLConfig.from_env()

    def test_15_url_never_contains_the_password(self):
        config = mysql.MySQLConfig(
            host="db.internal", port=3306, database="snmk",
            user="snmk", password="a-very-secret-value",
        )
        self.assertNotIn("a-very-secret-value", config.url())
        self.assertIn("***", config.url())


class TestAlertManager(unittest.TestCase):
    def setUp(self):
        import tempfile
        from pathlib import Path

        self.tmp = tempfile.TemporaryDirectory()
        self.manager = AlertManager(path=Path(self.tmp.name) / "alerts.json")

    def tearDown(self):
        self.tmp.cleanup()

    def test_16_alert_has_the_full_lifecycle_fields(self):
        alert = self.manager.create("Disk full", Severity.HIGH, "monitor", "disk", "usage at 98%")
        data = alert.to_dict()
        for field in ("id", "created_at", "severity", "source", "component",
                      "description", "evidence", "related_id", "remediation",
                      "owner", "status", "resolution", "updated_at"):
            self.assertIn(field, data)

    def test_17_deduplication_returns_the_existing_alert(self):
        kwargs = {"title": "Repeated failure", "severity": Severity.MEDIUM,
                  "source": "scan", "component": "engine", "description": "x"}
        first = self.manager.create(**kwargs)
        second = self.manager.create(**kwargs)
        self.assertEqual(first.id, second.id)
        self.assertEqual(self.manager.summary()["total"], 1)

    def test_18_acknowledge_assign_resolve(self):
        alert = self.manager.create("Failure", Severity.LOW, "test", "unit")
        self.assertTrue(self.manager.acknowledge(alert.id))
        self.assertEqual(alert.status, AlertStatus.ACKNOWLEDGED)
        self.assertTrue(self.manager.assign(alert.id, "operator"))
        self.assertEqual(alert.owner, "operator")
        self.assertTrue(self.manager.resolve(alert.id, "fixed"))
        self.assertEqual(alert.status, AlertStatus.RESOLVED)
        self.assertFalse(self.manager.acknowledge(alert.id))

    def test_19_delivery_is_never_claimed_without_confirmation(self):
        alert = self.manager.create("Notify", Severity.LOW, "test", "unit")
        results = self.manager.notify(alert.id)
        self.assertEqual(results["unconfigured"], DeliveryStatus.NOT_CONFIGURED.value)

        self.manager.register_channel("confirming", lambda a: True)
        results = self.manager.notify(alert.id)
        self.assertEqual(results["confirming"], DeliveryStatus.DELIVERED.value)

        self.manager.register_channel("failing", lambda a: False)
        results = self.manager.notify(alert.id)
        self.assertEqual(results["failing"], DeliveryStatus.FAILED.value)

    def test_20_suppression_is_fingerprint_based(self):
        alert = self.manager.create("Suppressed", Severity.LOW, "test", "unit")
        self.manager.suppress(alert.fingerprint)
        second = self.manager.create("Suppressed", Severity.LOW, "test", "unit")
        self.assertEqual(second.status, AlertStatus.SUPPRESSED)


if __name__ == "__main__":
    unittest.main()
