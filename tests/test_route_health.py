"""
Regression tests for the compatibility aliases in web/server.py.

Two aliases imported function names that had been renamed in
web/enterprise_api.py, so both endpoints returned 500 on every request.
A route smoke test over every parameterless GET endpoint is included so a
future rename cannot silently break an alias again.
"""

import unittest

from fastapi.testclient import TestClient

from web.server import app


class TestCompatibilityAliases(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_01_approval_gates_alias_returns_success(self):
        response = self.client.get("/api/enterprise/approval-gates")
        self.assertLess(response.status_code, 500)
        self.assertIn(response.status_code, (200, 401, 403))

    def test_02_drift_alias_returns_success(self):
        response = self.client.get("/api/enterprise/drift")
        self.assertLess(response.status_code, 500)
        self.assertIn(response.status_code, (200, 401, 403))

    def test_03_every_parameterless_get_route_avoids_a_server_error(self):
        """A 500 is a defect; 4xx is an intentional guard (auth, scope, etc.)."""
        failures = []
        for route in app.routes:
            path = getattr(route, "path", "")
            methods = getattr(route, "methods", set()) or set()
            if "GET" not in methods or not path.startswith("/api/") or "{" in path:
                continue
            try:
                response = self.client.get(path)
                if response.status_code >= 500:
                    failures.append((path, response.status_code))
            except Exception as exc:  # noqa: BLE001 - record every route failure
                failures.append((path, type(exc).__name__))
        self.assertEqual(failures, [], f"Endpoints returning 5xx: {failures}")


if __name__ == "__main__":
    unittest.main()
