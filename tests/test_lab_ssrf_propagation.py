"""Regression tests: explicit lab authorization must reach tool-level SSRF guards."""

from fastapi.testclient import TestClient

from web.server import app
from core.cyber_tools import _validate_safe_target_url


class TestLabAuthorizationPropagation:
    def setup_method(self):
        self.client = TestClient(app)

    def test_url_guard_blocks_loopback_without_opt_in(self):
        assert _validate_safe_target_url("http://127.0.0.1:8123") is None

    def test_url_guard_allows_loopback_with_explicit_lab_opt_in(self):
        assert _validate_safe_target_url("http://127.0.0.1:8123", allow_lab=True) is not None

    def test_url_guard_never_allows_metadata_even_with_lab_opt_in(self):
        assert _validate_safe_target_url("http://169.254.169.254/latest/meta-data", allow_lab=True) is None

    def test_headers_tool_honours_explicit_lab_authorization(self):
        # No external server is required: with lab authorization the request
        # passes the SSRF guard and fails only at connection time. Without it
        # the guard refuses the target before any connection is attempted.
        response = self.client.post(
            "/api/tools/headers/execute",
            json={"target": "http://127.0.0.1:8123", "options": {"lab_mode": True}},
        )
        assert response.status_code == 200
        result = response.json()["result"]
        assert "restricted" not in (result.get("error") or "")

    def test_headers_tool_refuses_implicit_loopback_access(self):
        response = self.client.post(
            "/api/tools/headers/execute",
            json={"target": "http://127.0.0.1:8123", "options": {}},
        )
        assert response.status_code == 200
        assert "restricted" in response.json()["result"].get("error", "")
