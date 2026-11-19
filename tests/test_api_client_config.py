"""
Tests for the centralized frontend API client and its server bootstrap.

The reported "Failed to launch assessment: Failed to fetch" failure was
caused by API calls being issued against whatever origin happened to serve
the HTML, with no single place to configure the backend origin. These tests
lock in the central client wiring and the environment-driven bootstrap.
"""

import re
from pathlib import Path

from fastapi.testclient import TestClient

from web.server import app

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "web" / "static"


class TestClientConfigEndpoint:
    def setup_method(self):
        self.client = TestClient(app)

    def test_bootstrap_endpoint_sets_empty_base_by_default(self, monkeypatch):
        monkeypatch.delenv("SWA_PUBLIC_API_BASE_URL", raising=False)
        response = self.client.get("/api/client-config.js")
        assert response.status_code == 200
        assert "javascript" in response.headers["content-type"]
        assert "window.SNMK_API_BASE_URL" in response.text

    def test_bootstrap_endpoint_honours_environment(self, monkeypatch):
        monkeypatch.setenv("SWA_PUBLIC_API_BASE_URL", "http://127.0.0.1:8000")
        response = self.client.get("/api/client-config.js")
        assert 'window.SNMK_API_BASE_URL = "http://127.0.0.1:8000";' in response.text

    def test_bootstrap_endpoint_rejects_unsafe_values(self, monkeypatch):
        monkeypatch.setenv("SWA_PUBLIC_API_BASE_URL", 'javascript:alert(1)//')
        response = self.client.get("/api/client-config.js")
        assert 'window.SNMK_API_BASE_URL = "";' in response.text

    def test_bootstrap_endpoint_is_public_when_auth_enabled(self, monkeypatch):
        from core import app_security

        assert "/api/client-config.js" in app_security.PUBLIC_PATHS


class TestCentralizedClientWiring:
    def test_index_loads_client_before_consumers(self):
        html = (STATIC / "index.html").read_text(encoding="utf-8")
        assert '<meta name="snmk-api-base"' in html
        assert html.index('src="/api/client-config.js"') < html.index('src="api-client.js')
        assert html.index('src="api-client.js') < html.index('src="app.js')

    def test_all_legacy_fetch_calls_are_routed_through_client(self):
        for name in ("app.js", "map.js", "digital_forensics.js"):
            source = (STATIC / name).read_text(encoding="utf-8")
            assert not re.search(r"(?<![\w])fetch\s*\(", source), f"raw fetch() remains in {name}"
            assert "apiFetch(" in source

    def test_client_implements_required_features(self):
        source = (STATIC / "api-client.js").read_text(encoding="utf-8")
        for feature in ("AbortController", "X-Request-ID", "X-Correlation-ID", "Authorization",
                        "isNetworkError", "isTimeout", "isAuthFailure", "snmk:auth-failure",
                        "snmk_api_base_url"):
            assert feature in source, f"missing client feature: {feature}"

    def test_client_javascript_is_syntactically_valid(self):
        import shutil
        import subprocess

        node = shutil.which("node")
        if not node:
            return  # Node is not available in every environment
        result = subprocess.run([node, "--check", str(STATIC / "api-client.js")],
                                check=False, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
