"""
Regression tests for the authentication bypasses found in the security audit.

The findings these cover:

SEC-01  The login endpoints minted a valid session for *any* caller, and the
        v1 login derived the role (``admin``) from the client-supplied
        username.
SEC-02  The authentication gate only protected paths starting with
        ``/api``, so the OpenAI-compatible endpoints (``/v1/...``,
        ``/chat/...``, ``/models``) were reachable without a credential.
SEC-09  The ``/ws`` telemetry stream was not authenticated; Starlette does
        not run HTTP middleware for a WebSocket scope.

The tests patch the configuration attributes of ``core.app_security`` rather
than reloading the module.  ``authenticate_request`` and
``create_login_session`` read those attributes when they are called, so the
patch is effective -- and, unlike a reload, it cannot leak into the rest of
the test session.
"""

import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import core.app_security as security
from web.server import app


def _config(**overrides):
    """
    Patches the security configuration for the duration of a test.

    The defaults describe a deployment with authentication switched on and a
    master key configured, which is the configuration in which a bypass is
    meaningful.
    """
    values = {
        "SWA_AUTH_ENABLED": True,
        "SWA_MASTER_API_KEY": "a-real-master-key-of-sufficient-length",
        "SWA_OPERATOR_PASSWORD": "",
        "SWA_DEFAULT_ROLE": "auditor",
    }
    values.update(overrides)
    return patch.multiple(security, **values)


class TestAuthenticationBypass(unittest.TestCase):
    # -- SEC-01 -----------------------------------------------------------
    def test_01_login_never_grants_admin_from_the_username(self):
        """The username must not be able to select the role."""
        with _config():
            ok, token, role, identity = security.create_login_session(
                identity="admin", api_key=None, password=None
            )
        self.assertFalse(ok, "A login without a credential must be refused")
        self.assertEqual(token, "")
        self.assertNotEqual(role, "admin")

    def test_02_login_refuses_when_auth_is_enabled_and_no_credential(self):
        with _config():
            ok, _, role, _ = security.create_login_session(identity="operator")
        self.assertFalse(ok)
        self.assertNotEqual(role, "admin")

    def test_03_master_api_key_grants_admin(self):
        with _config():
            ok, token, role, _ = security.create_login_session(
                identity="ci", api_key="a-real-master-key-of-sufficient-length"
            )
        self.assertTrue(ok)
        self.assertTrue(token)
        self.assertEqual(role, "admin")

    def test_04_wrong_api_key_is_refused(self):
        with _config():
            ok, _, _, _ = security.create_login_session(identity="x", api_key="wrong")
        self.assertFalse(ok)

    def test_05_operator_password_grants_the_default_role(self):
        with _config(SWA_MASTER_API_KEY="", SWA_OPERATOR_PASSWORD="operator-secret"):
            ok, token, role, _ = security.create_login_session(
                identity="analyst", password="operator-secret"
            )
        self.assertTrue(ok)
        self.assertTrue(token)
        self.assertEqual(role, "auditor")

    def test_06_wrong_password_is_refused(self):
        with _config(SWA_MASTER_API_KEY="", SWA_OPERATOR_PASSWORD="operator-secret"):
            ok, _, _, _ = security.create_login_session(identity="x", password="wrong")
        self.assertFalse(ok)

    def test_07_development_mode_issues_a_session_but_not_admin(self):
        """With authentication off the UI must still work, but not as admin."""
        with _config(
            SWA_AUTH_ENABLED=False, SWA_MASTER_API_KEY="", SWA_OPERATOR_PASSWORD=""
        ):
            ok, token, role, _ = security.create_login_session(identity="dev")
        self.assertTrue(ok)
        self.assertTrue(token)
        self.assertEqual(role, "auditor")

    def test_08_login_endpoint_rejects_a_bare_username(self):
        """End to end: the HTTP endpoint must refuse a credential-free login."""
        with _config():
            client = TestClient(app)

            response = client.post("/api/auth/login", json={"username": "attacker"})
            self.assertEqual(response.status_code, 401)

            response = client.post("/api/v1/auth/login", json={"username": "admin"})
            self.assertEqual(response.status_code, 401)

    def test_09_login_endpoint_issues_a_session_with_the_master_key(self):
        with _config():
            client = TestClient(app)
            response = client.post(
                "/api/auth/login",
                json={"username": "ci", "api_key": "a-real-master-key-of-sufficient-length"},
            )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["role"], "admin")
        self.assertTrue(body["token"])

    # -- SEC-02 -----------------------------------------------------------
    def test_10_openai_compatible_paths_are_protected(self):
        """The gate must cover the paths outside the ``/api`` prefix."""
        from web.server import _is_protected_api_path

        for path in (
            "/api/scans",
            "/v1/chat/completions",
            "/chat/completions",
            "/v1/models",
            "/models",
            "/api/v1/auth/login",
        ):
            with self.subTest(path=path):
                self.assertTrue(_is_protected_api_path(path))

        for path in ("/", "/static/app.js", "/favicon.ico", "/health"):
            with self.subTest(path=path):
                self.assertFalse(_is_protected_api_path(path))

    def test_11_openai_endpoint_requires_a_credential(self):
        """An unauthenticated chat completion must not be served."""
        with _config():
            client = TestClient(app)
            response = client.post(
                "/v1/chat/completions",
                json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
            )
        self.assertEqual(response.status_code, 401)

    def test_12_the_public_surface_stays_reachable(self):
        """The health probes must not require a credential."""
        with _config():
            client = TestClient(app)
            for path in ("/api/health", "/api/auth/status"):
                with self.subTest(path=path):
                    self.assertEqual(client.get(path).status_code, 200)


if __name__ == "__main__":
    unittest.main()
