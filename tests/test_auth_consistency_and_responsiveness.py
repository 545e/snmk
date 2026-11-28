"""Regression tests for two real dashboard failures.

1. Auth policy drift: the HTTP middleware treated a template API key as "not
   configured" while ``authenticate_request`` treated the same key as a real
   credential.  Result: every MAP/network endpoint returned 401 while the rest
   of the dashboard worked.  Both paths now share ``is_auth_required()``.

2. Blocking tool discovery: version probes spawn subprocesses and used to run
   directly inside async endpoints, freezing the whole event loop for ~10s.
   They now run in worker threads and their results are cached.
"""

import os
from unittest import TestCase, main, mock

from starlette.requests import Request

from core import app_security


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _request(path="/api/network/interfaces"):
    return Request({"type": "http", "method": "GET", "path": path, "headers": []})


class TestAuthPolicyConsistency(TestCase):
    def test_template_master_key_is_not_a_real_key(self):
        key = "sk-change_me-please-replace-this-template-value-1234"
        with mock.patch.object(app_security, "SWA_MASTER_API_KEY", key), \
             mock.patch.object(app_security, "SWA_AUTH_ENABLED", False):
            self.assertFalse(app_security.is_real_master_key())
            self.assertFalse(app_security.is_auth_required())
            # The exact drift that broke the MAP view used to raise here.
            ctx = app_security.authenticate_request(_request())
            self.assertTrue(ctx.authenticated)
            self.assertEqual(ctx.role, "admin")

    def test_real_master_key_still_requires_auth(self):
        key = "a9f3c1e77b0d4e8fa1c2047d9e6b58f2deadbeef00c0ffee"
        with mock.patch.object(app_security, "SWA_MASTER_API_KEY", key), \
             mock.patch.object(app_security, "SWA_AUTH_ENABLED", False):
            self.assertTrue(app_security.is_real_master_key())
            self.assertTrue(app_security.is_auth_required())
            with self.assertRaises(Exception):
                app_security.authenticate_request(_request())

    def test_explicit_auth_flag_enforces_auth(self):
        with mock.patch.object(app_security, "SWA_MASTER_API_KEY", ""), \
             mock.patch.object(app_security, "SWA_AUTH_ENABLED", True):
            self.assertTrue(app_security.is_auth_required())
            with self.assertRaises(Exception):
                app_security.authenticate_request(_request())

    def test_middleware_uses_the_shared_policy(self):
        with open(os.path.join(REPO, "web", "server.py"), encoding="utf-8") as fh:
            src = fh.read()
        marker = "def auth_enforcement_middleware"
        start = src.index(marker)
        body = src[start:start + 2200]
        self.assertIn("is_auth_required()", body)
        self.assertNotIn("_placeholder_markers", body)


class TestNonBlockingToolDiscovery(TestCase):
    def _source(self, relative):
        with open(os.path.join(REPO, *relative.split("/")), encoding="utf-8") as fh:
            return fh.read()

    def test_tools_status_runs_inventory_in_a_thread(self):
        src = self._source("web/server.py")
        start = src.index('@app.get("/api/tools/status")')
        self.assertIn("asyncio.to_thread(ScannerIntegrations.get_tool_inventory)", src[start:start + 600])

    def test_dev_tools_snapshot_is_cached(self):
        src = self._source("core/dev_tool_registry.py")
        self.assertIn("_SNAPSHOT_TTL_SEC", src)
        start = src.index("def snapshot(self, force_refresh: bool = False)")
        self.assertIn("_snapshot_cache", src[start:start + 900])

    def test_startup_warms_tool_caches(self):
        src = self._source("web/server.py")
        start = src.index("async def on_startup()")
        self.assertIn("_warm_tool_caches", src[start:start + 1600])


if __name__ == "__main__":
    main()
