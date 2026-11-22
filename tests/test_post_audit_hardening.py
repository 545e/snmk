"""
Regression tests for the findings closed in the post-audit hardening pass.

Covers:

* SEC-20  Path traversal in the kill-chain report download.
* SEC-23  The orchestrator sending an encrypted credential envelope to the
          LLM provider instead of the decrypted key.
* B101    Internal invariants implemented with ``assert``, which vanishes
          under ``python -O``.
"""

import re
import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from web.server import app


class TestReportDownloadTraversal(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_01_traversal_in_report_id_is_refused(self):
        """A report id must be an identifier, never a path."""
        for malicious in (
            "..\\..\\..\\secrets",
            "../../../etc/passwd",
            "C:\\Windows\\win",
            "..%5C..%5Cwindows",
            "abc/def",
        ):
            with self.subTest(report_id=malicious):
                response = self.client.get(
                    f"/api/kill-chain/reports/{malicious}/download?format=html"
                )
                # 400 on validation, 404 if the route did not match -- never 200.
                self.assertIn(response.status_code, (400, 404))
                self.assertNotEqual(response.status_code, 200)

    def test_02_valid_report_id_reaches_the_file_lookup(self):
        """A legitimate identifier must pass validation and reach FileResponse."""
        from web.kill_chain_router import download_kill_chain_report

        with patch("web.kill_chain_router.FileResponse") as _, patch(
            "web.kill_chain_router.Path"
        ) as path_cls:
            path_cls.return_value.resolve.return_value.__truediv__ = MagicMock()
            # The route builds a Path and resolves it; patching away the
            # filesystem means the only assertion we need is that HTTPException
            # with 400 was not raised at the identifier step.
            try:
                download_kill_chain_report(report_id="kc_report_abc123", format="html")
            except Exception as exc:
                self.assertNotEqual(
                    getattr(exc, "status_code", None),
                    400,
                    "A valid identifier must not be rejected as invalid",
                )

    def test_03_pattern_rejects_path_characters(self):
        """The identifier pattern itself is the first line of defence."""
        pattern = re.compile(r"[A-Za-z0-9_-]{1,128}")
        for bad in ("a/b", "a\\b", "a.b", "a:b", "..", ""):
            with self.subTest(value=bad):
                self.assertIsNone(pattern.fullmatch(bad))
        for good in ("report_1", "kc-ev-2026", "A" * 128):
            with self.subTest(value=good[:20]):
                self.assertIsNotNone(pattern.fullmatch(good))


class TestRateLimiterOrdering(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app, client=("198.51.100.23", 51000))

    def test_10_rate_limiter_is_the_outermost_middleware(self):
        """The limiter must run before the auth gate.

        Starlette inserts each middleware at index 0, so the outermost one is
        at index 0 of ``user_middleware``. If auth ran first, a bad credential
        would return 401 before the limiter ever saw the request.
        """
        from web.server import app as current_app

        first = current_app.user_middleware[0]
        dispatch = getattr(first, "kwargs", {}).get("dispatch")
        self.assertEqual(
            getattr(dispatch, "__name__", None),
            "_rate_limit_middleware_impl",
        )

    def test_11_failed_login_is_throttled(self):
        """A rejected credential still consumes the rate-limit budget."""
        from core.app_security import rate_limiter

        with patch.object(rate_limiter, "is_allowed", return_value=False) as allowed, \
             patch.object(rate_limiter, "retry_after", return_value=7):
            response = self.client.post(
                "/api/auth/login",
                json={"username": "attacker", "api_key": "wrong"},
            )

        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers.get("Retry-After"), "7")
        allowed.assert_called_once()
        self.assertEqual(allowed.call_args.args[0], "198.51.100.23")


class TestOrchestratorKeyDecryption(unittest.TestCase):
    def test_04_encrypted_envelope_is_decrypted(self):
        """The provider must receive the key, never the enc:v1 envelope."""
        from core import credentials
        from agents.orchestrator import SWAOrchestrator

        plaintext = "sk-a-real-looking-test-key-abcdefghijklmnop"
        encrypted = credentials.encrypt_secret_value(plaintext)

        with patch(
            "core.database.db.get_setting", return_value=encrypted
        ):
            resolved = SWAOrchestrator._load_ai_key_from_vault()

        self.assertEqual(resolved, plaintext)
        self.assertNotIn("enc:", resolved)

    def test_05_plaintext_legacy_value_still_works(self):
        """An old unencrypted setting must remain readable."""
        from agents.orchestrator import SWAOrchestrator

        with patch(
            "core.database.db.get_setting",
            return_value="plain-legacy-key",
        ):
            self.assertEqual(
                SWAOrchestrator._load_ai_key_from_vault(), "plain-legacy-key"
            )

    def test_06_unreadable_envelope_fails_closed(self):
        """A corrupt envelope must not be sent to the provider."""
        from agents.orchestrator import SWAOrchestrator

        with patch(
            "core.database.db.get_setting", return_value="enc:v1:corrupt:salt"
        ):
            self.assertEqual(SWAOrchestrator._load_ai_key_from_vault(), "")

    def test_07_explicit_config_key_wins_over_vault(self):
        """A key supplied in the scan config is already plaintext."""

        from core.models import ScanConfig
        from agents.orchestrator import SWAOrchestrator

        config = MagicMock(spec=ScanConfig)
        config.ai_api_key = "config-supplied-key"
        config.ai_provider = "openai"
        config.ai_model = "gpt-4o-mini"
        config.ai_base_url = None

        job = MagicMock()
        job.id = "test"
        job.config = config

        with patch(
            "core.database.db.get_setting", return_value="enc:v1:corrupt:salt"
        ), patch("agents.orchestrator.SWALLMClient") as llm_client:
            SWAOrchestrator(job)

        self.assertEqual(llm_client.call_args.kwargs["api_key"], "config-supplied-key")


class TestInvariantsSurviveOptimisation(unittest.TestCase):
    def test_08_group_parser_rejects_bad_position_without_assert(self):
        """The check must still fire when Python is run with -O."""
        from core.pattern_gating import _Parser

        parser = _Parser("abc")
        parser.i = 0
        with self.assertRaises(ValueError):
            parser._parse_group()

    def test_09_char_class_parser_rejects_bad_position_without_assert(self):
        from core.pattern_gating import _Parser

        parser = _Parser("abc")
        parser.i = 0
        with self.assertRaises(ValueError):
            parser._skip_char_class()


if __name__ == "__main__":
    unittest.main()
