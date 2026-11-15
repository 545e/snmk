"""
Tests for the webhook and notification dispatcher.

``core/notifier.py`` signs outbound payloads with an HMAC and posts them to
operator-controlled endpoints, so both the signature and the failure
handling are worth pinning down.
"""

import asyncio
import hashlib
import hmac
import json
import unittest
from unittest.mock import patch

from core.notifier import NotificationDispatcher


class _Response:
    def __init__(self, status_code: int):
        self.status_code = status_code


class _Recorder:
    """Captures the arguments of the patched ``AsyncClient.post``."""

    def __init__(self, status_code: int = 200):
        self.status_code = status_code
        self.calls = []

    async def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return _Response(self.status_code)

    @property
    def last(self):
        return self.calls[-1][1]


class TestNotificationDispatcher(unittest.TestCase):
    def _patch(self, recorder):
        return patch(
            "httpx.AsyncClient.post", new=recorder.post
        )

    # -- Slack ------------------------------------------------------------
    def test_01_slack_without_a_url_does_nothing(self):
        result = asyncio.run(
            NotificationDispatcher.send_slack_alert(
                "", "title", "HIGH", "endpoint", "details"
            )
        )
        self.assertFalse(result)

    def test_02_slack_posts_a_block_kit_attachment(self):
        recorder = _Recorder(200)
        with self._patch(recorder):
            result = asyncio.run(
                NotificationDispatcher.send_slack_alert(
                    "https://hooks.slack.test/abc", "Title", "critical",
                    "https://target.test/x", "Some detail"
                )
            )
        self.assertTrue(result)
        url, kwargs = recorder.calls[0]
        self.assertEqual(url, "https://hooks.slack.test/abc")
        payload = kwargs["json"]
        self.assertIn("attachments", payload)
        attachment = payload["attachments"][0]
        self.assertIn("CRITICAL", attachment["title"])
        self.assertIn("Title", attachment["title"])
        # The severity drives the colour, so a critical finding stands out.
        self.assertEqual(attachment["color"], "#f85149")

    def test_03_slack_uses_the_severity_colour(self):
        recorder = _Recorder(200)
        with self._patch(recorder):
            asyncio.run(
                NotificationDispatcher.send_slack_alert(
                    "https://hooks.slack.test/abc", "T", "low", "e", "d"
                )
            )
        self.assertEqual(recorder.last["json"]["attachments"][0]["color"], "#58a6ff")

    def test_04_slack_reports_failure_for_a_non_200(self):
        recorder = _Recorder(500)
        with self._patch(recorder):
            result = asyncio.run(
                NotificationDispatcher.send_slack_alert(
                    "https://hooks.slack.test/abc", "T", "HIGH", "e", "d"
                )
            )
        self.assertFalse(result)

    def test_05_slack_swallows_a_transport_error(self):
        async def boom(*args, **kwargs):
            raise RuntimeError("network down")

        with patch("httpx.AsyncClient.post", new=boom):
            result = asyncio.run(
                NotificationDispatcher.send_slack_alert(
                    "https://hooks.slack.test/abc", "T", "HIGH", "e", "d"
                )
            )
        self.assertFalse(result)

    # -- signed webhook ---------------------------------------------------
    def test_06_custom_webhook_without_a_url_does_nothing(self):
        result = asyncio.run(
            NotificationDispatcher.send_custom_webhook("", "event", {"a": 1})
        )
        self.assertFalse(result)

    def test_07_custom_webhook_posts_the_payload_and_the_event_header(self):
        recorder = _Recorder(202)
        with self._patch(recorder):
            result = asyncio.run(
                NotificationDispatcher.send_custom_webhook(
                    "https://siem.test/hook", "finding.created", {"id": 7}
                )
            )
        self.assertTrue(result)
        url, kwargs = recorder.calls[0]
        self.assertEqual(url, "https://siem.test/hook")
        self.assertEqual(kwargs["headers"]["X-SWA-Event"], "finding.created")
        self.assertEqual(json.loads(kwargs["content"].decode("utf-8")), {"id": 7})

    def test_08_custom_webhook_signs_the_body_with_hmac_sha256(self):
        recorder = _Recorder(200)
        secret = "shhh"
        data = {"id": 7, "name": "example"}
        with self._patch(recorder):
            asyncio.run(
                NotificationDispatcher.send_custom_webhook(
                    "https://siem.test/hook", "finding.created", data, secret=secret
                )
            )
        body = recorder.last["content"]
        expected = hmac.new(
            secret.encode("utf-8"), body, hashlib.sha256
        ).hexdigest()
        self.assertEqual(recorder.last["headers"]["X-SWA-Signature"], f"sha256={expected}")

    def test_09_custom_webhook_omits_the_signature_without_a_secret(self):
        recorder = _Recorder(200)
        with self._patch(recorder):
            asyncio.run(
                NotificationDispatcher.send_custom_webhook(
                    "https://siem.test/hook", "finding.created", {"id": 7}
                )
            )
        self.assertNotIn("X-SWA-Signature", recorder.last["headers"])

    def test_10_custom_webhook_accepts_the_accepted_status_codes(self):
        for status in (200, 201, 202, 204):
            with self.subTest(status=status):
                recorder = _Recorder(status)
                with self._patch(recorder):
                    result = asyncio.run(
                        NotificationDispatcher.send_custom_webhook(
                            "https://siem.test/hook", "e", {"a": 1}
                        )
                    )
                self.assertTrue(result)

    def test_11_custom_webhook_rejects_an_unexpected_status_code(self):
        recorder = _Recorder(500)
        with self._patch(recorder):
            result = asyncio.run(
                NotificationDispatcher.send_custom_webhook(
                    "https://siem.test/hook", "e", {"a": 1}
                )
            )
        self.assertFalse(result)

    def test_12_custom_webhook_swallows_a_transport_error(self):
        async def boom(*args, **kwargs):
            raise RuntimeError("network down")

        with patch("httpx.AsyncClient.post", new=boom):
            result = asyncio.run(
                NotificationDispatcher.send_custom_webhook(
                    "https://siem.test/hook", "e", {"a": 1}
                )
            )
        self.assertFalse(result)

    def test_13_custom_webhook_serialises_values_that_are_not_json(self):
        recorder = _Recorder(200)
        with self._patch(recorder):
            asyncio.run(
                NotificationDispatcher.send_custom_webhook(
                    "https://siem.test/hook", "e", {"when": datetime_stub()}
                )
            )
        body = json.loads(recorder.last["content"].decode("utf-8"))
        # ``default=str`` turns the value into its string form.
        self.assertEqual(body["when"], "2026-01-01 00:00:00")


def datetime_stub():
    from datetime import datetime

    return datetime(2026, 1, 1)


if __name__ == "__main__":
    unittest.main()
