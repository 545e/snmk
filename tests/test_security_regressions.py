"""Regression tests for the security defects confirmed during the DSA audit.

Each test corresponds to a confirmed defect that was fixed; they exist so
that the defect cannot silently come back.

* DSA-CYB-09 - the lab-target decision was a substring test on the raw
  target, which let a remote URL bypass the human-approval gate.
* DSA-BE-12  - the prompt, the retrieved session history and the RAG
  grounding context were forwarded to a third-party LLM provider unscrubbed.
* DSA-BE-13  - the agent-memory metadata blob was persisted unscrubbed.
* DSA-AI-06  - the heuristic fallback asserted ``verified=True`` and
  fabricated "validated through active probe" evidence.
* DSA-CYB-01 - the SQL error signature corpus backtracks quadratically on
  attacker-controlled response bodies.
"""

import pytest

from core.agent_memory import redact_secrets_from_text
from core.llm_client import SWALLMClient
from core.scope_policy import scope_policy
from core.signature_matching import SignatureMatcher
from core.sqli_engine import DB_ENGINE_SIGNATURES


# ---------------------------------------------------------------------------
# DSA-CYB-09 - lab-target detection must use the parsed hostname
# ---------------------------------------------------------------------------
class TestLabTargetDetection:
    @pytest.mark.parametrize("target,expected", [
        ("127.0.0.1", True),
        ("127.0.0.1:8000", True),
        ("http://127.0.0.1:8000", True),
        ("localhost", True),
        ("http://localhost:3000", True),
        ("http://[::1]:8000", True),
        # A remote URL that merely *mentions* a lab host is not a lab host.
        ("https://evil.example/?ref=http://localhost", False),
        ("https://evil.example/?x=127.0.0.1", False),
        ("https://127.0.0.1.evil.example/", False),
        ("https://notlocalhost.com/", False),
        ("https://mylocalhost.com/", False),
        ("https://example.com/", False),
        ("https://localhost.evil.example/", False),
    ])
    def test_is_lab_target(self, target, expected):
        assert scope_policy.is_lab_target(target) is expected

    def test_substring_target_does_not_bypass_approval_gate(self):
        """The old check was ``"localhost" in target``."""
        target = "https://evil.example/?ref=http://localhost"
        old_result = "localhost" in target
        assert old_result is True          # the vulnerable behaviour
        assert scope_policy.is_lab_target(target) is False  # the fixed behaviour


# ---------------------------------------------------------------------------
# DSA-BE-12 / DSA-BE-13 - credential scrubbing
# ---------------------------------------------------------------------------
class TestSecretScrubbing:
    @pytest.mark.parametrize("secret", [
        "sk-abcdefghijklmnopqrstuvwxyz012345",
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "AKIA1234567890ABCDEF",
        "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
        "Set-Cookie: session=abcdefghijklmnopqrstuvwxyz",
    ])
    def test_known_secret_shapes_are_redacted(self, secret):
        assert "REDACTED" in redact_secrets_from_text(f"token is {secret} end")

    def test_jwt_is_redacted(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop"
        assert "REDACTED" in redact_secrets_from_text(f"auth {jwt}")

    def test_llm_transmission_is_scrubbed(self, monkeypatch):
        """Nothing that leaves the process may contain a credential."""
        import asyncio

        client = SWALLMClient(provider="heuristic")
        captured = {}

        async def fake_call(prompt, history=None, system_instruction=None):
            captured["prompt"] = prompt
            captured["history"] = history
            captured["system"] = system_instruction
            return "ok"

        monkeypatch.setattr(client, "_call_llm", fake_call)

        asyncio.run(client.reason(
            prompt="my key is sk-abcdefghijklmnopqrstuvwxyz012345",
            system_instruction="system sk-ant-abcdefghijklmnopqrstuvwxyz0123456789",
        ))

        blob = " ".join([
            captured.get("prompt") or "",
            captured.get("system") or "",
            str(captured.get("history") or ""),
        ])
        assert "sk-abcdefghijklmnopqrstuvwxyz012345" not in blob
        assert "sk-ant-abcdefghijklmnopqrstuvwxyz0123456789" not in blob
        assert "REDACTED" in blob

    def test_memory_metadata_is_scrubbed(self, tmp_path, monkeypatch):
        """The metadata blob is persisted verbatim unless it is scrubbed."""
        import core.agent_memory as am

        rows = []

        class FakeConn:
            row_factory = None

            def cursor(self):
                return self

            def execute(self, sql, params=()):
                rows.append((sql, params))
                return self

            def commit(self):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        class FakeDB:
            def get_connection(self):
                return FakeConn()

        monkeypatch.setattr(am, "db", FakeDB())
        store = am.AgentMemoryStore.__new__(am.AgentMemoryStore)

        store.record_turn(
            session_id="s1",
            agent_id="a1",
            role="user",
            content="hello",
            metadata={"auth": "Bearer ghp_abcdefghijklmnopqrstuvwxyz0123456789"},
        )

        assert rows, "no memory row was written"
        written = str(rows[0][1])
        assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789" not in written
        assert "REDACTED" in written


# ---------------------------------------------------------------------------
# DSA-AI-06 - the heuristic fallback must not fabricate verification
# ---------------------------------------------------------------------------
class TestHeuristicHonesty:
    def test_heuristic_analysis_does_not_claim_verification(self):
        client = SWALLMClient(provider="heuristic")
        result = client._heuristic_poc_analysis(
            finding_title="SQL Injection in login form",
            endpoint="http://example.com/login",
            request_data="",
            response_data="",
        )
        assert result["verified"] is False
        assert result["source"] == "heuristic"
        assert result["evidence_observed"] is False
        assert "Validated through active probe" not in result["explanation"]
        # The severity mapping itself is unchanged.
        assert result["cvss_score"] == 9.8
        assert result["owasp_category"] == "A03:2021-Injection"


# ---------------------------------------------------------------------------
# DSA-CYB-01 - the signature corpus must not backtrack quadratically
# ---------------------------------------------------------------------------
class TestSignatureMatchingSafety:
    def test_quadratic_body_is_handled_promptly(self):
        import time

        patterns = [p for pats in DB_ENGINE_SIGNATURES.values() for p in pats]
        matcher = SignatureMatcher(patterns)
        body = "Warning " * 4000  # 32 KB, no "mysql_" literal present
        t0 = time.perf_counter()
        assert matcher.matches(body) is False
        elapsed = time.perf_counter() - t0
        # The naive scan needs ~5 s for this body; the gate needs milliseconds.
        assert elapsed < 1.0, f"gate did not prefilter the pattern ({elapsed:.3f}s)"

    def test_detection_is_unchanged(self):
        patterns = [p for pats in DB_ENGINE_SIGNATURES.values() for p in pats]
        matcher = SignatureMatcher(patterns)
        assert matcher.matches("PostgreSQL.*ERROR") is True
        assert matcher.matches("sqlite3.OperationalError: no such table") is True
        assert matcher.matches("completely clean response") is False
