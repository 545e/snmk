"""
Unit and Integration Tests for SNMK Enterprise Exceptions and Standard Error Envelopes.
"""

from fastapi.testclient import TestClient

from core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    LLMProviderError,
    SecurityScopeError,
    SNMKError,
    StandardErrorEnvelope,
    ToolExecutionError,
)
from web.server import app


def test_snmk_base_exception():
    err = SNMKError("Base failure", error_code="SYS_ERR", details={"key": "val"})
    assert str(err) == "Base failure"
    assert err.error_code == "SYS_ERR"
    assert err.details == {"key": "val"}


def test_security_scope_error():
    err = SecurityScopeError("Target out of authorized scope", target="169.254.169.254")
    assert err.error_code == "SECURITY_SCOPE_VIOLATION"
    assert err.details["target"] == "169.254.169.254"


def test_auth_and_authz_errors():
    auth_err = AuthenticationError("Token expired")
    assert auth_err.error_code == "AUTHENTICATION_REQUIRED"

    authz_err = AuthorizationError("Admin access required", required_role="secops_lead")
    assert authz_err.error_code == "AUTHORIZATION_REFUSAL"
    assert authz_err.details["required_role"] == "secops_lead"


def test_tool_and_llm_errors():
    tool_err = ToolExecutionError("Process terminated", tool_id="nmap", exit_code=1)
    assert tool_err.error_code == "TOOL_EXECUTION_FAILURE"
    assert tool_err.details["tool_id"] == "nmap"
    assert tool_err.details["exit_code"] == 1

    llm_err = LLMProviderError("Rate limit reached", provider="anthropic")
    assert llm_err.error_code == "LLM_PROVIDER_ERROR"
    assert llm_err.details["provider"] == "anthropic"


def test_standard_error_envelope_creation():
    envelope = StandardErrorEnvelope.create(
        code="TEST_ERROR",
        message="A test error occurred",
        request_id="req-123456",
        details={"module": "test"}
    )
    assert envelope["success"] is False
    assert envelope["error"]["code"] == "TEST_ERROR"
    assert envelope["error"]["message"] == "A test error occurred"
    assert envelope["error"]["request_id"] == "req-123456"
    assert envelope["error"]["details"] == {"module": "test"}
    assert "timestamp" in envelope


def test_request_correlation_id_middleware():
    client = TestClient(app)
    # Request without correlation ID header
    res1 = client.get("/health")
    assert "X-Request-ID" in res1.headers
    assert res1.headers["X-Request-ID"].startswith("req-")

    # Request with custom correlation ID header
    res2 = client.get("/health", headers={"X-Request-ID": "custom-trace-id-999"})
    assert res2.headers["X-Request-ID"] == "custom-trace-id-999"
