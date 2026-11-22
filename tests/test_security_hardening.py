"""Regression tests for the CodeQL-driven hardening changes."""

from fastapi.testclient import TestClient

from web.server import app

client = TestClient(app)

REQUIRED_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)


def test_all_responses_carry_defensive_headers():
    response = client.get("/health")
    assert response.status_code == 200
    for header in REQUIRED_HEADERS:
        assert response.headers.get(header), f"missing security header: {header}"


def test_security_headers_middleware_covers_error_responses():
    response = client.get("/api/definitely-not-a-real-endpoint")
    for header in REQUIRED_HEADERS:
        assert response.headers.get(header), f"missing header on error response: {header}"


def test_v1_tool_run_unknown_tool_is_reported_honestly():
    """The v1 route must not depend on a circular import from web.server."""
    response = client.post(
        "/api/v1/security-tools/run",
        json={"tool_id": "definitely-not-a-tool", "target": "127.0.0.1"},
    )
    assert response.status_code == 404
