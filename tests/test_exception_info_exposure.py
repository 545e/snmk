"""Regression coverage for CodeQL py/info-exposure-through-exception fixes.

Exception messages must stay in server-side logs and never appear in values
returned to API clients.
"""

from core.error_sanitizer import safe_error
from core.digital_forensics import PhotoRecCarver


SENSITIVE = "/srv/secret/private-key.pem: permission denied (user=admin)"


def test_safe_error_never_returns_exception_text():
    exc = RuntimeError(SENSITIVE)
    result = safe_error("Operation failed.", exc)
    assert result == "Operation failed."
    assert SENSITIVE not in result
    assert "permission denied" not in result


def test_safe_error_return_is_independent_of_exception_presence():
    message = "Provider is unavailable."
    assert safe_error(message) == message
    assert safe_error(message, RuntimeError(SENSITIVE)) == message


def test_safe_error_context_is_caller_authored_only():
    exc = ValueError(SENSITIVE)
    result = safe_error("Handler 'core.example:run' could not be executed.", exc)
    assert result == "Handler 'core.example:run' could not be executed."
    assert SENSITIVE not in result


def test_forensics_browse_error_is_generic(tmp_path, monkeypatch):
    root = tmp_path / "evidence"
    root.mkdir()
    monkeypatch.setenv("SWA_EVIDENCE_ROOT", str(root))

    carver = PhotoRecCarver()
    secret_dir = tmp_path / "secret_vault"
    result = carver.browse_directory(str(secret_dir))

    assert result["error"] == "The requested path is outside the evidence root."
    assert "secret_vault" not in result["error"]
    assert str(tmp_path) not in result["error"]
