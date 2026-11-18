"""
Unit and Integration Tests for SNMK Enterprise Environment Security and Loader.
"""

from core.env_loader import (
    get_bool,
    get_int,
    get_masked_config,
    get_str,
    is_sensitive_key,
    mask_secret,
    validate_environment,
)


def test_sensitive_key_detection():
    assert is_sensitive_key("SWA_API_KEY") is True
    assert is_sensitive_key("DATABASE_PASSWORD") is True
    assert is_sensitive_key("JWT_SECRET") is True
    assert is_sensitive_key("OPENAI_API_KEY") is True
    assert is_sensitive_key("ANTHROPIC_TOKEN") is True
    assert is_sensitive_key("SWA_HOST") is False
    assert is_sensitive_key("SWA_PORT") is False


def test_secret_masking():
    # Short secret
    assert mask_secret("short") == "********"
    assert mask_secret("12345678") == "********"

    # Longer secret
    masked = mask_secret("sk-proj-supersecretkey123456789")
    assert masked.startswith("sk-")
    assert masked.endswith("789")
    assert "..." in masked
    assert "supersecret" not in masked

    # None / Empty
    assert mask_secret(None) == ""
    assert mask_secret("") == ""


def test_typed_env_getters(monkeypatch):
    monkeypatch.setenv("TEST_STR", "  hello_snmk  ")
    monkeypatch.setenv("TEST_BOOL_TRUE", "true")
    monkeypatch.setenv("TEST_BOOL_ON", "on")
    monkeypatch.setenv("TEST_BOOL_FALSE", "0")
    monkeypatch.setenv("TEST_INT", "8080")
    monkeypatch.setenv("TEST_INT_INVALID", "invalid")

    assert get_str("TEST_STR") == "hello_snmk"
    assert get_str("NONEXISTENT", default="def") == "def"

    assert get_bool("TEST_BOOL_TRUE") is True
    assert get_bool("TEST_BOOL_ON") is True
    assert get_bool("TEST_BOOL_FALSE") is False
    assert get_bool("NONEXISTENT", default=True) is True

    assert get_int("TEST_INT") == 8080
    assert get_int("TEST_INT_INVALID", default=9000) == 9000
    assert get_int("NONEXISTENT", default=443) == 443


def test_masked_config_never_exposes_raw_secrets(monkeypatch):
    monkeypatch.setenv("SWA_API_KEY", "ultra_sensitive_production_api_key_value")
    monkeypatch.setenv("SWA_HOST", "127.0.0.1")

    masked = get_masked_config()
    assert "SWA_API_KEY" in masked
    assert "ultra_sensitive_production_api_key_value" not in masked["SWA_API_KEY"]
    assert masked["SWA_API_KEY"] == mask_secret("ultra_sensitive_production_api_key_value")
    assert masked["SWA_HOST"] == "127.0.0.1"


def test_validate_environment():
    val = validate_environment(strict_production=False)
    assert "valid" in val
    assert "issues" in val
    assert "warnings" in val
    assert "config_summary" in val
    assert val["config_summary"]["port"] >= 1
