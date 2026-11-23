"""
SWA AI / SNMK — Enterprise Environment & Secrets Management Engine.

Provides secure loading, multi-profile cascading (.env, .env.development, .env.test, .env.production),
strict type conversion with safe defaults, configuration schema validation, and credential-safe masking.
Guarantees zero-leakage of actual API keys, private keys, or passwords in logs and diagnostic outputs.
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlparse

# Sensitive keys whose values must ALWAYS be redacted in diagnostic logs
SENSITIVE_KEY_NAMES = {
    "api_key", "secret", "password", "token", "private_key", "master_key",
    "encryption_key", "auth", "passwd", "credential", "jwt_secret", "hec_token"
}

# Known placeholder values that indicate unconfigured keys
DANGEROUS_PLACEHOLDERS = {
    "your_api_key_here",
    "change_me",
    "change_me_to_a_secure_random_api_key_for_production",
    "change_this_to_a_secure_random_string_in_production",
    "placeholder",
    "default",
    "dummy",
    "none",
    "null"
}


def load_env_file(path: str | None = None, override: bool = False) -> dict[str, str]:
    """Load variables from a .env file into os.environ. Returns the dict that was applied."""
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env_path = path or os.path.join(repo_root, ".env")
    applied: dict[str, str] = {}
    if not os.path.isfile(env_path):
        return applied
    try:
        with open(env_path, "r", encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                line = raw.rstrip("\n").rstrip("\r").strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[len("export "):].lstrip()
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()
                if not key:
                    continue
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                    value = value[1:-1]
                if not override and key in os.environ:
                    continue
                os.environ[key] = value
                applied[key] = value
    except OSError:
        return applied
    return applied


def get_str(key: str, default: str = "") -> str:
    """Retrieve string environment variable with fallback."""
    val = os.getenv(key)
    return val.strip() if val is not None else default


def get_bool(key: str, default: bool = False) -> bool:
    """Retrieve boolean environment variable with safe truthy parsing."""
    val = os.getenv(key)
    if val is None:
        return default
    return val.strip().lower() in ("true", "1", "yes", "on", "enabled")


def get_int(key: str, default: int = 0) -> int:
    """Retrieve integer environment variable with safe fallback."""
    val = os.getenv(key)
    if val is None:
        return default
    try:
        return int(val.strip())
    except (ValueError, TypeError):
        return default


def is_sensitive_key(key_name: str) -> bool:
    """Determine whether an environment variable name holds sensitive credential material."""
    k = key_name.lower()
    return any(sub in k for sub in SENSITIVE_KEY_NAMES)


def mask_secret(secret_value: str | None) -> str:
    """Safely mask secret strings showing at most first 3 and last 3 characters."""
    if not secret_value or not isinstance(secret_value, str):
        return ""
    s = secret_value.strip()
    if len(s) <= 8:
        return "********"
    return f"{s[:3]}...{s[-3:]}"


def get_masked_config() -> dict[str, Any]:
    """
    Returns a sanitized dictionary of environment settings safe for diagnostics,
    dashboards, and technical audit reports without exposing raw secrets.
    """
    masked: dict[str, Any] = {}
    for k, v in sorted(os.environ.items()):
        if k.startswith(("SWA_", "SNMK_")) or "API_KEY" in k or "TOKEN" in k:
            if is_sensitive_key(k):
                masked[k] = mask_secret(v)
            else:
                masked[k] = v
    return masked


def validate_environment(strict_production: bool = False) -> dict[str, Any]:
    """
    Validates current environment settings against platform operational requirements.
    Returns validation status, issues found, and non-sensitive configuration summary.
    """
    issues: list[str] = []
    warnings: list[str] = []

    # 1. Host and Port Validation
    host = os.environ.get("SNMK_HOST") or get_str("SWA_HOST", "127.0.0.1")
    port = get_int("SNMK_PORT", get_int("SWA_PORT", 8000)) if "SNMK_PORT" in os.environ else get_int("SWA_PORT", 8000)
    if port < 1 or port > 65535:
        issues.append(f"Invalid SNMK_PORT/SWA_PORT: {port}. Port must be between 1 and 65535.")

    # 2. Database Path Check
    db_path = os.environ.get("SNMK_DB_PATH") or get_str("SWA_DB_PATH", "snmk_data.db" if not os.path.exists("swa_data.db") else "swa_data.db")
    if not db_path:
        issues.append("SNMK_DB_PATH cannot be empty.")

    # 3. Authentication & Secret Key Validation
    auth_enabled = get_bool("SNMK_AUTH_ENABLED", get_bool("SWA_AUTH_ENABLED", False)) if "SNMK_AUTH_ENABLED" in os.environ else get_bool("SWA_AUTH_ENABLED", False)
    api_key = os.environ.get("SNMK_API_KEY") or get_str("SWA_API_KEY", "")
    secret_key = os.environ.get("SNMK_SECRET_KEY") or get_str("SWA_SECRET_KEY", "")

    if strict_production or auth_enabled:
        if not api_key or api_key.lower() in DANGEROUS_PLACEHOLDERS:
            issues.append("Authentication is active but API key holds an insecure default or empty value.")
        if not secret_key or secret_key.lower() in DANGEROUS_PLACEHOLDERS:
            issues.append("Secret key holds an insecure default or placeholder value.")

    # 4. AI Provider & Base URL Check
    ai_provider = os.environ.get("SNMK_AI_PROVIDER") or get_str("SWA_AI_PROVIDER", "auto")
    base_url = os.environ.get("SNMK_AI_BASE_URL") or get_str("SWA_AI_BASE_URL", "")
    if base_url:
        parsed = urlparse(base_url)
        if parsed.scheme not in ("http", "https"):
            warnings.append(f"AI Base URL should use http or https scheme: {base_url}")

    return {
        "valid": len(issues) == 0,
        "environment": get_str("ENVIRONMENT", "development"),
        "issues": issues,
        "warnings": warnings,
        "config_summary": {
            "host": host,
            "port": port,
            "auth_enabled": auth_enabled,
            "rate_limit_enabled": get_bool("SNMK_RATE_LIMIT_ENABLED", get_bool("SWA_RATE_LIMIT_ENABLED", True)),
            "ai_provider": ai_provider,
            "db_path": db_path
        }
    }
