"""
SNMK Enterprise Platform — Centralized Exception Hierarchy & Error Envelopes
Defines custom typed exceptions, standard error codes, and serialization models
to ensure consistent, credential-safe error handling across all backend services.
"""

from __future__ import annotations

import datetime
from typing import Any

from pydantic import BaseModel, Field


class SNMKError(Exception):
    """Base exception for all SNMK cybersecurity platform errors."""
    def __init__(self, message: str, error_code: str = "INTERNAL_ERROR", details: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}


class SecurityScopeError(SNMKError):
    """Raised when an operation targets an out-of-scope domain, IP, or cloud IMDS."""
    def __init__(self, message: str, target: str = "", details: dict[str, Any] | None = None):
        super().__init__(message, error_code="SECURITY_SCOPE_VIOLATION", details=details or {"target": target})


class AuthenticationError(SNMKError):
    """Raised when request lacks valid credentials or token is expired/invalid."""
    def __init__(self, message: str = "Authentication required or invalid credential", details: dict[str, Any] | None = None):
        super().__init__(message, error_code="AUTHENTICATION_REQUIRED", details=details)


class AuthorizationError(SNMKError):
    """Raised when authenticated user or agent lacks RBAC permissions for an action."""
    def __init__(self, message: str = "Insufficient privileges for requested action", required_role: str = "", details: dict[str, Any] | None = None):
        super().__init__(message, error_code="AUTHORIZATION_REFUSAL", details=details or {"required_role": required_role})


class ToolExecutionError(SNMKError):
    """Raised when an approved security tool fails, times out, or encounters execution fault."""
    def __init__(self, message: str, tool_id: str = "", exit_code: int | None = None, details: dict[str, Any] | None = None):
        d = details or {}
        if tool_id:
            d["tool_id"] = tool_id
        if exit_code is not None:
            d["exit_code"] = exit_code
        super().__init__(message, error_code="TOOL_EXECUTION_FAILURE", details=d)


class DatabaseStorageError(SNMKError):
    """Raised when database query, migration, or transaction integrity check fails."""
    def __init__(self, message: str, details: dict[str, Any] | None = None):
        super().__init__(message, error_code="DATABASE_ERROR", details=details)


class LLMProviderError(SNMKError):
    """Raised when AI/LLM upstream provider fails, times out, or returns invalid syntax."""
    def __init__(self, message: str, provider: str = "", details: dict[str, Any] | None = None):
        d = details or {}
        if provider:
            d["provider"] = provider
        super().__init__(message, error_code="LLM_PROVIDER_ERROR", details=d)


class WorkflowExecutionError(SNMKError):
    """Raised when an automation workflow step fails or encounters an unhandled condition."""
    def __init__(self, message: str, workflow_id: str = "", step_id: str = "", details: dict[str, Any] | None = None):
        d = details or {}
        if workflow_id:
            d["workflow_id"] = workflow_id
        if step_id:
            d["step_id"] = step_id
        super().__init__(message, error_code="WORKFLOW_EXECUTION_FAILURE", details=d)


class ConfigurationValidationError(SNMKError):
    """Raised when required environment settings or API configurations are invalid."""
    def __init__(self, message: str, invalid_keys: list[str] | None = None, details: dict[str, Any] | None = None):
        d = details or {}
        if invalid_keys:
            d["invalid_keys"] = invalid_keys
        super().__init__(message, error_code="CONFIGURATION_VALIDATION_ERROR", details=d)


class StandardErrorEnvelope(BaseModel):
    """Standardized error response model across all SNMK REST and WebSocket endpoints."""
    success: bool = False
    error: dict[str, Any] = Field(..., description="Error metadata containing code, message, and request_id")
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())

    @classmethod
    def create(cls, code: str, message: str, request_id: str = "", details: dict[str, Any] | None = None) -> dict[str, Any]:
        return {
            "success": False,
            "error": {
                "code": code,
                "message": message,
                "request_id": request_id,
                "details": details or {}
            },
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat()
        }
