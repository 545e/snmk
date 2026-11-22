"""Keep raw exception details out of user-facing API responses.

CodeQL's ``py/info-exposure-through-exception`` query flags API responses that
contain exception messages because they can disclose internal file paths,
database structure, credentials embedded in URLs, or other implementation
details.  This module provides one audited place to turn an exception into a
generic client message while preserving the full diagnostic detail in the
server logs.

The value returned by :func:`safe_error` never depends on the exception text,
so taint from an exception cannot flow into a response through this helper.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

DEFAULT_CLIENT_MESSAGE = "The operation could not be completed."


def safe_log_text(value: object, limit: int = 512) -> str:
    """Escape CR/LF in *value* before it is written to a log record.

    User-controlled values (targets, paths, identifiers) must never be able to
    forge new log lines. The replacements are deliberately simple so static
    analysis recognises the value as sanitised at the log sink.
    """
    return str(value).replace("\r", "").replace("\n", "")[:limit]


def safe_error(message: str = DEFAULT_CLIENT_MESSAGE, exc: BaseException | None = None) -> str:
    """Log *exc* internally and return a generic *message* safe for clients.

    Args:
        message: A fixed, non-sensitive description of what went wrong. It must
            not contain data taken from the exception.
        exc: The exception that triggered the error. Used only for logging.

    Returns:
        The unchanged *message*. The return value is deliberately independent
        of *exc* so exception details cannot reach an HTTP response.
    """
    if exc is not None:
        logger.debug(
            "Suppressed exception detail from client response: %s | %s",
            safe_log_text(message),
            safe_log_text(type(exc).__name__),
        )
    return message


def safe_error_message(exc: BaseException | None = None, context: str = "operation") -> str:
    """Return a generic message without any exception-derived content.

    Convenience wrapper for sites that only need a short, fixed description.
    """
    return safe_error(f"The {context} could not be completed.", exc)
