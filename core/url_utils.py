"""
Safe URL helpers for CodeQL 'Incomplete URL substring sanitization' fixes.

The vulnerable pattern is::

    if "example.com" in url.lower() or url.startswith("https://example.com"):
        ...

An attacker can satisfy either check with a different host, e.g.
``https://example.com.attacker.tld`` or ``https://attacker.tld/?x=example.com``.
All host decisions in SNMK must go through the helpers below, which parse the
URL and compare the *hostname* with dot-boundary semantics.
"""

from __future__ import annotations

from urllib.parse import urlsplit

__all__ = ["safe_hostname", "host_matches", "is_expected_redirect"]


def safe_hostname(value: str | None) -> str:
    """Return a lowercase hostname from an absolute, scheme-relative or bare URL.

    Returns an empty string when the value cannot yield a hostname. Never
    raises on attacker-controlled input.
    """
    if not value or not isinstance(value, str):
        return ""
    raw = value.strip()
    if not raw:
        return ""
    # Scheme-relative redirects (//host/path) have no scheme in urlsplit.
    candidate = raw if "://" in raw else ("https:" + raw if raw.startswith("//") else "https://" + raw)
    try:
        host = (urlsplit(candidate).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""
    # urlsplit.hostname may include userinfo tricks; reject credentials.
    try:
        parsed = urlsplit(candidate)
        if parsed.username or parsed.password or "@" in parsed.netloc:
            return ""
    except ValueError:
        return ""
    return host


def host_matches(hostname: str, expected: str, *, allow_subdomains: bool = False) -> bool:
    """Exact (or dot-boundary subdomain) comparison of two hostnames."""
    hostname = (hostname or "").lower().rstrip(".")
    expected = (expected or "").lower().rstrip(".")
    if not hostname or not expected:
        return False
    if hostname == expected:
        return True
    return allow_subdomains and hostname.endswith("." + expected)


def is_expected_redirect(location: str, expected_host: str, *, scheme: str | None = None) -> bool:
    """True only when *location* resolves to *expected_host*.

    ``scheme`` optionally restricts the scheme (used to distinguish a genuine
    ``https://`` redirect from a protocol-relative ``//`` one).
    """
    raw = (location or "").strip()
    if not raw:
        return False
    if "://" in raw:
        try:
            if scheme and urlsplit(raw).scheme.lower() != scheme:
                return False
        except ValueError:
            return False
    return host_matches(safe_hostname(raw), expected_host)
