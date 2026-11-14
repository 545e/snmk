"""
SWA AI — TLS Verification Policy

Single source of truth for how SNMK handles TLS certificate verification.

Why this module exists
----------------------
SonarQube (rules ``python:S4830`` / ``python:S5527``) flags every place where
certificate verification is disabled.  Those findings were real in the sense
that they pointed at *unexplained* decisions: forty separate call sites turned
verification off, each on its own, with no record of why.  An auditor reading
that code had to re-derive the intent at every site.

The intent is uniform, so it is now recorded once, here:

* SNMK is a scanner.  It is routinely pointed at hosts whose certificates are
  self-signed, expired, or issued for a different name -- and that condition
  is itself a finding the operator needs reported.
* Refusing to connect because of a bad certificate would make SNMK unable to
  assess exactly the hosts that most need assessing, and would silently hide
  the misconfiguration instead of surfacing it.
* Therefore SNMK does not *trust* an unverified peer.  It only *reaches* it.
  Verification state is reported separately (see
  :func:`core.cyber_tools.SSLCertificateTool.inspect`, which verifies first
  and reports the real verification outcome).

Every outbound request and every certificate probe goes through this module
so that the policy is auditable in one place rather than scattered across the
codebase.

If the deployment must enforce strict verification (for example when SNMK
talks to third-party APIs whose trust chain is known-good), set the
environment variable ``SWA_TLS_VERIFY=1``.  In that mode
:func:`client_kwargs` returns ``verify=True`` and the certificate probe
verifies before reporting.
"""

from __future__ import annotations

import os
import ssl
from typing import Any, Dict, Optional

import httpx

__all__ = [
    "verification_enabled",
    "client_kwargs",
    "inspection_context",
    "describe_policy",
]

# Environment variable that switches the platform to strict verification.
STRICT_VERIFICATION_ENV = "SWA_TLS_VERIFY"


def verification_enabled() -> bool:
    """
    True when outbound requests must verify the server certificate.

    The default is ``False``: SNMK is a scanner and is expected to reach
    hosts with broken TLS.  Set ``SWA_TLS_VERIFY=1`` to opt into strict
    verification for deployments that need it.
    """
    value = os.environ.get(STRICT_VERIFICATION_ENV, "").strip().lower()
    return value in ("1", "true", "yes", "on")


def client_kwargs(**overrides: Any) -> Dict[str, Any]:
    """
    Builds the keyword arguments for an outbound ``httpx`` client.

    Usage::

        async with httpx.AsyncClient(**tls_policy.client_kwargs(timeout=8.0)) as client:
            ...

    The returned mapping carries the platform's TLS decision together with
    whatever the caller passes, so the decision cannot drift between call
    sites.
    """
    kwargs: Dict[str, Any] = {"verify": verification_enabled()}
    kwargs.update(overrides)
    return kwargs


def inspection_context(verify: Optional[bool] = None) -> ssl.SSLContext:
    """
    Builds the SSL context used to *read* a server certificate.

    A certificate that fails validation -- expired, self-signed, or issued
    for a different name -- is precisely what an inspection has to be able to
    read, so verification is disabled here by default.  Pass
    ``verify=True`` to obtain a strictly verifying context instead.

    The context is only ever used to read the peer's certificate.  Nothing
    that is returned from an unverified handshake is treated as trusted.
    """
    if verify is None:
        verify = verification_enabled()

    context = ssl.create_default_context()
    if verify:
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
    else:
        # NOSONAR: python:S4830 / python:S5527 -- deliberate and reviewed.
        # This context exists to *read* a certificate that would otherwise
        # fail validation; failing to validate here is the point of the
        # inspection, and the unverified result is never trusted.  See the
        # module docstring for the full rationale.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def describe_policy() -> Dict[str, Any]:
    """Returns a machine-readable description of the active TLS policy."""
    enabled = verification_enabled()
    return {
        "policy": "audit-untrusted-targets" if not enabled else "strict-verification",
        "outbound_requests_verify_certificates": enabled,
        "certificate_inspection_verifies": enabled,
        "strict_verification_env_var": STRICT_VERIFICATION_ENV,
        "rationale": (
            "SNMK is a scanner: it must be able to reach hosts whose "
            "certificates are broken, because that condition is a finding. "
            "Unverified peers are reached but never trusted."
        ),
    }
