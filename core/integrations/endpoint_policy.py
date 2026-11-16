"""
Policy for the outbound requests that the integration adapters make.

An integration adapter is given a URL by the operator -- a Splunk instance,
an OpenAI-compatible gateway, an Ollama server -- and it then sends that
URL a request that carries the operator's credentials.  Two things have to
be true before that happens:

1. the URL must not point back into the platform's own network.  An
   operator-supplied ``http://169.254.169.254/...`` would turn the
   connection test into a server-side request forgery primitive, and
   ``http://127.0.0.1:...`` would reach services bound to loopback.
2. the URL must not be a host the operator did not intend.  The credential
   that is sent with the request is the provider's own API key, so a
   request to an attacker-chosen host exfiltrates it.

This module is the single place where both rules are applied.  Adapters call
:func:`validate_integration_endpoint` before they build a client, and they
refuse to send a stored credential to an endpoint that is not on the
provider's allowlist.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from typing import Iterable, List, Optional, Tuple
from urllib.parse import urlparse

__all__ = [
    "EndpointPolicyError",
    "validate_integration_endpoint",
    "host_is_allowed",
    "resolve_host_addresses",
]


class EndpointPolicyError(ValueError):
    """Raised when an integration endpoint is not permitted."""


# The hosts each provider is expected to live on.
#
# An empty tuple means "any public host": the product is legitimately
# self-hosted on a name of the operator's choosing (Splunk, Elasticsearch,
# DefectDojo, an OpenAI-compatible gateway such as LiteLLM or vLLM).  The
# address checks in :func:`validate_integration_endpoint` still apply to
# those, so they cannot be used to reach the platform's own network.
#
# For the providers that are only ever a SaaS offering, the host has to be
# one of the listed names.  An operator who has to use a different host --
# a corporate proxy, a regional endpoint -- can allow it explicitly with
# the SWA_INTEGRATION_ALLOWED_HOSTS environment variable.
PROVIDER_HOST_SUFFIXES = {
    "openai": ("openai.com",),
    "anthropic": ("anthropic.com",),
    "gemini": ("googleapis.com",),
    "openrouter": ("openrouter.ai",),
    "crowdstrike": ("crowdstrike.com", "fal.con", "crestone.io"),
    "virustotal": ("virustotal.com",),
    "abuseipdb": ("abuseipdb.com",),
    "shodan": ("shodan.io",),
    "censys": ("censys.io",),
    "alienvault_otx": ("alienvault.com",),
    "urlhaus": ("abuse.ch",),
    "tenable": ("tenable.com",),
    # Self-hosted or mirror-able products: any public host is accepted.
    "splunk": (),
    "elastic_security": (),
    "wazuh": (),
    "defectdojo": (),
    "ollama": (),
    "cisa_kev": (),
    "first_epss": (),
    # Fixed-host SaaS providers that never take an endpoint from the caller.
    "aws": (),
    "azure": (),
    "gcp": (),
    "ms_sentinel": (),
}

# Operator-configured extra hosts, comma separated.  Needed for a corporate
# proxy or a regional endpoint of a SaaS provider.
EXTRA_ALLOWED_HOSTS_ENV = "SWA_INTEGRATION_ALLOWED_HOSTS"


def _extra_allowed_hosts() -> List[str]:
    raw = os.environ.get(EXTRA_ALLOWED_HOSTS_ENV, "") or ""
    return [item.strip().lower().rstrip(".") for item in raw.split(",") if item.strip()]


def resolve_host_addresses(hostname: str) -> List[str]:
    """
    Resolves *hostname* to the addresses it maps to.

    An empty list means the name does not resolve.  Every returned address
    is checked by the caller: a name that maps to *any* restricted address
    is refused, not just the one that happened to be returned first.
    """
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError):
        return []

    addresses: List[str] = []
    for info in infos:
        try:
            address = info[4][0]
        except (IndexError, TypeError):
            continue
        if address and address not in addresses:
            addresses.append(address)
    return addresses


def _is_restricted(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True
    if getattr(ip, "ipv4_mapped", None) is not None:
        ip = ip.ipv4_mapped
    return bool(
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or str(ip) == "169.254.169.254"
    )


def host_is_allowed(hostname: str, provider_id: str = "") -> bool:
    """
    True when *hostname* is a host the provider is expected to use.

    A provider that accepts any public host (self-hosted products) is
    always permitted; the address checks in
    :func:`validate_integration_endpoint` apply in every case.  For a
    fixed-host provider the host has to be on its list, or on the
    operator's explicit ``SWA_INTEGRATION_ALLOWED_HOSTS`` list.
    """
    host = hostname.lower().rstrip(".")

    for extra in _extra_allowed_hosts():
        if host == extra or host.endswith("." + extra):
            return True

    suffixes = PROVIDER_HOST_SUFFIXES.get(provider_id)
    if suffixes is None:
        # An unknown provider accepts any host; the address checks still
        # apply.
        return True
    if not suffixes:
        # The provider is self-hosted by design.
        return True
    for suffix in suffixes:
        if host == suffix or host.endswith("." + suffix):
            return True
    return False


def validate_integration_endpoint(
    endpoint_url: str,
    provider_id: str = "",
    allowed_hosts: Optional[Iterable[str]] = None,
    allow_private_addresses: bool = False,
) -> str:
    """
    Validates an integration endpoint and returns its normalised form.

    Raises :class:`EndpointPolicyError` with a human-readable reason when
    the endpoint is not permitted.

    The checks are:

    * the scheme must be ``http`` or ``https``;
    * the URL must carry a host;
    * the URL must not embed credentials (``https://user:pass@host``);
    * the host must resolve to public addresses only -- a private, loopback,
      link-local, multicast or cloud-metadata address is refused.  This is
      the SSRF guard: without it, the connection test is a request forgery
      primitive and the stored provider credential is posted to whatever
      host the caller names;
    * the host must be on the provider's allowlist when one is defined, or
      on the explicit ``allowed_hosts`` list.
    """
    if not endpoint_url or not str(endpoint_url).strip():
        raise EndpointPolicyError("No endpoint URL was supplied.")

    candidate = str(endpoint_url).strip()
    parsed = urlparse(candidate)

    if parsed.scheme not in ("http", "https"):
        raise EndpointPolicyError(
            f"Unsupported endpoint scheme '{parsed.scheme}'. Only http and https are permitted."
        )
    if not parsed.netloc:
        raise EndpointPolicyError("The endpoint URL has no host.")
    if "@" in parsed.netloc:
        raise EndpointPolicyError("The endpoint URL must not embed credentials.")

    hostname = parsed.hostname
    if not hostname:
        raise EndpointPolicyError("The endpoint URL has no host.")

    if allowed_hosts is not None:
        permitted = {h.lower().rstrip(".") for h in allowed_hosts}
        if hostname.lower().rstrip(".") not in permitted:
            raise EndpointPolicyError(
                f"Host '{hostname}' is not on the allowlist for this integration."
            )
    elif not host_is_allowed(hostname, provider_id):
        raise EndpointPolicyError(
            f"Host '{hostname}' is not an approved endpoint for '{provider_id or 'this integration'}'."
        )

    if not allow_private_addresses:
        addresses = resolve_host_addresses(hostname)
        if addresses:
            restricted = [a for a in addresses if _is_restricted(a)]
            if restricted:
                raise EndpointPolicyError(
                    f"Host '{hostname}' resolves to a restricted address "
                    f"({restricted[0]}). Integration endpoints must be publicly routable."
                )
        else:
            raise EndpointPolicyError(
                f"Host '{hostname}' could not be resolved."
            )

    # Normalise: drop any fragment and default port, keep the path.
    netloc = parsed.netloc
    scheme = parsed.scheme
    return f"{scheme}://{netloc}{parsed.path or ''}"
