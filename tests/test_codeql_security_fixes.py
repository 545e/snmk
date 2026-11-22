"""Regressions for the CodeQL High findings fixed on the main branch."""

from __future__ import annotations


from core.js_intelligence import EndpointAndStorageExtractor
from core.url_utils import host_matches, is_expected_redirect, safe_hostname


def test_safe_hostname_parses_and_rejects_userinfo():
    assert safe_hostname("https://Example.COM./path?q=1") == "example.com"
    assert safe_hostname("//example.com/path") == "example.com"
    assert safe_hostname("example.com/path") == "example.com"
    assert safe_hostname("https://user:pass@example.com/") == ""


def test_host_matches_uses_dot_boundary():
    assert host_matches("example.com", "example.com")
    assert host_matches("s3.amazonaws.com", "amazonaws.com", allow_subdomains=True)
    assert not host_matches("example.com.attacker.tld", "example.com", allow_subdomains=True)
    assert not host_matches("notexample.com", "example.com", allow_subdomains=True)


def test_redirect_check_cannot_be_bypassed_by_substring():
    assert is_expected_redirect("https://example.com/login", "example.com")
    assert is_expected_redirect("//example.com/login", "example.com")
    assert not is_expected_redirect("https://example.com.attacker.tld/", "example.com")
    assert not is_expected_redirect("https://attacker.tld/?next=https://example.com", "example.com")
    assert not is_expected_redirect("http://example.com/", "example.com", scheme="https")


def test_provider_classification_uses_hostname_not_substring():
    classify = EndpointAndStorageExtractor._classify_provider
    assert classify("https://bucket.s3.amazonaws.com/file") == "AWS S3"
    assert not classify("https://attacker.tld/?x=amazonaws.com") == "AWS S3"
    assert classify("https://attacker.tld/?x=amazonaws.com") == "Cloud Storage"
    assert classify("https://storage.googleapis.com/bucket") == "Google Cloud Storage"


def test_api_path_pattern_is_bounded_and_prefix_filtered():
    body = 'const a = "/api/v1/users"; const b = "/internal/admin"; const c = "/docs";'
    paths = [m.group(1) for m in EndpointAndStorageExtractor.API_PATH_PATTERN.finditer(body)]
    accepted = [p for p in paths if EndpointAndStorageExtractor.API_PATH_PREFIX.match(p)]
    assert accepted == ["/api/v1/users", "/internal/admin"]


def test_api_path_pattern_does_not_backtrack_on_long_input():
    # A pathological body must be processed in linear time (no nested quantifiers).
    body = "x" * 20000 + '"/api/v1/users"'
    matches = list(EndpointAndStorageExtractor.API_PATH_PATTERN.finditer(body))
    assert len(matches) == 1


def test_dangerous_scheme_signature_is_not_a_sanitizer():
    import benchmarks.run_polyglot_benchmarks as bench  # noqa: F401

    with open(bench.__file__, encoding="utf-8") as fh:
        source = fh.read()
    assert "(javascript|data):[^\\s]*" not in source


def test_evidence_root_confinement_still_enforced():
    from core.digital_forensics import confine_to_evidence_root

    try:
        confine_to_evidence_root("..\\..\\Windows\\win.ini")
    except ValueError:
        return
    # If the configured evidence root happens to allow it, ensure at least
    # the returned path stays inside the root.
    from core.digital_forensics import forensics_evidence_root

    resolved = confine_to_evidence_root("..\\..\\Windows\\win.ini")
    import os

    assert os.path.commonpath([str(forensics_evidence_root()), str(resolved)]) == str(
        forensics_evidence_root()
    )
