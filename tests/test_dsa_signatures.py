"""Tests for the repository-wide DSA utilities.

Covers:
  * ``core.pattern_gating``  - required-literal gate derivation and filtering.
  * ``core.signature_matching`` - localised, semantics-preserving signature
    matching (the SQL-error corpus).
  * ``core.js_intelligence`` - the JavaScript secret scanner, including the
    line index and the required-literal gate.

The gate is a *necessary* condition for a match, so the central invariant is:
"a pattern that the gate rejects can never match".  These tests assert that
invariant directly.
"""

import re

import pytest

from core.pattern_gating import (
    GateFilter,
    required_literal_groups,
    required_literal_runs,
    select_gate,
)
from core.signature_matching import SignatureMatcher, build_line_index
from core.sqli_engine import DB_ENGINE_SIGNATURES


# --------------------------------------------------------------------------
# core.pattern_gating
# --------------------------------------------------------------------------
class TestRequiredLiteralDerivation:
    def test_plain_literal(self):
        assert required_literal_groups(r"AKIA[0-9A-Z]{16}") == [frozenset({"AKIA"})]

    def test_literal_terminating_pattern(self):
        # A pattern that ends with a bare literal used to be mis-parsed.
        assert required_literal_groups("mysql_") == [frozenset({"mysql_"})]

    def test_two_required_literals(self):
        groups = required_literal_groups(r"Warning.*mysql_.*")
        assert groups == [frozenset({"Warning"}), frozenset({"mysql_"})]

    def test_alternation_intersection(self):
        groups = required_literal_groups(
            r"(?:client[_\s-]?secret|consumer[_\s-]?secret|app[_\s-]?secret)"
        )
        assert groups == [
            frozenset({"client", "consumer", "app"}),
            frozenset({"secret"}),
        ]

    def test_optional_element_contributes_nothing(self):
        # `abc` is optional -> it is not a required literal.
        assert required_literal_groups(r"(?:abc)?mysql_") == [frozenset({"mysql_"})]

    def test_lookahead_inherits_constraint(self):
        groups = required_literal_groups(r"(?=[A-Z]{3})AKIA")
        assert frozenset({"AKIA"}) in groups

    def test_negative_lookahead_contributes_nothing(self):
        groups = required_literal_groups(r"(?!xyz)AKIA")
        assert frozenset({"AKIA"}) in groups

    def test_character_class_is_not_a_literal(self):
        assert required_literal_groups(r"[A-Z]{16}") == []

    def test_unknown_construct_is_conservative(self):
        # A back reference cannot be reasoned about -> no constraint at all.
        assert required_literal_groups(r"(a)\1mysql_") == []

    def test_runs_and_select_gate(self):
        assert "AKIA" in required_literal_runs(r"AKIA[0-9A-Z]{16}")
        assert select_gate(r"AKIA[0-9A-Z]{16}") == "AKIA"
        assert select_gate(r"[A-Z]{16}") is None

    def test_short_literals_are_rejected(self):
        # Literals shorter than MIN_GATE_LENGTH are too common to be useful.
        assert required_literal_groups(r"ab[cdef]") == []


class TestGateFilter:
    def test_absent_literal_blocks_pattern(self):
        gf = GateFilter([r"AKIA[0-9A-Z]{16}"])
        assert gf.should_run(0, "no aws key here") is False
        assert gf.should_run(0, "AKIA1234567890ABCDEF") is True

    def test_case_insensitive(self):
        gf = GateFilter([r"AKIA[0-9A-Z]{16}"])
        assert gf.should_run(0, "AKIA1234567890ABCDEF") is True

    def test_all_groups_must_be_satisfied(self):
        gf = GateFilter([r"Warning.*mysql_.*"])
        assert gf.should_run(0, "Warning something") is False
        assert gf.should_run(0, "mysql_ only") is False
        assert gf.should_run(0, "Warning mysql_") is True

    def test_alternation_group_needs_only_one_alternative(self):
        gf = GateFilter([r"(?:client|consumer|app)[_\s-]?secret"])
        assert gf.should_run(0, "app_secret") is True
        assert gf.should_run(0, "nothing here") is False

    def test_empty_text_runs_everything(self):
        gf = GateFilter([r"AKIA[0-9A-Z]{16}"])
        assert gf.should_run(0, "") is True

    def test_prefolded_input_matches(self):
        gf = GateFilter([r"AKIA[0-9A-Z]{16}"])
        text = "AKIA1234567890ABCDEF"
        assert gf.should_run(0, text, text.lower()) is True


# --------------------------------------------------------------------------
# core.signature_matching
# --------------------------------------------------------------------------
SQLI_PATTERNS = [p for pats in DB_ENGINE_SIGNATURES.values() for p in pats]


def _naive_match(patterns, body):
    return any(re.search(p, body, re.IGNORECASE) for p in patterns)


class TestSignatureMatcher:
    @pytest.mark.parametrize("body", [
        "Warning mysql_ something",
        "warning MYSQL_ thing",
        "PostgreSQL ERROR occurred",
        "valid MySQL result",
        "MySqlClient. exception",
        "Npgsql. driver error",
        "SqlException raised",
        "sqlite3.OperationalError: nope",
        "SQLite/JDBCDriver",
        "ORA-12345: bad",
        "syntax error near 'x'",
        "no database error at all",
        "",
    ])
    def test_matches_naive_implementation(self, body):
        matcher = SignatureMatcher(SQLI_PATTERNS)
        assert matcher.matches(body) == _naive_match(SQLI_PATTERNS, body)

    def test_engine_attribution_preserved(self):
        """The matcher must report the same engine as the naive scan."""
        from core.sqli_engine import SQLiEngine

        engine = SQLiEngine()
        for body in [
            "SQL syntax.*MySQL",
            "PostgreSQL.*ERROR",
            "ORA-12345:",
            "sqlite3.OperationalError",
            "unrelated body",
        ]:
            expected = None
            for eng, pats in DB_ENGINE_SIGNATURES.items():
                if any(re.search(p, body, re.IGNORECASE) for p in pats):
                    expected = eng
                    break
            assert engine.detect_db_engine(body) == expected, body

    def test_quadratic_pattern_is_prefiltered(self):
        """The classic ReDoS shape must not be executed when its literal is absent."""
        body = "Warning " * 2000
        matcher = SignatureMatcher(SQLI_PATTERNS)
        assert matcher.matches(body) is False

    def test_line_localisation_still_detects(self):
        body = "\n".join(["filler line"] * 50 + ["Warning mysql_ boom"] + ["x"] * 50)
        matcher = SignatureMatcher(SQLI_PATTERNS)
        assert matcher.matches(body) is True

    def test_search_index(self):
        matcher = SignatureMatcher(SQLI_PATTERNS)
        idx = matcher.search_index("PostgreSQL ERROR")
        assert idx is not None
        assert matcher.signatures[idx].source == r"PostgreSQL.*ERROR"

    def test_search_all(self):
        matcher = SignatureMatcher(SQLI_PATTERNS)
        hits = matcher.search_all("PostgreSQL.*ERROR")
        assert r"PostgreSQL.*ERROR" in hits


class TestLineIndex:
    def test_offsets_match_splitlines(self):
        for text in ["a\nb\nc", "a\r\nb", "a\rb", "single", "", "\n\n\n"]:
            offsets = build_line_index(text)
            assert offsets[0] == 0
            assert offsets[-1] <= len(text)

    def test_line_content(self):
        text = "alpha\nbeta\ngamma"
        offsets = build_line_index(text)
        assert text[offsets[1]:offsets[2]].strip() == "beta"


# --------------------------------------------------------------------------
# core.js_intelligence
# --------------------------------------------------------------------------
class TestJavaScriptSecretScanner:
    def test_finds_aws_key(self):
        from core.js_intelligence import JavaScriptSecretScanner

        scanner = JavaScriptSecretScanner()
        findings = scanner.scan("const k = 'AKIA1234567890ABCDEF';")
        assert any(f["name"] == "AWS Access Key" for f in findings)

    def test_line_numbers_are_correct(self):
        from core.js_intelligence import JavaScriptSecretScanner

        scanner = JavaScriptSecretScanner()
        text = "line one\nline two\nconst k = 'AKIA1234567890ABCDEF';\nline four"
        findings = scanner.scan(text)
        aws = [f for f in findings if f["name"] == "AWS Access Key"]
        assert aws and aws[0]["line"] == 3

    def test_line_numbers_with_crlf(self):
        from core.js_intelligence import JavaScriptSecretScanner

        scanner = JavaScriptSecretScanner()
        text = "line one\r\nline two\r\nconst k = 'AKIA1234567890ABCDEF';"
        findings = scanner.scan(text)
        aws = [f for f in findings if f["name"] == "AWS Access Key"]
        assert aws and aws[0]["line"] == 3

    def test_no_findings_on_clean_text(self):
        from core.js_intelligence import JavaScriptSecretScanner

        scanner = JavaScriptSecretScanner()
        assert scanner.scan("const x = 1; function f(){ return 2; }") == []

    def test_shared_compiled_table(self):
        """The signature table is compiled once and shared between instances."""
        from core.js_intelligence import JavaScriptSecretScanner

        a = JavaScriptSecretScanner()
        b = JavaScriptSecretScanner()
        assert a.compiled_patterns is b.compiled_patterns

    def test_gate_never_rejects_a_matching_pattern(self):
        """The central invariant of the required-literal gate.

        For every signature and a corpus of realistic secrets, a pattern that
        the gate rejects must not produce any match.
        """
        from core.js_intelligence import (
            GHOSTJS_RAW_PATTERNS,
            JavaScriptSecretScanner,
        )

        corpus = [
            "AKIA1234567890ABCDEF",
            "const k = 'AKIA1234567890ABCDEF';",
            "ghp_" + "a" * 36,
            "xoxb-12345678901-12345678901-" + "b" * 24,
            "sk_live_" + "c" * 20,
            "AIzaSyD-" + "d" * 33,
            "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
            "mongodb://user:pass123456@host.example.com:27017/db",
            "nothing interesting here",
        ]

        scanner = JavaScriptSecretScanner()
        gate_filter = scanner.gate_filter

        for body in corpus:
            lowered = body.lower()
            for idx, meta in enumerate(GHOSTJS_RAW_PATTERNS):
                raw = meta["regex"].encode().decode("unicode_escape")
                flags = 0
                if "i" in meta["flags"]:
                    flags |= re.IGNORECASE
                if "s" in meta["flags"]:
                    flags |= re.DOTALL
                if "m" in meta["flags"]:
                    flags |= re.MULTILINE
                matches = [
                    m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                    for m in re.compile(raw, flags).finditer(body)
                ]
                if not gate_filter.should_run(idx, body, lowered):
                    assert not matches, (
                        f"gate rejected {meta['name']!r} but it matched {matches!r}"
                    )
