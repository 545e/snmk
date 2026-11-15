"""
Tests for the TLS verification policy.

``core/tls_policy.py`` is the single place where SNMK decides whether to
verify a server certificate.  Because that decision is security-relevant and
because the rest of the codebase routes through it, the policy itself is
tested directly here.
"""

import os
import ssl
import unittest
from pathlib import Path
from unittest.mock import patch

from core import tls_policy


class TestTLSVerificationPolicy(unittest.TestCase):
    def tearDown(self):
        os.environ.pop(tls_policy.STRICT_VERIFICATION_ENV, None)

    # -- the switch -------------------------------------------------------
    def test_01_verification_is_disabled_by_default(self):
        """A scanner must be able to reach hosts with broken certificates."""
        os.environ.pop(tls_policy.STRICT_VERIFICATION_ENV, None)
        self.assertFalse(tls_policy.verification_enabled())

    def test_02_verification_can_be_switched_on(self):
        for value in ("1", "true", "TRUE", "yes", "on"):
            with self.subTest(value=value):
                os.environ[tls_policy.STRICT_VERIFICATION_ENV] = value
                self.assertTrue(tls_policy.verification_enabled())

    def test_03_unrecognised_values_leave_verification_off(self):
        for value in ("0", "false", "no", "", "maybe"):
            with self.subTest(value=value):
                os.environ[tls_policy.STRICT_VERIFICATION_ENV] = value
                self.assertFalse(tls_policy.verification_enabled())

    # -- outbound requests ------------------------------------------------
    def test_04_client_kwargs_carry_the_policy_decision(self):
        os.environ.pop(tls_policy.STRICT_VERIFICATION_ENV, None)
        kwargs = tls_policy.client_kwargs(timeout=8.0)
        self.assertFalse(kwargs["verify"])
        self.assertEqual(kwargs["timeout"], 8.0)

    def test_05_client_kwargs_respect_strict_mode(self):
        os.environ[tls_policy.STRICT_VERIFICATION_ENV] = "1"
        self.assertTrue(tls_policy.client_kwargs()["verify"])

    def test_06_client_kwargs_let_the_caller_override(self):
        """A caller may still pass its own value; the mapping is a dict."""
        kwargs = tls_policy.client_kwargs(verify=True, timeout=1.0)
        self.assertTrue(kwargs["verify"])
        self.assertEqual(kwargs["timeout"], 1.0)

    def test_07_client_kwargs_produce_a_usable_httpx_client(self):
        import asyncio

        import httpx

        kwargs = tls_policy.client_kwargs(timeout=3.0, follow_redirects=True)
        client = httpx.AsyncClient(**kwargs)
        try:
            self.assertEqual(client.timeout.connect, 3.0)
            self.assertTrue(client.follow_redirects)
        finally:
            asyncio.run(client.aclose())

    # -- certificate inspection -------------------------------------------
    def test_08_inspection_context_can_read_a_broken_certificate(self):
        """The default context must not validate, or it could not read one."""
        os.environ.pop(tls_policy.STRICT_VERIFICATION_ENV, None)
        context = tls_policy.inspection_context()
        self.assertFalse(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)

    def test_09_inspection_context_can_be_strict(self):
        context = tls_policy.inspection_context(verify=True)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_10_inspection_context_follows_the_policy_by_default(self):
        os.environ[tls_policy.STRICT_VERIFICATION_ENV] = "1"
        context = tls_policy.inspection_context()
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    # -- the description --------------------------------------------------
    def test_11_describe_policy_reports_the_active_policy(self):
        os.environ.pop(tls_policy.STRICT_VERIFICATION_ENV, None)
        description = tls_policy.describe_policy()
        self.assertEqual(description["policy"], "audit-untrusted-targets")
        self.assertFalse(description["outbound_requests_verify_certificates"])
        self.assertIn("rationale", description)

        os.environ[tls_policy.STRICT_VERIFICATION_ENV] = "1"
        description = tls_policy.describe_policy()
        self.assertEqual(description["policy"], "strict-verification")
        self.assertTrue(description["outbound_requests_verify_certificates"])

    def test_12_describe_policy_names_the_environment_variable(self):
        self.assertEqual(
            tls_policy.describe_policy()["strict_verification_env_var"],
            tls_policy.STRICT_VERIFICATION_ENV,
        )

    # -- the callers route through it -------------------------------------
    def test_13_no_module_disables_verification_on_its_own(self):
        """
        No module may turn verification off without going through the policy.

        This is the guard that keeps the scattered ``verify=False`` calls
        from coming back.  The check is made on the parsed syntax tree, so
        that example code inside a string literal -- for instance a
        remediation snippet that is handed to the operator -- is not
        mistaken for a real connection.
        """
        import ast
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent
        offenders = []

        for path in root.rglob("*.py"):
            if any(
                part in (".venv", ".git", "__pycache__", "node_modules")
                for part in path.parts
            ):
                continue
            if path.name == "tls_policy.py" or path.name == Path(__file__).name:
                continue

            try:
                tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
            except SyntaxError:
                continue

            relative = str(path.relative_to(root))
            for node in ast.walk(tree):
                # verify=False passed as a keyword argument
                if isinstance(node, ast.Call):
                    for keyword in node.keywords:
                        if (
                            keyword.arg == "verify"
                            and isinstance(keyword.value, ast.Constant)
                            and keyword.value.value is False
                        ):
                            offenders.append((relative, node.lineno, "verify=False"))
                # context.check_hostname = False
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if (
                            isinstance(target, ast.Attribute)
                            and target.attr == "check_hostname"
                            and isinstance(node.value, ast.Constant)
                            and node.value.value is False
                        ):
                            offenders.append(
                                (relative, node.lineno, "check_hostname = False")
                            )
                # context.verify_mode = ssl.CERT_NONE
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if (
                            isinstance(target, ast.Attribute)
                            and target.attr == "verify_mode"
                            and isinstance(node.value, ast.Attribute)
                            and node.value.attr == "CERT_NONE"
                        ):
                            offenders.append(
                                (relative, node.lineno, "verify_mode = ssl.CERT_NONE")
                            )

        self.assertEqual(
            offenders, [],
            f"TLS verification is disabled outside core/tls_policy.py: {offenders}",
        )


if __name__ == "__main__":
    unittest.main()
