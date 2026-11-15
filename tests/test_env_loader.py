"""
Tests for the ``.env`` loader.

``core/env_loader.py`` reads secrets and configuration out of the
repository-root ``.env`` file into the process environment, so its
behaviour around quoting, comments and pre-existing variables matters.
"""

import os
import tempfile
import unittest
from pathlib import Path

from core.env_loader import load_env_file


class TestEnvLoader(unittest.TestCase):
    def setUp(self):
        self._saved = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._saved)

    def _write(self, content: str) -> str:
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".env", delete=False, encoding="utf-8"
        )
        handle.write(content)
        handle.close()
        self.addCleanup(lambda: Path(handle.name).unlink(missing_ok=True))
        return handle.name

    def test_01_missing_file_is_not_an_error(self):
        applied = load_env_file(os.path.join(tempfile.gettempdir(), "definitely-not-here.env"))
        self.assertEqual(applied, {})

    def test_02_simple_pairs_are_loaded(self):
        path = self._write("SWA_TEST_ONE=alpha\nSWA_TEST_TWO=beta\n")
        applied = load_env_file(path)
        self.assertEqual(applied["SWA_TEST_ONE"], "alpha")
        self.assertEqual(applied["SWA_TEST_TWO"], "beta")
        self.assertEqual(os.environ["SWA_TEST_ONE"], "alpha")

    def test_03_comments_and_blank_lines_are_skipped(self):
        path = self._write(
            "# a comment\n"
            "\n"
            "   \n"
            "SWA_TEST_COMMENTED=value\n"
        )
        applied = load_env_file(path)
        self.assertEqual(applied, {"SWA_TEST_COMMENTED": "value"})

    def test_04_export_prefix_is_accepted(self):
        path = self._write("export SWA_TEST_EXPORT=exported\n")
        applied = load_env_file(path)
        self.assertEqual(applied["SWA_TEST_EXPORT"], "exported")

    def test_05_lines_without_an_equals_sign_are_skipped(self):
        path = self._write("SWA_TEST_OK=ok\nnot a pair\n")
        applied = load_env_file(path)
        self.assertEqual(applied, {"SWA_TEST_OK": "ok"})

    def test_06_empty_keys_are_skipped(self):
        path = self._write("=value\nSWA_TEST_OK=ok\n")
        applied = load_env_file(path)
        self.assertEqual(applied, {"SWA_TEST_OK": "ok"})

    def test_07_quoted_values_are_unquoted(self):
        path = self._write(
            'SWA_TEST_DOUBLE="double"\n'
            "SWA_TEST_SINGLE='single'\n"
        )
        applied = load_env_file(path)
        self.assertEqual(applied["SWA_TEST_DOUBLE"], "double")
        self.assertEqual(applied["SWA_TEST_SINGLE"], "single")

    def test_08_values_keep_their_inner_quotes(self):
        path = self._write('SWA_TEST_INNER="a"b"\n')
        applied = load_env_file(path)
        self.assertEqual(applied["SWA_TEST_INNER"], 'a"b')

    def test_09_existing_variables_are_not_overridden(self):
        os.environ["SWA_TEST_EXISTING"] = "original"
        path = self._write("SWA_TEST_EXISTING=replacement\n")
        applied = load_env_file(path)
        self.assertNotIn("SWA_TEST_EXISTING", applied)
        self.assertEqual(os.environ["SWA_TEST_EXISTING"], "original")

    def test_10_override_replaces_an_existing_variable(self):
        os.environ["SWA_TEST_EXISTING"] = "original"
        path = self._write("SWA_TEST_EXISTING=replacement\n")
        applied = load_env_file(path, override=True)
        self.assertEqual(applied["SWA_TEST_EXISTING"], "replacement")
        self.assertEqual(os.environ["SWA_TEST_EXISTING"], "replacement")

    def test_11_a_value_may_contain_an_equals_sign(self):
        path = self._write("SWA_TEST_URL=https://example.test/a?b=c\n")
        applied = load_env_file(path)
        self.assertEqual(applied["SWA_TEST_URL"], "https://example.test/a?b=c")

    def test_12_carriage_returns_are_stripped(self):
        path = self._write("SWA_TEST_CRLF=windows\r\n")
        applied = load_env_file(path)
        self.assertEqual(applied["SWA_TEST_CRLF"], "windows")


if __name__ == "__main__":
    unittest.main()
