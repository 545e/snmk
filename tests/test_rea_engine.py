"""
Unit tests for SWA AI REA (Reverse Engineer Anything) Engine.
Verifies truthful availability reporting, target path validation,
path traversal & sensitive OS file protection, explicit authorization enforcement,
and native fallback inspection for SQLite, JavaScript, and binary artifacts.
"""

import logging
import asyncio
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.rea_engine import REAEngine


class TestREAEngine(unittest.TestCase):
    def setUp(self):
        self.engine = REAEngine()
        self.temp_dir = tempfile.TemporaryDirectory()
        # The analyser may only read from an allowed root; the artefacts
        # under test live in the temporary directory, so it is declared as
        # the allowed root for the duration of the test.
        root_patch = patch.dict(
            os.environ, {"SWA_REA_ALLOWED_ROOTS": self.temp_dir.name}
        )
        root_patch.start()
        self.addCleanup(root_patch.stop)

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            logging.getLogger(__name__).debug("Suppressed exception (audited empty handler)", exc_info=True)

    def test_check_availability_schema(self):
        status = REAEngine.check_availability()
        self.assertIn("installed", status)
        self.assertIn("binary_path", status)
        self.assertIn("runtime_environment", status)
        self.assertIn("install_guide", status)
        self.assertIn("supported_target_types", status)
        self.assertIn("native_fallback_available", status)
        self.assertIsInstance(status["installed"], bool)
        self.assertIsInstance(status["runtime_environment"], dict)
        self.assertIn("node_installed", status["runtime_environment"])
        self.assertTrue(status["native_fallback_available"])

    def test_path_validation_and_blocking(self):
        # Valid path: a file inside the allowed analysis root.
        allowed = Path(self.temp_dir.name) / "sample.bin"
        allowed.write_bytes(b"sample")
        valid, path, err = REAEngine.validate_target_path(str(allowed))
        self.assertTrue(valid)
        self.assertIsNone(err)
        self.assertEqual(os.path.normcase(path), os.path.normcase(str(allowed.resolve())))

        # Empty path
        valid, _, err = REAEngine.validate_target_path("")
        self.assertFalse(valid)
        self.assertIn("empty", err.lower())

        # Null byte injection
        valid, _, err = REAEngine.validate_target_path("test\0bad.db")
        self.assertFalse(valid)
        self.assertIn("null byte", err.lower())

        # Nonexistent path
        valid, _, err = REAEngine.validate_target_path("C:\\nonexistent_dir_12345\\file.exe")
        self.assertFalse(valid)
        self.assertIn("does not exist", err.lower())
        # Blocked sensitive system paths
        blocked_samples = [
            r"C:\Windows\System32\config\SAM",
            r"C:\Windows\System32\config\SYSTEM",
            "/etc/shadow",
            "/etc/passwd",
            r"C:\Users\admin\.ssh\id_rsa",
            r"C:\Users\admin\.aws\credentials",
            r"C:\project\.env"
        ]
        for b_path in blocked_samples:
            valid, _, err = REAEngine.validate_target_path(b_path)
            self.assertFalse(valid, f"Path should be blocked: {b_path}")
            self.assertIn("sensitive system paths", err.lower())

    def test_path_outside_the_allowed_roots_is_refused(self):
        """The analyser may only read from the declared analysis roots."""
        outside = Path(self.temp_dir.name).parent / "outside_rea_target.bin"
        outside.write_bytes(b"not evidence")
        try:
            valid, _, err = REAEngine.validate_target_path(str(outside))
            self.assertFalse(valid, "A path outside the allowed roots must be refused")
            self.assertIn("allowed analysis roots", err.lower())
        finally:
            outside.unlink(missing_ok=True)

    def test_allowed_roots_can_be_configured(self):
        """SWA_REA_ALLOWED_ROOTS replaces the defaults."""
        with tempfile.TemporaryDirectory() as other:
            marker = Path(other) / "target.bin"
            marker.write_bytes(b"x")
            with patch.dict(os.environ, {"SWA_REA_ALLOWED_ROOTS": other}):
                valid, _, err = REAEngine.validate_target_path(str(marker))
                self.assertTrue(valid, err)

    def test_infer_target_type(self):
        self.assertEqual(REAEngine.infer_target_type("sample.js"), "javascript")
        self.assertEqual(REAEngine.infer_target_type("bundle.asar"), "javascript")
        self.assertEqual(REAEngine.infer_target_type("data.sqlite3"), "sqlite")
        self.assertEqual(REAEngine.infer_target_type("capture.pcapng"), "pcap")
        self.assertEqual(REAEngine.infer_target_type("agent.exe"), "binary")
        self.assertEqual(REAEngine.infer_target_type("lib.so"), "binary")

    def test_authorization_enforced(self):
        # Attempting analysis without authorization must raise PermissionError
        with self.assertRaises(PermissionError):
            asyncio.run(self.engine.analyze(__file__, authorized=False))

    def test_sqlite_fallback_analysis(self):
        # Create a test SQLite database
        db_path = os.path.join(self.temp_dir.name, "test_lab.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, api_token TEXT)")
        cur.execute("CREATE TABLE audit_logs (id INTEGER PRIMARY KEY, action TEXT, ts TIMESTAMP)")
        cur.execute("INSERT INTO users VALUES (1, 'sec_admin', 'secret-tok-999')")
        conn.commit()
        conn.close()

        result = asyncio.run(self.engine.analyze(db_path, target_type="sqlite", authorized=True, force_native=True))
        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["target_type"], "sqlite")
        self.assertIn("metadata", result)
        self.assertIn("tables", result["metadata"])
        self.assertIn("users", result["metadata"]["tables"])
        self.assertIn("audit_logs", result["metadata"]["tables"])
        self.assertEqual(result["metadata"]["table_count"], 2)

    def test_javascript_fallback_analysis(self):
        # Create a test JS file
        js_path = os.path.join(self.temp_dir.name, "bundle.js")
        js_content = """
        // Frontend Auth Bridge
        const API_KEY = "dummy-dev-key-1234";
        function authenticateUser(token) {
            fetch('/api/v1/auth/verify', { method: 'POST', body: JSON.stringify({ token }) });
        }
        function openAdminShell() {
            console.log("shell requested");
        }
        module.exports = { authenticateUser, openAdminShell };
        """
        with open(js_path, "w", encoding="utf-8") as f:
            f.write(js_content)

        result = asyncio.run(self.engine.analyze(js_path, target_type="javascript", authorized=True, force_native=True))
        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["target_type"], "javascript")
        self.assertIn("metadata", result)
        self.assertIn("discovered_api_routes", result["metadata"])
        self.assertIn("/api/v1/auth/verify", result["metadata"]["discovered_api_routes"])
        self.assertIn("exported_symbols", result["metadata"])

    def test_binary_fallback_analysis(self):
        # Create a minimal simulated PE header (MZ header)
        pe_path = os.path.join(self.temp_dir.name, "sample.exe")
        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        # Pointer to PE signature at offset 0x3C
        dos_header[0x3C:0x40] = (64).to_bytes(4, byteorder="little")
        # PE signature and minimal COFF header
        pe_sig = b"PE\x00\x00"
        coff_header = b"\x64\x86" + (4).to_bytes(2, byteorder="little") + (0).to_bytes(16, byteorder="little")
        with open(pe_path, "wb") as f:
            f.write(dos_header + pe_sig + coff_header + (b"\x00" * 256))

        result = asyncio.run(self.engine.analyze(pe_path, target_type="binary", authorized=True, force_native=True))
        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["target_type"], "binary")
        self.assertIn("metadata", result)
        self.assertEqual(result["metadata"].get("format"), "PE (Portable Executable)")
        self.assertEqual(result["metadata"].get("architecture"), "x64 (64-bit)")


if __name__ == "__main__":
    unittest.main()
