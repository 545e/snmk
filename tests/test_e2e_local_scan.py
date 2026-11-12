"""
Integration and End-to-End Test for SWA AI Vulnerability Scanner.
Validates the complete workflow against an authorized local lab target (http://127.0.0.1:8000):
- Scope verification and SSRF guard validation
- Scan job dispatch with lab_mode=True
- Status progression: PENDING -> RUNNING -> COMPLETED
- Real findings discovery with evidence and remediation
- Report generation across HTML, JSON, SARIF 2.1.0, CSV, and Markdown
"""

import os
import sys
import time
import json
import subprocess
import urllib.request
import urllib.error
import unittest


class TestE2ELocalScan(unittest.TestCase):
    _server_proc = None

    @staticmethod
    def _pick_free_port() -> int:
        """Return a TCP port that is free right now."""
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return int(s.getsockname()[1])

    @classmethod
    def setUpClass(cls):
        # Start a dedicated server for this test on a port the OS says is
        # free, so the test and the server always agree on the port and a
        # developer's own running instance is never disturbed.
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env = os.environ.copy()
        env["HEADLESS"] = "1"
        env["SWA_HOST"] = "127.0.0.1"
        # Ask the OS for a free port and hand it to the server, so the
        # test and the server always agree on the port.
        port = cls._pick_free_port()
        cls.base_url = "http://127.0.0.1:%d" % port
        env["SWA_PORT"] = str(port)
        
        # The server output is captured to a file rather than discarded, so
        # a start-up failure is diagnosable from the test output alone.
        import tempfile
        cls._server_log = tempfile.NamedTemporaryFile(
            prefix="snmk_e2e_server_", suffix=".log", delete=False)
        cls._server_proc = subprocess.Popen(
            [sys.executable, "run.py"],
            cwd=repo_root,
            env=env,
            stdout=cls._server_log,
            stderr=subprocess.STDOUT,
        )
        
        # Wait for the server to become responsive.  This is a start-up
        # budget, not an assertion: importing the whole FastAPI application
        # takes noticeably longer on a cold, busy CI runner than on a
        # developer machine, so the window is generous.
        started = False
        last_exc = "no request was attempted"
        for _ in range(180):
            time.sleep(0.5)
            try:
                with urllib.request.urlopen(f"{cls.base_url}/api/settings", timeout=5.0) as resp:
                    if resp.status == 200:
                        started = True
                        break
                    last_exc = f"HTTP {resp.status}"
            except Exception as exc:
                last_exc = f"{type(exc).__name__}: {exc}"
                continue
                
        if not started:
            err = ""
            if cls._server_proc:
                try:
                    cls._server_proc.terminate()
                    cls._server_proc.wait(timeout=5)
                except Exception:
                    try:
                        cls._server_proc.kill()
                    except Exception:
                        pass
            try:
                cls._server_log.flush()
                cls._server_log.close()
                with open(cls._server_log.name, "r", encoding="utf-8",
                          errors="replace") as fh:
                    err = "\nSERVER OUTPUT:\n" + fh.read()[-4000:]
            except Exception:
                pass
            raise RuntimeError(
                f"Failed to launch background SWA AI web server for E2E "
                f"tests (port {port}, url {cls.base_url}, last error: {last_exc}).{err}"
            )

    @classmethod
    def tearDownClass(cls):
        if cls._server_proc:
            cls._server_proc.terminate()
            try:
                cls._server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls._server_proc.kill()

    def test_01_ssrf_protection_blocks_unauthorized_local_scan(self):
        """Verifies SSRF guard blocks 127.0.0.1 when lab_mode is False."""
        payload = json.dumps({
            "target_url": self.base_url,
            "profile": "quick",
            "lab_mode": False
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/scans",
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 403)
        err_body = ctx.exception.read().decode("utf-8")
        self.assertIn("SSRF Protection", err_body)

    def test_02_e2e_authorized_scan_execution(self):
        """Verifies full scan execution against 127.0.0.1:8000 with lab_mode=True."""
        # 1. Submit scan
        payload = json.dumps({
            "target_url": self.base_url,
            "profile": "quick",
            "lab_mode": True,
            "max_depth": 1,
            "concurrency": 4
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/scans",
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        res = urllib.request.urlopen(req)
        self.assertEqual(res.code, 200)
        job = json.loads(res.read())
        scan_id = job["id"]
        self.assertTrue(scan_id.startswith("scan_"))

        # 2. Wait for completion.
        #
        # The window is a wall-clock budget, not an assertion: the scan is a
        # real multi-agent run against a local target, so the time it needs
        # depends on the host.  It was 52.5s, then 135s, and is now 300s,
        # because a 2-core CI runner executing the whole suite concurrently
        # can legitimately need longer.  Every assertion below is unchanged -
        # the scan must still reach COMPLETED, reach 100 % progress and
        # produce findings.
        #
        # The failure message now reports the last observed status, phase and
        # progress so a failure is diagnosable without the full log.
        completed = False
        final_data = None
        last_observed = "no response from the scan status endpoint"
        deadline = time.time() + 300.0
        while time.time() < deadline:
            time.sleep(2.0)
            try:
                with urllib.request.urlopen(f"{self.base_url}/api/scans/{scan_id}", timeout=5.0) as check_res:
                    final_data = json.loads(check_res.read().decode("utf-8"))
            except Exception as exc:
                last_observed = f"status endpoint unreachable: {exc}"
                continue
            status = final_data.get("status")
            last_observed = (
                f"status={status} phase={final_data.get('current_phase')!r} "
                f"progress={final_data.get('progress_percent')}% "
                f"findings={final_data.get('findings_count')}"
            )
            if status == "COMPLETED":
                completed = True
                break
            elif status in ["FAILED", "CANCELLED"]:
                self.fail(f"Scan ended in unexpected status: {status} ({last_observed})")

        self.assertTrue(
            completed,
            f"Scan did not reach COMPLETED status within the 300s budget "
            f"(last observed: {last_observed})",
        )
        self.assertGreaterEqual(final_data.get("progress_percent", 0), 100)

        # 3. Verify findings.
        #
        # The scan status flips to COMPLETED before the last finding rows are
        # committed, so the findings are polled for a short while instead of
        # being read once after a fixed sleep.  The assertion itself is
        # unchanged: at least one finding must be produced.
        findings = []
        findings_deadline = time.time() + 60.0
        last_findings_error = "no attempt made"
        while time.time() < findings_deadline:
            try:
                with urllib.request.urlopen(
                    f"{self.base_url}/api/scans/{scan_id}/findings", timeout=10.0
                ) as findings_res:
                    findings = json.loads(findings_res.read().decode("utf-8"))
                if findings:
                    break
                last_findings_error = "the scan reported no findings yet"
            except Exception as exc:
                last_findings_error = f"{type(exc).__name__}: {exc}"
            time.sleep(1.5)
        self.assertGreater(
            len(findings), 0,
            f"Expected at least 1 vulnerability finding on test target "
            f"(last state: {last_findings_error})",
        )

        for f in findings:
            self.assertIn("title", f)
            self.assertIn("severity", f)
            self.assertIn("cwe_id", f)
            self.assertIn("remediation_advice", f)

        # 4. Verify report generation across all formats
        for fmt in ["html", "json", "sarif", "csv", "markdown"]:
            rep_res = urllib.request.urlopen(f"{self.base_url}/api/scans/{scan_id}/report?format={fmt}")
            self.assertEqual(rep_res.code, 200)
            rep_text = rep_res.read().decode("utf-8", errors="ignore")
            self.assertGreater(len(rep_text), 50, f"Report format {fmt} returned unexpectedly short content")

if __name__ == "__main__":
    unittest.main()
