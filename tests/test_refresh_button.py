"""Regression test for the dashboard "Refresh assessments" button.

The background ``loadScans()`` call fired on dashboard init used to grab
``#refreshScansBtn`` through the fallback selector, disable it, and leave it
disabled until its slow request settled -- so on page load the button appeared
greyed out / broken.  The fix makes button locking happen only for genuine user
clicks, and adds a watchdog so the button can never be stuck disabled.

These assertions pin that behavior in the shipped static asset so it cannot
silently regress.
"""

import os
import re

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_JS = os.path.join(REPO, "web", "static", "app.js")

with open(APP_JS, encoding="utf-8") as fh:
    APP_JS_SRC = fh.read()


def _load_scans_source():
    match = re.search(
        r"async function loadScans\(triggerBtn\)\s*\{.*?\n\}\s*\n",
        APP_JS_SRC,
        re.S,
    )
    assert match, "loadScans definition not found in app.js"
    return match.group(0)


class TestRefreshButton:
    def test_background_refresh_does_not_lock_the_button(self):
        """Only a real DOM trigger button may be locked, never the fallback."""
        src = _load_scans_source()
        assert "const btn = (triggerBtn && triggerBtn.nodeType) ? triggerBtn : null;" in src, (
            "loadScans must only disable the button passed by a user click; "
            "the document.getElementById fallback reintroduced the stuck-button bug"
        )
        assert "getElementById('refreshScansBtn')" not in src

    def test_watchdog_guards_against_a_stuck_disabled_button(self):
        src = _load_scans_source()
        assert "_refreshWatchdog" in src, "missing watchdog safety net"
        assert "setTimeout" in src and "clearTimeout" in src

    def test_finally_always_releases_the_button_and_clears_watchdog(self):
        src = _load_scans_source()
        finally_block = re.search(r"finally\s*\{(.*?)\n\s*\}", src, re.S)
        assert finally_block, "loadScans finally block not found"
        body = finally_block.group(1)
        assert "btn.disabled = false" in body
        assert "clearTimeout(btn._refreshWatchdog)" in body

    def test_report_button_wires_modal_open_handler(self):
        """The Recent Assessments Report button must open its format modal."""
        assert "onclick=\"openReportFormatModal('${s.id}')\"" in APP_JS_SRC
        assert re.search(r"function openReportFormatModal\(scanId\)", APP_JS_SRC)
