"""Deterministic, content-addressed asset versioning for the static UI.

The static assets were referenced with a hand-maintained query string
(``app.js?v=3.5.1``) that was never bumped when the files changed.  Browsers
therefore kept serving a **stale** ``app.js`` after a deployment, which
produced a UI whose behaviour no longer matched the server - for example the
tool-health popover showing tab counters that disagreed with the list it
rendered.

This module computes a short content hash per asset so the URL changes
exactly when the file changes:

    app.js?v=<sha256[:12] of app.js>

The result is that assets can be cached immutably (a changed file always has
a new URL) and a stale script can never be served.
"""

from __future__ import annotations

import hashlib
import os
import re
from typing import Dict, Optional

__all__ = ["asset_versions", "version_for", "inject_asset_versions"]

_VERSION_RE = re.compile(
    r"([A-Za-z0-9_.\-/]+\.(?:js|css))(\?v=[0-9A-Za-z._-]+)?"
)

# Only these assets participate; other files are served normally.
_VERSIONED_EXTENSIONS = (".js", ".css")


def _hash_file(path: str) -> Optional[str]:
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()[:12]
    except OSError:
        return None


def asset_versions(static_dir: str) -> Dict[str, str]:
    """Return ``{filename: short content hash}`` for the versioned assets."""
    versions: Dict[str, str] = {}
    try:
        names = sorted(os.listdir(static_dir))
    except OSError:
        return versions
    for name in names:
        if not name.endswith(_VERSIONED_EXTENSIONS):
            continue
        digest = _hash_file(os.path.join(static_dir, name))
        if digest:
            versions[name] = digest
    return versions


def version_for(static_dir: str, filename: str, cache: Optional[Dict[str, str]] = None) -> str:
    """Return the version token for ``filename``.

    ``cache`` may be a dict used to memoise the per-file hashes; it is keyed by
    the absolute file path and the file's mtime + size so a changed file is
    re-hashed.
    """
    path = os.path.join(static_dir, filename)
    try:
        st = os.stat(path)
        stamp = (st.st_mtime_ns, st.st_size)
    except OSError:
        return "0"
    if cache is not None:
        entry = cache.get(path)
        if entry and entry[0] == stamp:
            return entry[1]
    digest = _hash_file(path) or "0"
    if cache is not None:
        cache[path] = (stamp, digest)
    return digest


def inject_asset_versions(html: str, static_dir: str, cache: Optional[Dict[str, str]] = None) -> str:
    """Rewrite the ``?v=...`` token on local script/link tags.

    A reference that already carries a version token has it replaced; a
    reference without one gets one appended.  Either way the token becomes the
    content hash of the referenced file.
    """

    def repl(match: "re.Match[str]") -> str:
        path = match.group(1)
        filename = path.rsplit("/", 1)[-1]
        if not filename.endswith(_VERSIONED_EXTENSIONS):
            return match.group(0)
        return "%s?v=%s" % (path, version_for(static_dir, filename, cache))

    return _VERSION_RE.sub(repl, html)
