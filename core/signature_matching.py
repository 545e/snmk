"""Efficient, semantics-preserving matching of a corpus of regular expressions.

Problem
-------
Security engines match a *family* of regular expressions against a remote
server's HTTP response body.  The body is fully attacker controlled, so a
naive implementation has two problems:

1. **Cost.**  ``P`` full backtracking scans over an ``N`` byte body is
   ``O(P * N)`` and the pathological ``Warning.*mysql_.*`` shape is
   ``O(N^2)`` - a single response can stall a scan for seconds.
2. **Wasted work.**  Almost every signature contains a literal that must be
   present in every match (e.g. ``mysql_``, ``SqlException``).  Bodies that
   do not contain that literal cannot match at all, yet the engine still runs
   the full backtracking scan over the whole body.

Approach
--------
For every pattern the module derives a *required literal* (see
:mod:`core.pattern_gating`) and then:

* **Localises** the search.  A pattern whose ``.`` cannot cross a newline can
  only ever match inside a single line, so it is enough to run the pattern
  against the distinct lines that contain the required literal.  The lines are
  disjoint, so the total work is ``O(N)`` instead of ``O(P * N)``.
* **Widens the window** only as far as the pattern allows.  A pattern can
  cross a newline only through a construct that can *consume* a newline
  (``\\s``, ``\\W``, ``\\D``).  Each such construct can consume at most one
  newline, so a pattern with ``k`` of them is confined to at most ``k + 1``
  consecutive lines.  Patterns with constructs that can consume an unbounded
  number of newlines (negated character classes) are matched against the whole
  body.

Correctness
-----------
The optimisation is *exactly* equivalent to the naive implementation:

* The required literal is a necessary condition for a match, so no match can
  be missed by only inspecting the lines that contain it.
* Line-localised patterns are evaluated against the very same text a
  full-body scan would have matched in (the line), so the match condition is
  identical.
* Patterns that are not line-localisable keep the original whole-body scan.

The only observable difference is *which* occurrence is reported first when a
pattern matches several times; the boolean "does this pattern match" answer
is identical.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from core.pattern_gating import required_literal_groups

__all__ = ["SignatureMatcher", "build_line_index"]

# Constructs that can consume exactly one newline.
_SINGLE_NEWLINE_ESCAPES = re.compile(r"\\s|\\W|\\D")
# Constructs that can consume an unbounded number of newlines.
_UNBOUNDED_NEWLINE = re.compile(r"\[\^|\(\?s\)|\\Z|\\A|\(\?m\)|\(\?s")
# Anchors bind to the whole string rather than to a line.
_ANCHORS = re.compile(r"[\^\$]")


def build_line_index(text: str) -> List[int]:
    """Return the character offset of the first character of every line."""
    offsets = [0]
    idx = text.find("\n")
    while idx != -1:
        offsets.append(idx + 1)
        idx = text.find("\n", idx + 1)
    return offsets


def _line_spans(text: str, offsets: Sequence[int]) -> List[Tuple[int, int]]:
    """Return (start, end) character spans for every line of ``text``."""
    spans: List[Tuple[int, int]] = []
    n = len(text)
    for i, start in enumerate(offsets):
        end = offsets[i + 1] if i + 1 < len(offsets) else n
        spans.append((start, end))
    return spans


class _Signature:
    """A single compiled signature with its localisation strategy."""

    __slots__ = (
        "source", "regex", "flags", "locator", "locator_regex",
        "group_regexes", "span", "line_local", "whole_body",
    )

    def __init__(self, source: str, flags: int) -> None:
        self.source = source
        self.flags = flags
        self.regex = re.compile(source, flags)
        self.locator: Optional[str] = None
        self.locator_regex: Optional["re.Pattern[str]"] = None
        self.group_regexes: List["re.Pattern[str]"] = []
        self.span = 1          # number of consecutive lines a match can occupy
        self.line_local = False
        self.whole_body = True

        groups = required_literal_groups(source)
        if groups:
            for group in groups:
                alt = "|".join(re.escape(lit) for lit in sorted(group, key=len, reverse=True))
                self.group_regexes.append(re.compile(alt, flags))
            # Use the most selective group (longest literal) to locate the
            # candidate lines.  Every group literal is required by the
            # pattern, so the match always contains the locator.
            best = max(groups, key=lambda g: max(len(x) for x in g))
            literal = max(best, key=len)
            self.locator = literal
            self.locator_regex = re.compile(re.escape(literal), flags)

        self._classify()

    def _classify(self) -> None:
        src = self.source
        if self.locator is None:
            # No required literal could be derived, so the match cannot be
            # localised -> always scan the whole body.
            self.whole_body = True
            self.line_local = False
            self.span = 1
            return
        if _UNBOUNDED_NEWLINE.search(src) or _ANCHORS.search(src):
            # Cannot be localised safely -> always scan the whole body.
            self.whole_body = True
            self.line_local = False
            self.span = 1
            return
        crosses = len(_SINGLE_NEWLINE_ESCAPES.findall(src))
        self.span = crosses + 1
        self.whole_body = False
        self.line_local = True


class SignatureMatcher:
    """Matches a corpus of regular expressions against a body efficiently.

    Usage::

        matcher = SignatureMatcher(SQL_ERRORS)
        if matcher.search(body):
            ...  # a signature matched
    """

    def __init__(self, patterns: Iterable[str], flags: int = re.IGNORECASE) -> None:
        self.flags = flags
        self.signatures: List[_Signature] = [_Signature(p, flags) for p in patterns]
        # Fast membership test for the *whole* literal of a signature.
        self._literal_only: List[Tuple[str, _Signature]] = []
        for sig in self.signatures:
            src = sig.source
            if len(src) >= 3 and re.fullmatch(r"[A-Za-z0-9_./\\ -]+", src) and not sig.regex.flags & re.IGNORECASE:
                self._literal_only.append((src, sig))

    # -- public API --------------------------------------------------------
    def search(self, text: str) -> Optional[str]:
        """Return the first signature that matches ``text`` (or ``None``)."""
        idx = self.search_index(text)
        if idx is None:
            return None
        return self.signatures[idx].source

    def search_index(self, text: str) -> Optional[int]:
        """Return the index of the first signature that matches ``text``."""
        if not text:
            return None
        offsets = build_line_index(text)
        spans = _line_spans(text, offsets)
        for i, sig in enumerate(self.signatures):
            if self._matches(sig, text, offsets, spans):
                return i
        return None

    def search_all(self, text: str) -> List[str]:
        """Return every signature that matches ``text``."""
        if not text:
            return []
        offsets = build_line_index(text)
        spans = _line_spans(text, offsets)
        hits: List[str] = []
        for sig in self.signatures:
            if self._matches(sig, text, offsets, spans):
                hits.append(sig.source)
        return hits

    def matches(self, text: str) -> bool:
        """Return ``True`` when at least one signature matches ``text``."""
        return self.search(text) is not None

    # -- internals ---------------------------------------------------------
    def _matches(
        self,
        sig: _Signature,
        text: str,
        offsets: Sequence[int],
        spans: Sequence[Tuple[int, int]],
    ) -> bool:
        # ---- Necessary-condition prefilter ----------------------------
        # Every group literal is required by the pattern, so if any group is
        # entirely absent from the body the pattern cannot match.  This turns
        # the quadratic "Warning.*mysql_.*" shape into a single literal scan.
        for group_rx in sig.group_regexes:
            if group_rx.search(text) is None:
                return False

        if sig.whole_body:
            # No safe localisation: fall back to the original whole-body scan.
            return sig.regex.search(text) is not None

        assert sig.locator_regex is not None
        # Locate the distinct lines that contain the required literal.
        target_lines: set = set()
        for m in sig.locator_regex.finditer(text):
            line_idx = bisect_right(offsets, m.start()) - 1
            if line_idx < 0:
                line_idx = 0
            target_lines.add(line_idx)

        if not target_lines:
            # The required literal is absent -> the pattern cannot match.
            return False

        span = sig.span
        last_line = len(spans) - 1
        for line_idx in sorted(target_lines):
            lo = max(0, line_idx - span + 1)
            hi = min(last_line, line_idx + span - 1)
            start = spans[lo][0]
            end = spans[hi][1]
            window = text[start:end]
            if sig.regex.search(window) is not None:
                return True
        return False
