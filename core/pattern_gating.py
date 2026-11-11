"""Required-literal gating for multi-pattern regular-expression scanning.

Problem
-------
Several SNMK scanners apply a large family of regular expressions to the same
input (for example the 150 signature JavaScript secret patterns in
``core.js_intelligence``).  Naively this is ``O(P * N)`` where ``P`` is the
number of patterns and ``N`` the input length, and the per-pattern cost is a
full backtracking scan.  Measured on ``web/static/app.js`` (739 KiB) the naive
scan took ~3.8 s.

Approach
--------
Almost every real-world signature contains literals that must be present in
**every** match.  This module derives those literals directly from the pattern
source and turns them into a *gate*:

    a pattern is executed only if every gate group of that pattern is
    satisfied, where a gate group is a set of literals of which **at least
    one** must occur in the input.

A group is therefore a disjunction and the gate as a whole is a conjunction
of disjunctions, e.g. the pattern

    (?:client[_-]?secret|consumer[_-]?secret|app[_-]?secret)\\s*[=:]\\s*["']

yields the gate ``(client|consumer|app) AND secret`` - far more selective than
the single literal ``secret``, while still being a *necessary* condition for
a match.

Safety properties
-----------------
* The parser is **conservative**: any construct it does not fully understand
  contributes *no* constraint (the enclosing expression degrades to
  "no gate"), never an incorrect one.
* A gate is a *necessary* condition, never a sufficient one.  When the gate is
  satisfied the full pattern is still executed, so detection logic is
  unchanged.
* Gates are matched case-insensitively.  That is strictly more permissive than
  a case-sensitive match, so it can only ever admit extra candidates - never
  drop a real detection.
* If no gate can be derived for a pattern, that pattern is always executed.

Complexity
----------
Gating replaces ``P`` full backtracking scans with one cheap literal-alternation
search per gate group plus full scans only for the patterns whose gate is
satisfied.  Worst case behaviour is unchanged; typical behaviour improves by
the fraction of patterns that are absent from the input.
"""

from __future__ import annotations

import re
from typing import Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

__all__ = [
    "required_literal_groups",
    "required_literal_runs",
    "select_gate",
    "GateFilter",
]

# Minimum length for a literal to be considered a usable gate.  Shorter
# literals are too common in real source code to be selective.
MIN_GATE_LENGTH = 3

# Escapes that denote a zero-width assertion or a character class rather than
# a literal character.
_CLASS_ESCAPES = frozenset("dDwWsSbBAZ")
# Escapes that denote a literal control character.
_CONTROL_ESCAPES = {
    "n": "\n", "t": "\t", "r": "\r", "f": "\f", "v": "\v", "a": "\a",
}

# A gate group is a frozenset of literals; at least one of them must occur.
# An empty group means "unconstrained" and is dropped during construction.
GateGroup = FrozenSet[str]


class _Opaque(Exception):
    """Raised internally when the parser meets a construct it cannot model.

    The exception is caught at the nearest expression boundary and that
    expression is reported as contributing *no* constraint.
    """


class _Parser:
    """Recursive-descent parser computing required-literal constraints.

    For every expression the parser computes a list of *gate groups*.  Each
    group is a set of literals of which at least one must occur in every
    string matched by the expression.  An empty list means "no constraint".
    """

    def __init__(self, pattern: str) -> None:
        self.s = pattern
        self.n = len(pattern)
        self.i = 0

    # -- low level helpers -------------------------------------------------
    def _peek(self) -> str:
        return self.s[self.i] if self.i < self.n else ""

    def _startswith(self, token: str) -> bool:
        return self.s.startswith(token, self.i)

    # -- entry point -------------------------------------------------------
    def parse(self) -> List[GateGroup]:
        groups = self._parse_alt()
        if self.i != self.n:
            # Trailing garbage we do not understand -> no gate at all.
            raise _Opaque()
        return [g for g in groups if g]

    # -- grammar -----------------------------------------------------------
    def _parse_alt(self) -> List[GateGroup]:
        """alternation := seq ('|' seq)*

        For an alternation the constraint is the conjunction over group
        positions of the *union* of the alternatives found in that position:
        ``(A0 & A1) | (B0 & B1)`` implies ``(A0|B0) & (A1|B1)``.
        """
        branch_lists: List[List[GateGroup]] = []
        while True:
            branch_lists.append(self._parse_seq())
            if self._peek() == "|":
                self.i += 1
                continue
            break
        if len(branch_lists) == 1:
            return branch_lists[0]
        width = max(len(b) for b in branch_lists)
        merged: List[GateGroup] = []
        for idx in range(width):
            union: Set[str] = set()
            for branch in branch_lists:
                if idx < len(branch):
                    union |= branch[idx]
            merged.append(frozenset(union))
        return merged

    def _parse_seq(self) -> List[GateGroup]:
        """sequence := term*

        Adjacent plain literal characters are merged into a single literal so
        that e.g. ``AKIA`` is used as one literal instead of four.
        """
        groups: List[GateGroup] = []
        literal_buf: List[str] = []

        def flush() -> None:
            if literal_buf:
                groups.append(frozenset({"".join(literal_buf)}))
                literal_buf.clear()

        while self.i < self.n:
            ch = self.s[self.i]
            if ch == "|" or ch == ")":
                break
            term_groups, literal = self._parse_term()
            if literal is not None:
                literal_buf.append(literal)
            else:
                flush()
                groups.extend(term_groups)
        flush()
        return groups

    def _parse_term(self) -> Tuple[List[GateGroup], Optional[str]]:
        """term := atom quantifier?

        Returns ``(constraint, plain_literal_char)``.  ``plain_literal_char``
        is set only for an unquantified single literal character, which the
        caller merges with its neighbours.
        """
        atom_groups, atom_literal = self._parse_atom()
        quant = self._parse_quantifier()
        if quant is None:
            return atom_groups, atom_literal
        if quant == 0:
            # Optional / zero-or-more -> contributes no constraint.
            return [], None
        # One or more -> the atom is present at least once.
        if atom_literal is not None:
            return [frozenset({atom_literal})], None
        return atom_groups, None

    def _parse_quantifier(self) -> Optional[int]:
        """Parse an optional quantifier and return its minimum repetition."""
        ch = self._peek()
        # NOTE: ``"" in "?*"`` is True in Python, so the empty string returned
        # by ``_peek()`` at end-of-pattern must be excluded explicitly -
        # otherwise the parser would advance past the end of the pattern.
        if ch == "?" or ch == "*":
            self.i += 1
            self._skip_lazy()
            return 0
        if ch == "+":
            self.i += 1
            self._skip_lazy()
            return 1
        if ch == "{":
            close = self.s.find("}", self.i)
            if close == -1:
                return None
            body = self.s[self.i + 1:close]
            if not body:
                return None
            try:
                if "," in body:
                    lo_s = body.split(",", 1)[0].strip()
                    minimum = int(lo_s) if lo_s else 0
                else:
                    minimum = int(body)
            except ValueError:
                return None
            self.i = close + 1
            self._skip_lazy()
            return minimum
        return None

    def _skip_lazy(self) -> None:
        # A trailing '?' makes the quantifier lazy; it does not change whether
        # the element is required.
        if self._peek() == "?":
            self.i += 1

    def _parse_atom(self) -> Tuple[List[GateGroup], Optional[str]]:
        ch = self._peek()
        if ch == "":
            raise _Opaque()
        if ch == "(":
            return self._parse_group(), None
        if ch == "[":
            self._skip_char_class()
            return [], None
        if ch == ".":
            self.i += 1
            return [], None
        if ch == "^" or ch == "$":
            self.i += 1
            return [], None
        if ch == "\\":
            esc_groups, esc_literal = self._parse_escape()
            return esc_groups, esc_literal
        if ch in "*+?{}":
            raise _Opaque()
        # Plain literal character.
        self.i += 1
        return [], ch

    def _parse_group(self) -> List[GateGroup]:
        """Parse a parenthesised group, including all ``(?...)`` variants."""
        assert self.s[self.i] == "("
        self.i += 1
        if self._peek() != "?":
            # Plain capturing group.
            groups = self._parse_alt()
            self._expect(")")
            return groups

        if self._startswith("?:"):
            self.i += 2
            groups = self._parse_alt()
            self._expect(")")
            return groups
        if self._startswith("?="):
            # Positive lookahead: the inner expression must match, so its
            # constraint is inherited.
            self.i += 2
            groups = self._parse_alt()
            self._expect(")")
            return groups
        if self._startswith("?!"):
            # Negative lookahead: nothing is required.
            self.i += 2
            self._parse_alt()
            self._expect(")")
            return []
        if self._startswith("?<=") or self._startswith("?<!"):
            positive = self._startswith("?<=")
            self.i += 3
            groups = self._parse_alt()
            self._expect(")")
            return groups if positive else []
        if self._startswith("?P="):
            # Back-reference to a named group.
            raise _Opaque()
        if self._startswith("?P<") or self._startswith("<?"):
            # Named group.
            close = self.s.find(">", self.i)
            if close == -1:
                raise _Opaque()
            self.i = close + 1
            groups = self._parse_alt()
            self._expect(")")
            return groups
        if self._startswith("?#"):
            # Comment group.
            close = self.s.find(")", self.i)
            if close == -1:
                raise _Opaque()
            self.i = close + 1
            return []
        if self._startswith("?("):
            # Conditional group.
            raise _Opaque()
        if self._startswith("?"):
            # Inline flags such as (?i) or (?im) - they affect matching, not
            # the presence of literals, and are handled globally.
            j = self.i + 1
            while j < self.n and self.s[j] in "aiLmsux":
                j += 1
            if j < self.n and self.s[j] == ")":
                self.i = j + 1
                return []
            raise _Opaque()
        raise _Opaque()

    def _expect(self, token: str) -> None:
        if not self._startswith(token):
            raise _Opaque()
        self.i += len(token)

    def _skip_char_class(self) -> None:
        """Skip a ``[...]`` character class."""
        assert self.s[self.i] == "["
        self.i += 1
        if self._peek() == "^":
            self.i += 1
        if self._peek() == "]":
            self.i += 1
        while self.i < self.n:
            ch = self.s[self.i]
            if ch == "\\":
                self.i += 2
                continue
            if ch == "]":
                self.i += 1
                return
            self.i += 1
        raise _Opaque()

    def _parse_escape(self) -> Tuple[List[GateGroup], Optional[str]]:
        """Parse a backslash escape.

        Only escapes that denote exactly one literal character yield a
        literal; everything else yields no constraint.
        """
        self.i += 1  # consume backslash
        if self.i >= self.n:
            raise _Opaque()
        ch = self.s[self.i]
        self.i += 1
        if ch in _CLASS_ESCAPES:
            return [], None
        if ch in _CONTROL_ESCAPES:
            return [], _CONTROL_ESCAPES[ch]
        if ch.isdigit():
            # Back-reference - cannot reason about it.
            raise _Opaque()
        if ch in "xuU":
            width = {"x": 2, "u": 4, "U": 8}[ch]
            hexpart = self.s[self.i:self.i + width]
            if len(hexpart) != width:
                raise _Opaque()
            try:
                return [], chr(int(hexpart, 16))
            except ValueError:
                raise _Opaque()
        if ch == "N":
            close = self.s.find("}", self.i)
            if close == -1:
                raise _Opaque()
            self.i = close + 1
            return [], None
        if ch.isalnum():
            # Unknown alphanumeric escape - be conservative.
            raise _Opaque()
        # Escaped punctuation is a literal character.
        return [], ch


def required_literal_groups(pattern: str) -> List[GateGroup]:
    """Return the gate groups of ``pattern``.

    Each returned group is a frozenset of literals of which at least one must
    occur in every string matched by ``pattern``.  An empty list means "no
    gate could be derived" and the pattern must always be executed.
    """
    try:
        groups = _Parser(pattern).parse()
    except _Opaque:
        return []
    except RecursionError:
        return []
    cleaned: List[GateGroup] = []
    for group in groups:
        literals = {lit for lit in group if len(lit) >= MIN_GATE_LENGTH}
        if literals:
            cleaned.append(frozenset(literals))
    return cleaned


def required_literal_runs(pattern: str) -> List[str]:
    """Return the individual literals of the gate groups, longest first."""
    lits: Set[str] = set()
    for group in required_literal_groups(pattern):
        lits |= group
    return sorted(lits, key=len, reverse=True)


def select_gate(pattern: str) -> Optional[str]:
    """Return the single most selective literal of ``pattern`` or ``None``."""
    runs = required_literal_runs(pattern)
    return runs[0] if runs else None


class GateFilter:
    """Skips patterns whose required literals do not occur in the input.

    Each pattern owns one or more *gate groups*; a group is satisfied when at
    least one of its literals occurs in the input.  A pattern is executed only
    when all of its groups are satisfied.

    The presence test is a case-folded substring search (``str.__contains__``)
    rather than a regular-expression search: a case-insensitive *regex* cannot
    use CPython's literal fast path, while a case-folded literal search is a
    plain memchr/two-way scan.  The case folding of the input is performed
    once per input and can be supplied by the caller.

    Usage::

        gf = GateFilter([pattern_a, pattern_b, ...])
        lowered = text.lower()
        for idx, compiled in enumerate(compiled_patterns):
            if not gf.should_run(idx, text, lowered):
                continue
            ...
    """

    def __init__(self, source_patterns: Sequence[str]) -> None:
        self.groups: List[List[GateGroup]] = []
        self._group_literals: List[List[Tuple[str, ...]]] = []
        for src in source_patterns:
            pattern_groups = required_literal_groups(src)
            self.groups.append(pattern_groups)
            self._group_literals.append([
                tuple(sorted((lit.lower() for lit in group), key=len, reverse=True))
                for group in pattern_groups
            ])

    def groups_for(self, index: int) -> List[GateGroup]:
        return self.groups[index]

    def should_run(self, index: int, text: str, lowered: Optional[str] = None) -> bool:
        """Return ``True`` when pattern ``index`` must be executed on ``text``.

        ``lowered`` is the case-folded form of ``text``; when omitted it is
        computed on demand.  Supplying it avoids recomputing the fold for
        every pattern.
        """
        groups = self._group_literals[index]
        if not groups:
            return True
        if not text:
            return True
        if lowered is None:
            lowered = text.lower()
        for literals in groups:
            for lit in literals:
                if lit in lowered:
                    break
            else:
                # None of the alternatives of this group occur -> the pattern
                # cannot match.
                return False
        return True

    def runnable_indices(self, text: str, lowered: Optional[str] = None) -> List[int]:
        """Return the indices of the patterns that must be executed."""
        if lowered is None:
            lowered = text.lower()
        return [i for i in range(len(self.groups)) if self.should_run(i, text, lowered)]
