"""Compiling a client-supplied regular expression without a ReDoS foothold.

Several routes compile a pattern that arrives in a request and run it with
``re`` — Splunk's ``rex``/``regex``/``match()``, Elasticsearch's ``regexp``,
KQL's ``matches``. Python's engine backtracks, so a pattern with one
unbounded quantifier nested inside another — ``(a+)+``, ``(a*)*``,
``(a+)*`` — takes time exponential in the subject length. Measured here,
``^(a+)+$`` against a 30-character subject held a worker for 26 seconds; the
real products run RE2/PCRE2 with backtracking limits and do not.

``check_regex`` walks the parsed pattern and refuses that shape before it is
ever run. It is conservative: it rejects a nested *unbounded* quantifier, not
every pattern that could ever backtrack, so ordinary patterns compile
unchanged.
"""
from __future__ import annotations

import re
from re import _parser as sre_parse  # type: ignore[attr-defined]
from typing import Any

_MAXREPEAT = sre_parse.MAXREPEAT
_REPEATS = frozenset({sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT})
_BRANCH = sre_parse.BRANCH
_SUBPATTERN = sre_parse.SUBPATTERN
#: Node kinds that always consume exactly one character — a fixed boundary
#: between repetitions, which is what makes ``([a-z]+\.)+`` safe where
#: ``(a+)+`` is not.
_ONE_CHAR = frozenset({
    sre_parse.LITERAL, sre_parse.NOT_LITERAL, sre_parse.IN,
    sre_parse.ANY, sre_parse.CATEGORY,
})


class UnsafeRegexError(ValueError):
    """The pattern has a nested unbounded quantifier — a ReDoS foothold."""


def _subsequences(op: Any, av: Any) -> list:  # noqa: ANN401 - sre_parse node fields
    """The parsed sub-sequences a node contains, whatever its kind."""
    if op in _REPEATS:
        return [av[2]]
    if op is _SUBPATTERN:
        return [av[3]]
    if op is _BRANCH:
        return list(av[1])
    return []


def _has_unbounded_repeat(seq: Any) -> bool:  # noqa: ANN401 - parsed regex
    """Whether *seq* holds any unbounded quantifier, at any depth."""
    for op, av in seq:
        if op in _REPEATS and av[1] == _MAXREPEAT:
            return True
        if any(_has_unbounded_repeat(sub) for sub in _subsequences(op, av)):
            return True
    return False


def _has_required_boundary(seq: Any) -> bool:  # noqa: ANN401 - parsed regex
    r"""Whether *seq* must consume a fixed character between repetitions.

    A single required one-character element — the ``\\.`` in
    ``([a-z]+\\.)+`` — pins each iteration of an outer repeat to a distinct
    stretch of the subject, so consecutive iterations cannot divide the same
    run in many ways. Its presence is what separates a safe nested repeat
    from a catastrophic one.
    """
    for op, av in seq:
        if op in _ONE_CHAR:
            return True
        # A required (non-optional) sub-group counts when it has a boundary
        # of its own; a repeat does not — ``\w+`` is the overlap, not a pin.
        if op is _SUBPATTERN and _has_required_boundary(av[3]):
            return True
    return False


def _nests_unbounded(seq: Any) -> bool:  # noqa: ANN401 - parsed regex
    r"""Whether *seq* nests an unbounded quantifier inside another.

    Flagged only when the outer repeat's body has no fixed boundary between
    iterations: ``(a+)+`` and ``(\\w+\\s?)*`` are flagged, ``([a-z]+\\.)+``
    and ``(?:foo|bar)+`` are not.
    """
    for op, av in seq:
        if (
            op in _REPEATS
            and av[1] == _MAXREPEAT
            and _has_unbounded_repeat(av[2])
            and not _has_required_boundary(av[2])
        ):
            return True
        if any(_nests_unbounded(sub) for sub in _subsequences(op, av)):
            return True
    return False


def check_regex(pattern: str, flags: int = 0) -> None:
    """Raise :class:`UnsafeRegexError` when *pattern* nests unbounded repeats.

    A pattern that will not parse at all is left for the caller's own
    ``re.compile`` to reject in the words it already uses.
    """
    try:
        parsed = sre_parse.parse(pattern, flags)
    except re.error:
        return
    if _nests_unbounded(parsed):
        msg = (
            "pattern nests an unbounded quantifier inside another, which can "
            "backtrack catastrophically; rewrite it without the nesting"
        )
        raise UnsafeRegexError(msg)
