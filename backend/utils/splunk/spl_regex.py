"""Compiling a client's regular expression the way splunkd compiles it.

splunkd runs PCRE2; mockdr runs Python's `re`.  The two accept nearly the
same patterns and reject them in entirely different words — and mockdr let
`re.PatternError` escape the handler, so a malformed pattern answered 500.
splunkd answers 200 with a FATAL message, which is the difference between a
client reporting a failed search and a client reporting a broken server.

Measured on 10.4.2, one pattern per error, against `search index=main`.
Three commands wrap the same PCRE clause in three different sentences:

    rex      Error in 'rex' command: Encountered the following error while
             compiling the regex '<pattern>': Regex: <clause>.
    regex    Error in 'SearchOperator:regex': The regex '<pattern>' is
             invalid. Regex: <clause>.
    eval     Error in 'EvalCommand': Regex: <clause>

The eval frame neither echoes the pattern nor ends in a full stop.  The
`Error in <subject>: ` opening is `_failure_text`'s to write, so what is
raised here is only what follows it.
"""

from __future__ import annotations

import re
from typing import Final


class RegexError(ValueError):
    """A pattern splunkd's PCRE2 would refuse, worded the way it refuses it.

    A plain `ValueError`, deliberately: `evaluate` converts `ArgumentError`
    into "the arguments are invalid", which is not what splunkd says about a
    regex it cannot compile, and lets anything else through to the pipeline's
    own handler.  Living below `spl_expr` also keeps `spl_functions` — which
    needs this for `replace()` — free of an import cycle.
    """

#: What PCRE2 calls the errors Python's `re` has its own names for.  Every
#: pair measured on 10.4.2; a pattern whose Python error is not in this table
#: keeps Python's wording rather than inventing a PCRE one, because a wrong
#: sentence in the right shape still lets a client see a failed search.
_PCRE_CLAUSE: Final[dict[str, str]] = {
    "unterminated character set": "missing terminating ] for character class",
    "missing ), unterminated subpattern": "missing closing parenthesis",
    "multiple repeat": "quantifier does not follow a repeatable item",
    "nothing to repeat": "quantifier does not follow a repeatable item",
    "min repeat greater than max repeat": "numbers out of order in {} quantifier",
    "unbalanced parenthesis": "unmatched closing parenthesis",
    "unexpected end of pattern": "subpattern name expected",
    # splunkd spells named groups `(?<name>`, which `_cmd_rex` rewrites to
    # Python's `(?P<name>` — so a truncated one reaches `re` under the second
    # spelling and comes back named differently.  Same PCRE2 clause.
    "missing group name": "subpattern name expected",
    "bad escape (end of pattern)": "\\ at end of pattern",
}
#: The same, for the errors Python names with the offending text inside.
_PCRE_PREFIXES: Final[tuple[tuple[str, str], ...]] = (
    ("bad character range", "range out of order in character class"),
    ("redefinition of group name",
     "two named subpatterns have the same name (PCRE2_DUPNAMES not set)"),
)

REX: Final = "rex"
REGEX: Final = "regex"
EVAL: Final = "eval"


def _clause(error: re.error) -> str:
    """PCRE2's name for what Python's `re` just refused."""
    message = error.msg or str(error)
    if message.startswith("bad character in group name"):
        # PCRE2 distinguishes the leading digit from any other bad character;
        # only the digit is measured, so only the digit is claimed.
        name = message.partition("'")[2].rpartition("'")[0]
        if name[:1].isdigit():
            return "subpattern name must start with a non-digit"
        return message
    for prefix, clause in _PCRE_PREFIXES:
        if message.startswith(prefix):
            return clause
    return _PCRE_CLAUSE.get(message, message)


def compile_client_regex(
    expression: str, *, frame: str, echo: str | None = None,
) -> re.Pattern[str]:
    """`re.compile`, refusing a bad pattern in splunkd's words for `frame`.

    `echo` is the pattern as the client wrote it, for the frames that quote
    it back: `rex` accepts splunkd's `(?<name>...)` spelling, which mockdr
    rewrites to Python's before compiling, and splunkd quotes back what it
    was given rather than what it compiled.
    """
    try:
        return re.compile(expression)
    except re.error as error:
        clause = _clause(error)
        written = expression if echo is None else echo
        if frame == REX:
            msg = (
                f"Encountered the following error while compiling the regex "
                f"'{written}': Regex: {clause}."
            )
        elif frame == REGEX:
            msg = f"The regex '{written}' is invalid. Regex: {clause}."
        else:
            msg = f"Regex: {clause}"
        raise RegexError(msg) from None
