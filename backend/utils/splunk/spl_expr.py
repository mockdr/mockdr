"""Expression parsing and evaluation shared by SPL ``search``, ``where`` and ``eval``.

Splunk uses one expression grammar in three places with slightly different
defaults, so they are parsed by one recursive-descent parser here:

* ``search`` — bare words match ``_raw``; ``field=value`` supports ``*``
  wildcards; ``AND`` is implicit between adjacent terms.
* ``where`` — bare words are field references and comparison operators are
  real comparisons, so ``where count > 5`` filters rather than matching text.
* ``eval`` — arithmetic, string concatenation with ``.``, and the common
  functions (``if``, ``case``, ``coalesce``, ``upper`` …).

The previous implementation regex-scraped a single ``field=value`` pair per
clause, so every later clause was discarded, ``!=`` and ``>`` were treated as
equality, ``NOT`` inverted into a positive match, and ``eval`` stored the
expression's source text as the field's value.
"""
from __future__ import annotations

import operator
import re
from collections.abc import Callable
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from fnmatch import fnmatch
from typing import Any

__all__ = [
    "SPLExprError",
    "evaluate",
    "parse_eval",
    "parse_search",
    "parse_where",
]


class SPLExprError(ValueError):
    """Raised when an expression cannot be parsed or evaluated.

    ``function`` names the function a command asked for and does not have, and
    ``at`` the text a parse stopped on. splunkd words those two failures
    differently from each other and from everything else, and the mock has to
    say the same things: a client that keys on the message sees one wording
    here and another in production.
    """

    def __init__(self, message: str, *, function: str = "", at: str = "") -> None:
        """Record the message and, where there is one, the offending token."""
        super().__init__(message)
        self.function = function
        self.at = at


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

# Two word classes, because the same character means different things by
# context: `*` is a wildcard in a search clause (`host=alph*`) but
# multiplication in an eval, and `.` is string concatenation in an eval but an
# ordinary character inside a value like `10.0.0.1`. A single permissive class
# swallowed `bytes*2` as one token, so the arithmetic never parsed.
_PREFIX = r"""
    (?P<ws>\s+)
  | (?P<string>"(?:[^"\\]|\\.)*")
"""

# A search clause has no arithmetic, so `*`, `.` and `-` belong to words:
# `host=alph*`, `src=10.0.0.1`, and a bare `*` meaning "everything".
_SEARCH_TOKEN_RE = re.compile(
    _PREFIX + r"""
  | (?P<number>(?![\w.*-])-?\d+\.\d+|(?![\w.*-])-?\d+)
  | (?P<op><=|>=|!=|==|=|<|>|,|\(|\))
  | (?P<word>[^\s()=<>!,]+)
    """,
    re.VERBOSE,
)

# `where` and `eval` do have arithmetic, so the operators are split out and
# words stop at them — otherwise `bytes*2` tokenizes as a single name.
_EXPR_TOKEN_RE = re.compile(
    _PREFIX + r"""
  | (?P<number>-?\d+\.\d+|-?\d+)
  | (?P<op><=|>=|!=|==|=|<|>|\+|-|\*|/|%|\.|,|\(|\))
  | (?P<word>[^\s()=<>!,+*/%.-]+)
    """,
    re.VERBOSE,
)


@dataclass(frozen=True)
class _Token:
    kind: str
    text: str


def _tokenize(source: str, *, mode: str) -> list[_Token]:
    pattern = _SEARCH_TOKEN_RE if mode == "search" else _EXPR_TOKEN_RE
    tokens: list[_Token] = []
    pos = 0
    while pos < len(source):
        match = pattern.match(source, pos)
        if match is None:
            raise SPLExprError(
                f"unexpected character at offset {pos}", at=source[pos:pos + 2],
            )
        pos = match.end()
        kind = match.lastgroup or ""
        if kind == "ws":
            continue
        tokens.append(_Token(kind, match.group()))
    return tokens


# ---------------------------------------------------------------------------
# AST
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Literal:
    """A constant value."""

    value: Any


@dataclass(frozen=True)
class FieldRef:
    """A reference to a field on the row."""

    name: str


@dataclass(frozen=True)
class RawTerm:
    """A bare word in a ``search`` clause — matched against the whole event."""

    text: str


@dataclass(frozen=True)
class Compare:
    """A binary comparison."""

    op: str
    left: Node
    right: Node


@dataclass(frozen=True)
class BinOp:
    """An arithmetic or concatenation operator."""

    op: str
    left: Node
    right: Node


@dataclass(frozen=True)
class BoolOp:
    """``AND`` / ``OR``."""

    op: str
    children: tuple[Node, ...]


@dataclass(frozen=True)
class NotOp:
    """``NOT``."""

    child: Node


@dataclass(frozen=True)
class FuncCall:
    """A function invocation."""

    name: str
    args: tuple[Node, ...]


Node = (
    Literal | FieldRef | RawTerm | Compare | BinOp | BoolOp | NotOp | FuncCall
)

_MAX_DEPTH = 60


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class _Parser:
    """Recursive-descent parser for the SPL expression grammar."""

    def __init__(self, tokens: list[_Token], *, mode: str) -> None:
        self._tokens = tokens
        self._pos = 0
        self._mode = mode  # "search" | "where" | "eval"
        self._depth = 0
        # True while parsing the right-hand side of a comparison, where a
        # bare word is the literal being compared against rather than free
        # text to search for.
        self._in_value = False

    # -- token helpers --------------------------------------------------

    def _peek(self) -> _Token | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _next(self) -> _Token:
        token = self._peek()
        if token is None:
            raise SPLExprError("unexpected end of expression")
        self._pos += 1
        return token

    def _accept(self, text: str) -> bool:
        token = self._peek()
        if token is not None and token.text.upper() == text.upper():
            self._pos += 1
            return True
        return False

    def _expect(self, text: str) -> None:
        if not self._accept(text):
            found = self._peek()
            got = found.text if found else "end of expression"
            raise SPLExprError(f"expected {text!r} but found {got!r}", at=str(got))

    # -- grammar --------------------------------------------------------

    def parse(self) -> Node:
        node = self._parse_or()
        trailing = self._peek()
        if trailing is not None:
            raise SPLExprError(
                f"unexpected trailing input at {trailing.text!r}", at=trailing.text,
            )
        return node

    def _guard(self) -> None:
        if self._depth > _MAX_DEPTH:
            raise SPLExprError("expression nested too deeply")

    def _parse_or(self) -> Node:
        self._depth += 1
        self._guard()
        try:
            children = [self._parse_and()]
            while self._accept("OR"):
                children.append(self._parse_and())
            return children[0] if len(children) == 1 else BoolOp("or", tuple(children))
        finally:
            self._depth -= 1

    def _parse_and(self) -> Node:
        self._depth += 1
        self._guard()
        try:
            children = [self._parse_not()]
            while True:
                if self._accept("AND"):
                    children.append(self._parse_not())
                    continue
                # Adjacent terms are an implicit AND in a search clause.
                token = self._peek()
                if (
                    self._mode == "search"
                    and token is not None
                    and token.text.upper() not in (")", "OR")
                ):
                    children.append(self._parse_not())
                    continue
                break
            return children[0] if len(children) == 1 else BoolOp("and", tuple(children))
        finally:
            self._depth -= 1

    def _parse_not(self) -> Node:
        if self._accept("NOT"):
            return NotOp(self._parse_not())
        return self._parse_comparison()

    def _parse_comparison(self) -> Node:
        left = self._parse_additive()
        token = self._peek()
        if token is not None and token.kind == "op" and token.text in (
            "=", "==", "!=", "<", "<=", ">", ">=",
        ):
            self._next()
            previous, self._in_value = self._in_value, True
            try:
                right = self._parse_additive()
            finally:
                self._in_value = previous
            return Compare(token.text, left, right)
        return left

    def _parse_additive(self) -> Node:
        node = self._parse_multiplicative()
        while True:
            token = self._peek()
            if token is None or token.kind != "op" or token.text not in ("+", "-", "."):
                return node
            self._next()
            node = BinOp(token.text, node, self._parse_multiplicative())

    def _parse_multiplicative(self) -> Node:
        node = self._parse_atom()
        while True:
            token = self._peek()
            if token is None or token.kind != "op" or token.text not in ("*", "/", "%"):
                return node
            # `*` is a wildcard, not multiplication, outside eval.
            if self._mode != "eval":
                return node
            self._next()
            node = BinOp(token.text, node, self._parse_atom())

    def _parse_atom(self) -> Node:
        self._depth += 1
        self._guard()
        try:
            return self._parse_atom_inner()
        finally:
            self._depth -= 1

    def _parse_atom_inner(self) -> Node:
        token = self._next()

        if token.text == "(":
            node = self._parse_or()
            self._expect(")")
            return node

        if token.kind == "string":
            return Literal(_unquote(token.text))

        if token.kind == "number":
            text = token.text
            return Literal(float(text) if "." in text else int(text))

        if token.kind == "op" and token.text == "-":
            inner = self._parse_atom()
            return BinOp("-", Literal(0), inner)

        if token.kind == "word":
            nxt = self._peek()
            # Functions exist in `eval` and `where`, not in the search clause:
            # `index=main (host=a OR host=b)` is a term and a group, and
            # reading it as a call to `main(...)` raised "unknown function
            # 'main'" out of the handler as a 500 — on one of the most
            # ordinary searches there is.
            if self._mode != "search" and nxt is not None and nxt.text == "(":
                self._next()
                args: list[Node] = []
                if not self._accept(")"):
                    args.append(self._parse_or())
                    while self._accept(","):
                        args.append(self._parse_or())
                    self._expect(")")
                return FuncCall(token.text.lower(), tuple(args))

            if self._mode == "search":
                if self._in_value:
                    # `sourcetype=access_combined` — the right side names the
                    # value, not another term to look for in the event text.
                    return Literal(token.text)
                # A bare word is free text unless it is the left side of a
                # comparison, which _parse_comparison decides after us.
                following = self._peek()
                is_field = (
                    following is not None
                    and following.kind == "op"
                    and following.text in ("=", "==", "!=", "<", "<=", ">", ">=")
                )
                return FieldRef(token.text) if is_field else RawTerm(token.text)
            return FieldRef(token.text)

        raise SPLExprError(f"unexpected token {token.text!r}", at=token.text)


def _unquote(text: str) -> str:
    return text[1:-1].replace('\\"', '"').replace("\\\\", "\\")


def parse_search(source: str) -> Node | None:
    """Parse a ``search`` clause into a predicate tree."""
    return _parse(source, mode="search")


def parse_where(source: str) -> Node | None:
    """Parse a ``where`` expression into a predicate tree."""
    return _parse(source, mode="where")


def parse_eval(source: str) -> Node | None:
    """Parse an ``eval`` right-hand side into a value expression."""
    return _parse(source, mode="eval")


def _parse(source: str, *, mode: str) -> Node | None:
    tokens = _tokenize(source.strip(), mode=mode)
    if not tokens:
        return None
    return _Parser(tokens, mode=mode).parse()


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def _numeric(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return None


_COMPARATORS: dict[str, Callable[[Any, Any], bool]] = {
    "<": operator.lt,
    "<=": operator.le,
    ">": operator.gt,
    ">=": operator.ge,
}


def _compare(op: str, left: Any, right: Any) -> bool:
    if op in ("=", "=="):
        return _matches(left, right)
    if op == "!=":
        return not _matches(left, right)

    # A relational comparison against a missing field is false in Splunk.
    # Falling through to string comparison made `where missing > 900000` true,
    # because "None" sorts after "9".
    if left is None or right is None or left == "" :
        return False

    left_num, right_num = _numeric(left), _numeric(right)
    if left_num is not None and right_num is not None:
        return _COMPARATORS[op](left_num, right_num)
    # Comparing a number against a non-number is undefined; Splunk yields no
    # match rather than ordering the two as text.
    if (left_num is None) != (right_num is None):
        return False
    return _COMPARATORS[op](str(left), str(right))


def _matches(left: Any, right: Any) -> bool:
    """Equality, honouring ``*`` wildcards and numeric equivalence."""
    if left is None:
        return right is None
    pattern = str(right)
    value = str(left)
    if "*" in pattern:
        return fnmatch(value.lower(), pattern.lower())
    left_num, right_num = _numeric(left), _numeric(right)
    if left_num is not None and right_num is not None:
        return left_num == right_num
    return value == pattern


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return value != 0
    return str(value) not in ("", "0", "false", "False")


def _func(name: str, args: list[Any]) -> Any:  # noqa: PLR0911, PLR0912
    """Evaluate one of the eval functions mockdr supports."""
    if name == "if":
        return args[1] if _truthy(args[0]) else args[2]
    if name == "case":
        for i in range(0, len(args) - 1, 2):
            if _truthy(args[i]):
                return args[i + 1]
        return None
    if name == "coalesce":
        return next((a for a in args if a not in (None, "")), None)
    if name == "nullif":
        return None if args[0] == args[1] else args[0]
    if name in ("isnull", "isnotnull"):
        is_null = args[0] is None or args[0] == ""
        return is_null if name == "isnull" else not is_null
    if name == "upper":
        return str(args[0]).upper()
    if name == "lower":
        return str(args[0]).lower()
    if name == "trim":
        return str(args[0]).strip()
    if name == "len":
        return len(str(args[0]))
    if name == "tostring":
        return str(args[0])
    if name == "tonumber":
        return _numeric(args[0])
    if name == "abs":
        num = _numeric(args[0])
        return abs(num) if num is not None else None
    if name == "round":
        num = _numeric(args[0])
        if num is None:
            return None
        digits = int(_numeric(args[1]) or 0) if len(args) > 1 else 0
        # Splunk keeps the requested precision — `round(10, 2)` is `10.00`,
        # not `10` — and rounds a half away from zero, where Python's own
        # `round` rounds it to even: `round(10.5)` is 11 there and 10 here.
        quantum = Decimal(1).scaleb(-digits)
        value = Decimal(str(num)).quantize(quantum, rounding=ROUND_HALF_UP)
        return str(value) if digits > 0 else int(value)
    if name == "substr":
        text = str(args[0])
        start = int(_numeric(args[1]) or 1)
        length = int(_numeric(args[2]) or 0) if len(args) > 2 else None
        begin = max(start - 1, 0)
        return text[begin : begin + length] if length else text[begin:]
    if name == "like":
        return fnmatch(str(args[0]).lower(), str(args[1]).lower().replace("%", "*"))
    if name in ("match", "searchmatch"):
        return bool(re.search(str(args[1]), str(args[0]))) if len(args) > 1 else False
    if name == "replace":
        return re.sub(str(args[1]), str(args[2]), str(args[0]))
    if name in ("min", "max"):
        nums = [n for n in (_numeric(a) for a in args) if n is not None]
        if not nums:
            return None
        return min(nums) if name == "min" else max(nums)
    raise SPLExprError(f"unknown function {name!r}", function=name)


def evaluate(node: Node | None, row: dict, *, mode: str = "where") -> Any:  # noqa: PLR0911
    """Evaluate *node* against *row*.

    In ``search``/``where`` mode the result is coerced to a bool so it can be
    used as a predicate; in ``eval`` mode the raw value is returned.
    """
    if node is None:
        return True if mode != "eval" else None

    if isinstance(node, Literal):
        return node.value

    if isinstance(node, FieldRef):
        return row.get(node.name)

    if isinstance(node, RawTerm):
        needle = node.text.lower()
        haystack = " ".join(str(v) for v in row.values()).lower()
        if "*" in needle:
            return fnmatch(haystack, f"*{needle}*")
        return needle in haystack

    if isinstance(node, NotOp):
        return not _truthy(evaluate(node.child, row, mode=mode))

    if isinstance(node, BoolOp):
        results = (evaluate(c, row, mode=mode) for c in node.children)
        if node.op == "and":
            return all(_truthy(r) for r in results)
        return any(_truthy(r) for r in results)

    if isinstance(node, Compare):
        return _compare(
            node.op,
            evaluate(node.left, row, mode="eval"),
            evaluate(node.right, row, mode="eval"),
        )

    if isinstance(node, BinOp):
        return _binop(node, row)

    if isinstance(node, FuncCall):
        # `if` must not evaluate both branches eagerly for side-effect-free
        # semantics, but all our functions are pure, so this is safe.
        return _func(node.name, [evaluate(a, row, mode="eval") for a in node.args])

    raise SPLExprError(f"cannot evaluate {node!r}")


def _binop(node: BinOp, row: dict) -> Any:
    left = evaluate(node.left, row, mode="eval")
    right = evaluate(node.right, row, mode="eval")

    if node.op == ".":
        return f"{_render(left)}{_render(right)}"

    left_num, right_num = _numeric(left), _numeric(right)
    if left_num is None or right_num is None:
        # Splunk yields null when arithmetic meets a non-numeric operand.
        return None
    if node.op == "+":
        return _shrink(left_num + right_num)
    if node.op == "-":
        return _shrink(left_num - right_num)
    if node.op == "*":
        return _shrink(left_num * right_num)
    if node.op == "%":
        return _shrink(left_num % right_num) if right_num else None
    if node.op == "/":
        return _shrink(left_num / right_num) if right_num else None
    raise SPLExprError(f"unknown operator {node.op!r}")


def _shrink(value: float) -> float | int:
    """Present a whole float as an int, the way Splunk renders it."""
    return int(value) if float(value).is_integer() else value


def _render(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)
