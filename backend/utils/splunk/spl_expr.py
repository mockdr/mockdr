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
from fnmatch import fnmatch
from typing import Any

from utils.splunk.spl_functions import (
    FUNCTIONS,
    ArgumentError,
    one_or_many,
    values_of,
)

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

    def __init__(
        self, message: str, *, function: str = "", at: str = "",
        invalid_arguments: bool = False,
    ) -> None:
        """Record the message and, where there is one, the offending token."""
        super().__init__(message)
        self.function = function
        self.at = at
        #: splunkd words a function it does not have and a function given the
        #: wrong types differently, and a client keying on the message reads
        #: one or the other.
        self.invalid_arguments = invalid_arguments


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
            if self._mode != "search":
                _check_compare(token.text, left, right)
            return Compare(token.text, left, right)
        return left

    def _parse_additive(self) -> Node:
        node = self._parse_multiplicative()
        while True:
            token = self._peek()
            if token is None or token.kind != "op" or token.text not in ("+", "-", "."):
                return node
            self._next()
            right = self._parse_multiplicative()
            if self._mode != "search":
                _check_binop(token.text, node, right)
            node = BinOp(token.text, node, right)

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
            right = self._parse_atom()
            _check_binop(token.text, node, right)
            node = BinOp(token.text, node, right)

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
                name = token.text.lower()
                _check_arguments(name, args)
                return FuncCall(name, tuple(args))

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


# ---------------------------------------------------------------------------
# Static typing
#
# splunkd type-checks an expression before it runs it, on the types it can
# see: a literal's, and the type an operator produces. `"1"+1` and `"x".null()`
# are refused before a row is read, where `field+1` waits for the row and
# yields null if the value is not a number. mockdr coerced both, so a search
# splunkd refuses returned an answer here.
#
# All four messages measured against Splunk 10.4.2.
# ---------------------------------------------------------------------------

_STR, _NUM, _NULL, _UNKNOWN = "str", "num", "null", "unknown"

_ARITHMETIC = ("-", "*", "/", "%")


def _static_type(node: Node) -> str:
    """The type splunkd can see for *node* without reading a row."""
    if isinstance(node, Literal):
        return _NUM if isinstance(node.value, (int, float)) else _STR
    if isinstance(node, FuncCall):
        # `null()` is a typed literal there — Invalid — not a missing value.
        return _NULL if node.name == "null" else _UNKNOWN
    if isinstance(node, BinOp):
        if node.op == ".":
            return _STR
        if node.op == "+":
            sides = (_static_type(node.left), _static_type(node.right))
            return _STR if _STR in sides else _NUM
        return _NUM
    return _UNKNOWN


def _check_binop(op: str, left: Node, right: Node) -> None:
    """Refuse an operand pairing splunkd type-checks away."""
    sides = (_static_type(left), _static_type(right))
    if op == ".":
        if _NULL in sides:
            raise SPLExprError(
                "Type checking failed. The '.' operator only takes strings "
                "and numbers.",
            )
        return
    if op == "+":
        if _NULL in sides or (_STR in sides and _NUM in sides):
            raise SPLExprError(
                "Type checking failed. '+' only takes two strings or two "
                "numbers.",
            )
        return
    if op in _ARITHMETIC and (_STR in sides or _NULL in sides):
        raise SPLExprError(f"Type checking failed. '{op}' only takes numbers.")


def _check_arguments(name: str, args: list[Node]) -> None:
    """Refuse ``null()`` where the function will not take a typed null.

    A *missing field* is a runtime null and makes the call null; the literal
    is refused before the search runs, so ``mvcount(null())`` is an argument
    error where ``mvcount(nosuchfield)`` is not.
    """
    if name in _NULL_ARGUMENT_OK:
        return
    if any(_static_type(arg) == _NULL for arg in args):
        raise SPLExprError(
            f"The arguments to the '{name}' function are invalid.",
            function=name, invalid_arguments=True,
        )


def _check_compare(op: str, left: Node, right: Node) -> None:
    """Refuse a comparison against ``null()``, which splunkd will not order."""
    sides = (_static_type(left), _static_type(right))
    if _NULL in sides and {_STR, _NUM} & set(sides):
        raise SPLExprError(
            f"Type checking failed. The '{op}' operator received different "
            "types.",
        )


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


#: Functions that answer *about* a value and so see a missing field
#: themselves; everything else yields null when one of its arguments is
#: missing. Measured: `typeof(nosuchfield)` is "Invalid",
#: `tostring(nosuchfield)` and `printf("%s", nosuchfield)` are "Null".
_NULL_TOLERANT = frozenset({
    "typeof", "tostring", "printf", "null", "true", "false", "now", "time",
    "pi", "random", "isnum", "isstr", "isbool", "isint", "in", "validate",
})


#: Functions that take ``null()`` itself as an argument rather than refusing
#: it: the conditionals, which choose between their arguments, and the ones
#: that answer about a value.
_NULL_ARGUMENT_OK = _NULL_TOLERANT | {
    "if", "case", "coalesce", "nullif", "isnull", "isnotnull", "min", "max",
}


def _sort_key(pair: tuple[Any, str]) -> tuple[int, float, str]:
    """How splunkd orders one ``min``/``max`` argument.

    Numbers order below strings, and among strings by their bytes. Which of
    the two a value is depends on where it came from: a quoted literal is a
    string even when it reads as a number — ``min("10", "9")`` is ``"10"`` —
    while a field holding ``10`` is that number, so ``max(field, 9)`` is
    ``10``. Ordering everything numerically got the first wrong, and ordering
    everything as text the second.
    """
    value, static = pair
    if static != _STR:
        number = _numeric(value)
        if number is not None:
            return (0, number, "")
    return (1, 0.0, str(value))


def _extreme(name: str, args: list[tuple[Any, str]]) -> Any:
    """``min``/``max`` over arguments of any type.

    A null argument takes no part; no argument at all is an error.
    """
    values = [(v, s) for v, s in args if v is not None]
    if not values:
        if not args:
            raise SPLExprError(
                f"The arguments to the '{name}' function are invalid.",
                function=name, invalid_arguments=True,
            )
        return None
    chosen = min(values, key=_sort_key) if name == "min" else max(values, key=_sort_key)
    return chosen[0]


def _func(name: str, args: list[Any]) -> Any:
    """Evaluate one of the eval functions mockdr supports.

    The conditionals stay here because they choose *between* arguments; every
    other function lives in :mod:`utils.splunk.spl_functions`, which also
    holds the argument checking splunkd does.
    """
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
    if name == "like":
        return fnmatch(str(args[0]).lower(), str(args[1]).lower().replace("%", "*"))
    if name in ("match", "searchmatch"):
        return bool(re.search(str(args[1]), str(args[0]))) if len(args) > 1 else False
    if name in ("min", "max"):
        return _extreme(name, [(a, _UNKNOWN) for a in args])

    handler = FUNCTIONS.get(name)
    if handler is None:
        raise SPLExprError(f"unknown function {name!r}", function=name)
    if any(a is None for a in args) and name not in _NULL_TOLERANT:
        # A missing field makes the call null rather than a type error:
        # `upper(nosuchfield)` leaves the field unassigned, where
        # `upper(null())` — a typed null — is refused by the parser above.
        return None
    try:
        return handler(args)
    except ArgumentError as exc:
        raise SPLExprError(
            str(exc), function=name, invalid_arguments=True,
        ) from exc
    except (IndexError, TypeError) as exc:
        # Too few arguments, or one of a type the handler could not use at
        # all: splunkd calls both invalid arguments.
        raise SPLExprError(
            f"The arguments to the '{name}' function are invalid.",
            function=name, invalid_arguments=True,
        ) from exc


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
        if node.name in ("min", "max"):
            # These two order their arguments, and where an argument came
            # from decides whether it counts as text or as a number.
            return _extreme(node.name, [
                (evaluate(a, row, mode="eval"), _static_type(a)) for a in node.args
            ])
        if node.name in ("mvfilter", "mvmap"):
            # These two evaluate their expression once per value of a
            # multivalue field, so they need it unevaluated.
            return _mv_lambda(node, row)
        # `if` must not evaluate both branches eagerly for side-effect-free
        # semantics, but all our functions are pure, so this is safe.
        return _func(node.name, [evaluate(a, row, mode="eval") for a in node.args])

    raise SPLExprError(f"cannot evaluate {node!r}")


def _field_names(node: Node) -> list[str]:
    """Every field the expression reads, first-mentioned first."""
    found: list[str] = []
    stack: list[Node] = [node]
    while stack:
        current = stack.pop(0)
        if isinstance(current, FieldRef):
            if current.name not in found:
                found.append(current.name)
        elif isinstance(current, NotOp):
            stack.append(current.child)
        elif isinstance(current, BoolOp):
            stack.extend(current.children)
        elif isinstance(current, Compare):
            stack.extend([current.left, current.right])
        elif isinstance(current, BinOp):
            stack.extend([current.left, current.right])
        elif isinstance(current, FuncCall):
            stack.extend(current.args)
    return found


def _mv_lambda(node: FuncCall, row: dict) -> Any:
    """``mvfilter(expr)`` and ``mvmap(field, expr)``.

    Both bind one field, value by value, and evaluate the expression against
    each: `mvfilter(m!="b")` keeps the values it holds for, `mvmap(m, m."!")`
    replaces each with what it produces. A field the row does not have makes
    the result null; an expression that names no field is an argument error,
    which is what splunkd calls it.
    """
    if node.name == "mvfilter":
        expression = node.args[0] if len(node.args) == 1 else None
        names = _field_names(expression) if expression is not None else []
        field_name = names[0] if len(names) == 1 else ""
    else:
        expression = node.args[1] if len(node.args) == 2 else None
        first = node.args[0] if node.args else None
        field_name = first.name if isinstance(first, FieldRef) else ""
    if expression is None or not field_name:
        raise SPLExprError(
            f"The arguments to the '{node.name}' function are invalid.",
            function=node.name, invalid_arguments=True,
        )

    source = row.get(field_name)
    if source is None:
        return None
    kept: list[Any] = []
    for value in values_of(source):
        scoped = {**row, field_name: value}
        result = evaluate(expression, scoped, mode="eval")
        if node.name == "mvfilter":
            if _truthy(result):
                kept.append(value)
        elif result is not None:
            kept.append(result)
    return one_or_many(kept)


def _binop(node: BinOp, row: dict) -> Any:
    left = evaluate(node.left, row, mode="eval")
    right = evaluate(node.right, row, mode="eval")

    # A missing field makes the whole expression null rather than an empty
    # string: `nosuchfield."x"` leaves the field unassigned there.
    if left is None or right is None:
        return None

    if node.op == "." or (node.op == "+" and _concatenates(node)):
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


def _concatenates(node: BinOp) -> bool:
    """Whether this ``+`` joins text rather than adding.

    splunkd decides by the types it can see: with a string on either side
    ``+`` concatenates and the other operand is rendered, so ``a+"2"`` is
    ``12`` whether ``a`` holds 1 or "1". With no string in sight it adds, and
    a value that is not a number makes the result null.
    """
    return _STR in (_static_type(node.left), _static_type(node.right))


def _shrink(value: float) -> float | int:
    """Present a whole float as an int, the way Splunk renders it."""
    return int(value) if float(value).is_integer() else value


def _render(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)
