"""The ``eval`` functions splunkd offers, and how strict it is about them.

mockdr had nineteen; a search using ``split``, ``cidrmatch``, ``strftime`` or
any of the multivalue family got a FATAL where splunkd answers a value. It is
also strict about argument *types* in a way the mock was not: ``len(123)``,
``upper(1)`` and ``md5(1)`` are all "The arguments to the '<name>' function
are invalid" there, and returned an answer here — a client calling one on a
number got a value from the mock and an error from production.

Every function and every refusal below was measured against Splunk 10.4.2 by
evaluating the expression and reading what came back.

Two behaviours are deliberately not imitated, both measured and both
Splunk-side quirks rather than contracts:

* ``pow`` renders its result with the *base's* decimal places, so
  ``pow(2.5, 2)`` is ``6.3`` rather than ``6.25`` and ``pow(2, 0.5)`` is
  ``1``. This returns the power.
* how a float renders at the edges — ``0.1+0.2`` is ``0.3`` there and
  ``0.30000000000000004`` under any shortest-round-trip formatting. Integral
  results and ordinary decimals agree.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import random
import re
import time
import urllib.parse
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

#: What splunkd renders for each ``typeof``.
_TYPE_NAMES = {
    "str": "String", "num": "Number", "bool": "Bool",
    "mv": "Multivalue", "null": "Invalid",
}


class ArgumentError(ValueError):
    """Raised when a function's arguments are not the types splunkd takes.

    Carries the function's name so the command can say
    "The arguments to the '<name>' function are invalid." — which is what
    splunkd answers, and what a client keying on the message reads.
    """

    def __init__(self, function: str) -> None:
        """Record which function refused its arguments."""
        self.function = function
        super().__init__(f"The arguments to the '{function}' function are invalid.")


# ---------------------------------------------------------------------------
# Argument checking
# ---------------------------------------------------------------------------

def _is_number(value: Any) -> bool:
    """Whether this is a number rather than a string that looks like one."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _string(name: str, value: Any) -> str:
    """A string argument. A number is refused, as splunkd refuses it."""
    if isinstance(value, str):
        return value
    raise ArgumentError(name)


def _number(name: str, value: Any) -> float:
    """A numeric argument, whether it arrived as a number or as its text."""
    if _is_number(value):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError as exc:
            raise ArgumentError(name) from exc
    raise ArgumentError(name)


def _integer(name: str, value: Any) -> int:
    """A whole-number argument."""
    return int(_number(name, value))


def values_of(value: Any) -> list[Any]:
    """A field as its list of values; a scalar counts as one."""
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def one_or_many(values: list[Any]) -> Any:
    """A multivalue result, collapsed to a scalar when it holds one value.

    ``split("abc", ";")`` is the string ``abc`` on splunkd, not a list of one.
    """
    if not values:
        return None
    return values[0] if len(values) == 1 else values


def _rendered(value: Any) -> str:
    """A value as the text splunkd would show for it."""
    if value is None:
        # `tostring(nosuchfield)` is "Null" there, not the empty string.
        return "Null"
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


# ---------------------------------------------------------------------------
# Multivalue
# ---------------------------------------------------------------------------

def _split(args: list[Any]) -> Any:
    parts = _string("split", args[0]).split(_string("split", args[1]))
    return one_or_many([p for p in parts if p != ""] or [])


def _mvcount(args: list[Any]) -> Any:
    if args[0] is None:
        raise ArgumentError("mvcount")
    return len(values_of(args[0]))


def _mvindex(args: list[Any]) -> Any:
    values = values_of(args[0])
    start = _integer("mvindex", args[1])
    if len(args) > 2:
        end = _integer("mvindex", args[2])
        return one_or_many(values[start : end + 1])
    try:
        return values[start]
    except IndexError:
        # Out of range is not an error: the field is simply not assigned.
        return None


def _mvjoin(args: list[Any]) -> Any:
    return _string("mvjoin", args[1]).join(_rendered(v) for v in values_of(args[0]))


def _mvappend(args: list[Any]) -> Any:
    joined: list[Any] = []
    for arg in args:
        joined.extend(values_of(arg))
    return one_or_many(joined)


def _mvdedup(args: list[Any]) -> Any:
    seen: list[Any] = []
    for value in values_of(args[0]):
        if value not in seen:
            seen.append(value)
    return one_or_many(seen)


def _mvrange(args: list[Any]) -> Any:
    start, end = _integer("mvrange", args[0]), _integer("mvrange", args[1])
    step = _integer("mvrange", args[2]) if len(args) > 2 else 1
    return one_or_many([str(n) for n in range(start, end, step or 1)])


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

def _typeof(args: list[Any]) -> str:
    value = args[0]
    if value is None:
        return _TYPE_NAMES["null"]
    if isinstance(value, (list, tuple)):
        return _TYPE_NAMES["mv"]
    if isinstance(value, bool):
        return _TYPE_NAMES["bool"]
    if _is_number(value):
        return _TYPE_NAMES["num"]
    return _TYPE_NAMES["str"]


def _in(args: list[Any]) -> bool:
    candidates = [_rendered(v) for v in values_of(args[0])]
    return any(_rendered(other) in candidates for other in args[1:])


# ---------------------------------------------------------------------------
# Text
# ---------------------------------------------------------------------------

def _trim_side(name: str, args: list[Any], side: str) -> Any:
    value = args[0]
    if _is_number(value):
        # `trim` and its siblings take a number and hand it back, where
        # `upper` and `len` refuse one (measured).
        return value
    text = _string(name, value)
    chars = _string(name, args[1]) if len(args) > 1 else " \t\n\r"
    if side == "left":
        return text.lstrip(chars)
    if side == "right":
        return text.rstrip(chars)
    return text.strip(chars)


def _digest(name: str, algorithm: str) -> Callable[[list[Any]], str]:
    def run(args: list[Any]) -> str:
        return hashlib.new(algorithm, _string(name, args[0]).encode()).hexdigest()
    return run


def _printf(args: list[Any]) -> str:
    template = _string("printf", args[0])
    # `printf("%s", nosuchfield)` writes "Null", the same word `tostring` uses.
    values = tuple("Null" if a is None else a for a in args[1:])
    try:
        return template % values
    except (TypeError, ValueError) as exc:
        raise ArgumentError("printf") from exc


def _substr(args: list[Any]) -> str:
    text = _string("substr", args[0])
    start = _integer("substr", args[1])
    # A negative start counts from the end: `substr("abcdef", -3)` is "def".
    begin = len(text) + start if start < 0 else max(start - 1, 0)
    if len(args) > 2:
        return text[begin : begin + _integer("substr", args[2])]
    return text[begin:]


_TOSTRING_FORMATS = {"hex", "commas", "duration"}


def _tostring(args: list[Any]) -> str:
    value = args[0]
    if len(args) == 1:
        return _rendered(value)
    fmt = _string("tostring", args[1])
    if fmt not in _TOSTRING_FORMATS:
        raise ArgumentError("tostring")
    number = _number("tostring", value)
    if fmt == "hex":
        return f"0x{int(number):X}"
    if fmt == "commas":
        return f"{int(number):,}"
    total = int(number)
    return f"{total // 3600:02d}:{total % 3600 // 60:02d}:{total % 60:02d}"


# ---------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------

#: splunkd's `%N` takes a digit for the fraction's width; strftime does not.
_FRACTION = re.compile(r"%(\d)N")


def _strftime(args: list[Any]) -> str:
    moment = _number("strftime", args[0])
    fmt = _string("strftime", args[1])
    stamp = datetime.fromtimestamp(moment, tz=UTC)
    fraction = _FRACTION.search(fmt)
    if fraction:
        width = int(fraction.group(1))
        digits = f"{stamp.microsecond:06d}"[:width]
        fmt = _FRACTION.sub(digits, fmt)
    return stamp.strftime(fmt)


def _strptime(args: list[Any]) -> Any:
    text = _string("strptime", args[0])
    fmt = _string("strptime", args[1])
    try:
        parsed = datetime.strptime(text, fmt).replace(tzinfo=UTC)
    except ValueError:
        # Unparseable is not an error: the field is simply not assigned.
        return None
    return f"{parsed.timestamp():.6f}"


def _relative_time(args: list[Any]) -> Any:
    from utils.splunk.spl_parser import resolve_relative_time

    moment = _number("relative_time", args[0])
    resolved = resolve_relative_time(_string("relative_time", args[1]), moment)
    return resolved or None


# ---------------------------------------------------------------------------
# JSON
#
# ``spath`` and ``json_extract`` read the same path grammar: dots descend into
# objects, ``{n}`` indexes an array and a bare ``{}`` asks for the array
# itself. A document that does not parse, or a path that is not there, is not
# an error — the field is simply not assigned. All measured.
# ---------------------------------------------------------------------------

_PATH_STEP = re.compile(r"([^.{}]+)|\{(\d*)\}")


def _json_path(document: Any, path: str) -> Any:
    """Follow *path* through an already-decoded document."""
    current = document
    for name, index in _PATH_STEP.findall(path):
        if current is None:
            return None
        if name:
            if not isinstance(current, dict):
                return None
            current = current.get(name)
        elif index:
            if not isinstance(current, list):
                return None
            position = int(index)
            current = current[position] if position < len(current) else None
        elif not isinstance(current, list):
            # A bare `{}` asks for the array; anything else has none.
            return None
    return current


def _json_value(value: Any) -> Any:
    """A decoded JSON value as the field value splunkd assigns."""
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        # A container comes back as its own compact JSON text.
        return json.dumps(value, separators=(",", ":"))
    return value


def _extract(name: str) -> Callable[[list[Any]], Any]:
    def run(args: list[Any]) -> Any:
        text = _string(name, args[0])
        try:
            document = json.loads(text)
        except (ValueError, TypeError):
            # Not JSON is not an error; the field is left unassigned.
            return None
        return _json_value(_json_path(document, _string(name, args[1])))
    return run


def _json_valid(args: list[Any]) -> bool:
    try:
        json.loads(_string("json_valid", args[0]))
    except (ValueError, TypeError):
        return False
    return True


def _json_object(args: list[Any]) -> str:
    if len(args) % 2:
        raise ArgumentError("json_object")
    pairs = {
        _string("json_object", args[i]): args[i + 1]
        for i in range(0, len(args), 2)
    }
    return json.dumps(pairs, separators=(",", ":"))


def _json_array(args: list[Any]) -> str:
    return json.dumps(list(args), separators=(",", ":"))


# ---------------------------------------------------------------------------
# Conditionals that read as functions
# ---------------------------------------------------------------------------

def _validate(args: list[Any]) -> Any:
    """The value belonging to the first condition that is *false*.

    The inverse of `case`: `validate(isint(x), "not an integer")` names what
    went wrong rather than what held. All conditions true leaves the field
    unassigned.
    """
    if len(args) < 2 or len(args) % 2:
        raise ArgumentError("validate")
    for i in range(0, len(args), 2):
        if not args[i]:
            return args[i + 1]
    return None


def _sigfig(args: list[Any]) -> Any:
    """`sigfig` with the one argument splunkd takes.

    splunkd rounds to the significant figures of the *operands that produced*
    the value, which is information an expression result no longer carries;
    for every value measured — a literal, a quotient, an integer — it hands
    the number back unchanged, which is what this does. A second argument is
    refused there, and here.
    """
    if len(args) != 1:
        raise ArgumentError("sigfig")
    return _number("sigfig", args[0])


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

def _cidrmatch(args: list[Any]) -> bool:
    try:
        network = ipaddress.ip_network(_string("cidrmatch", args[0]), strict=False)
        address = ipaddress.ip_address(_string("cidrmatch", args[1]))
    except ValueError:
        # Neither a bad network nor a value that is not an address is an
        # error there — both are simply "no".
        return False
    return address.version == network.version and address in network


# ---------------------------------------------------------------------------
# Maths
# ---------------------------------------------------------------------------

def _guarded(name: str, run: Callable[[float], float]) -> Callable[[list[Any]], Any]:
    def call(args: list[Any]) -> Any:
        # The conversion is deliberately outside the guard: `sqrt("x")` is a
        # bad argument and fails the search, where `sqrt(-1)` is merely
        # undefined and leaves the field unassigned.
        number = _number(name, args[0])
        try:
            return run(number)
        except ValueError:
            return None
    return call


def _log(args: list[Any]) -> Any:
    number = _number("log", args[0])
    base = _number("log", args[1]) if len(args) > 1 else 10.0
    try:
        return math.log(number, base)
    except ValueError:
        return None


def _round(args: list[Any]) -> Any:
    """Round, keeping the precision that was asked for.

    ``round(10, 2)`` is ``10.00`` on splunkd, not ``10``, and a half goes
    away from zero where Python's own ``round`` sends it to even.
    """
    number = _number("round", args[0])
    digits = _integer("round", args[1]) if len(args) > 1 else 0
    quantum = Decimal(1).scaleb(-digits)
    value = Decimal(str(number)).quantize(quantum, rounding=ROUND_HALF_UP)
    return str(value) if digits > 0 else int(value)


#: Every function this mock answers, and nothing else — an unknown name is
#: "The '<name>' function is unsupported or undefined."
FUNCTIONS: dict[str, Callable[[list[Any]], Any]] = {
    # multivalue
    "split": _split,
    "mvcount": _mvcount,
    "mvindex": _mvindex,
    "mvjoin": _mvjoin,
    "mvappend": _mvappend,
    "mvdedup": _mvdedup,
    "mvsort": lambda args: one_or_many(sorted(values_of(args[0]), key=_rendered)),
    "mvrange": _mvrange,
    # types
    "null": lambda _args: None,
    "typeof": _typeof,
    "isnum": lambda args: _is_number(args[0]),
    "isstr": lambda args: isinstance(args[0], str),
    "isbool": lambda args: isinstance(args[0], bool),
    "isint": lambda args: _is_number(args[0]) and float(args[0]).is_integer(),
    "true": lambda _args: True,
    "false": lambda _args: False,
    "in": _in,
    # text
    "ltrim": lambda args: _trim_side("ltrim", args, "left"),
    "rtrim": lambda args: _trim_side("rtrim", args, "right"),
    "urldecode": lambda args: urllib.parse.unquote(_string("urldecode", args[0])),
    "md5": _digest("md5", "md5"),
    "sha1": _digest("sha1", "sha1"),
    "sha256": _digest("sha256", "sha256"),
    "sha512": _digest("sha512", "sha512"),
    "printf": _printf,
    "substr": _substr,
    "tostring": _tostring,
    # text, continued — `upper`, `lower` and `len` refuse a number, where
    # `trim` takes one and hands it back (all measured).
    "upper": lambda args: _string("upper", args[0]).upper(),
    "lower": lambda args: _string("lower", args[0]).lower(),
    "len": lambda args: len(_string("len", args[0])),
    "trim": lambda args: _trim_side("trim", args, "both"),
    "replace": lambda args: re.sub(
        _string("replace", args[1]), _string("replace", args[2]),
        _string("replace", args[0]),
    ),
    # maths
    "tonumber": lambda args: _number("tonumber", args[0]),
    "abs": lambda args: abs(_number("abs", args[0])),
    "round": _round,
    "ceiling": lambda args: math.ceil(_number("ceiling", args[0])),
    "ceil": lambda args: math.ceil(_number("ceil", args[0])),
    "floor": lambda args: math.floor(_number("floor", args[0])),
    "sqrt": _guarded("sqrt", math.sqrt),
    "exp": lambda args: math.exp(_number("exp", args[0])),
    "ln": _guarded("ln", math.log),
    "log": _log,
    "pi": lambda _args: math.pi,
    "pow": lambda args: _number("pow", args[0]) ** _number("pow", args[1]),
    # time
    "now": lambda _args: int(time.time()),
    "time": lambda _args: time.time(),
    "strftime": _strftime,
    "strptime": _strptime,
    "relative_time": _relative_time,
    # json
    "spath": _extract("spath"),
    "json_extract": _extract("json_extract"),
    "json_valid": _json_valid,
    "json_object": _json_object,
    "json_array": _json_array,
    # conditionals that read as functions
    "validate": _validate,
    # `exact` asks splunkd not to round the result; mockdr does not round in
    # the first place, so it is the value itself.
    "exact": lambda args: _number("exact", args[0]),
    "sigfig": _sigfig,
    "random": lambda _args: random.randrange(2**31),  # noqa: S311
    # network
    "cidrmatch": _cidrmatch,
}
