"""The Painless a security client actually writes, and nothing else.

``_update`` and ``_update_by_query`` carry a script, and the ones a SIEM
sends are almost always a single assignment — closing a signal, stamping a
workflow status, bumping a counter:

    ctx._source.signal.status = 'closed'
    ctx._source['kibana.alert.workflow_status'] = params.status
    ctx._source.count += 1
    ctx.op = 'noop'

mockdr reads exactly that shape: assignment, compound assignment, ``remove``,
and a write to ``ctx.op``. It does not run Painless, and says so rather than
guessing at a script it cannot read — a wrong answer to a status update is
worse than a refusal, because the client believes the alert was closed.
"""
from __future__ import annotations

import re
from typing import Any

from utils.nested import get_nested

__all__ = ["PainlessError", "run_script"]


class PainlessError(ValueError):
    """Raised when a script is not one of the forms mockdr reads."""


#: `ctx._source.a.b`, `ctx._source['a']['b']`, `ctx.op`, `params.x`.
_TARGET = re.compile(
    r"""^ctx(?P<source>\._source|)(?P<path>(?:\.[A-Za-z_][\w.]*|\['[^']*'\]|\["[^"]*"\])*)$""",
)
_STATEMENT = re.compile(
    r"""^\s*(?P<target>[^=+\-]+?)\s*(?P<op>=|\+=|-=)\s*(?P<value>.+?)\s*$""",
)
_REMOVE = re.compile(
    r"""^\s*ctx\._source\.remove\(\s*['"](?P<field>[^'"]+)['"]\s*\)\s*$""",
)


def run_script(source: str, params: dict, document: dict) -> str:
    """Apply *source* to *document* in place.

    Args:
        source:   The script text.
        params:   The script's parameters.
        document: The ``_source`` to change.

    Returns:
        The operation the script asked for: ``index`` (the default),
        ``noop`` or ``delete``.

    Raises:
        PainlessError: If the script is not a form mockdr reads.
    """
    operation = "index"
    for raw in _statements(source):
        removal = _REMOVE.match(raw)
        if removal:
            _remove(document, removal.group("field"))
            continue
        statement = _STATEMENT.match(raw)
        if not statement:
            msg = f"mockdr reads assignments and remove(), not [{raw.strip()}]"
            raise PainlessError(msg)
        target = _parse_target(statement.group("target"))
        value = _value(statement.group("value"), params, document)
        if target == ["op"]:
            operation = str(value)
            continue
        _assign(document, target, value, statement.group("op"))
    return operation


def _statements(source: str) -> list[str]:
    """The script's statements, split on ``;`` and newlines."""
    return [s for s in re.split(r"[;\n]", source) if s.strip()]


def _parse_target(text: str) -> list[str]:
    """The path an assignment writes to, as its parts."""
    match = _TARGET.match(text.strip())
    if not match:
        msg = f"mockdr reads a write to ctx._source, not [{text.strip()}]"
        raise PainlessError(msg)
    parts = _path_parts(match.group("path"))
    if not match.group("source"):
        # `ctx.op`, `ctx._id` — a write to the context itself.
        return parts
    return ["_source", *parts]


def _path_parts(path: str) -> list[str]:
    """Split ``.a['b'].c`` into its names."""
    return [
        name or quoted or double
        for name, quoted, double in re.findall(
            r"""\.([A-Za-z_]\w*)|\['([^']*)'\]|\["([^"]*)"\]""", path,
        )
    ]


def _value(text: str, params: dict, document: dict) -> Any:
    """Evaluate the right-hand side of an assignment."""
    literal = text.strip()
    if literal.startswith(("'", '"')) and literal[-1] == literal[0]:
        return literal[1:-1]
    if literal in ("true", "false"):
        return literal == "true"
    if literal == "null":
        return None
    try:
        return int(literal)
    except ValueError:
        pass
    try:
        return float(literal)
    except ValueError:
        pass
    if literal.startswith("params"):
        return get_nested(params, ".".join(_path_parts(literal[len("params"):])))
    if literal.startswith("ctx._source"):
        return get_nested(document, ".".join(_path_parts(literal[len("ctx._source"):])))
    msg = f"mockdr reads a literal, a param or a field, not [{literal}]"
    raise PainlessError(msg)


def _assign(document: dict, target: list[str], value: Any, operator: str) -> None:
    """Write *value* at *target*, creating the objects on the way."""
    if target[:1] != ["_source"]:
        msg = f"mockdr writes to ctx._source, not to ctx.{'.'.join(target)}"
        raise PainlessError(msg)
    path = target[1:]
    if not path:
        msg = "mockdr writes a field of ctx._source, not the whole document"
        raise PainlessError(msg)
    # A field whose *name* has dots is written as it is when the document
    # already holds it that way; otherwise the path is nested.
    dotted = ".".join(path)
    if len(path) > 1 and dotted in document:
        holder, key = document, dotted
    else:
        holder = document
        for part in path[:-1]:
            nxt = holder.get(part)
            if not isinstance(nxt, dict):
                nxt = {}
                holder[part] = nxt
            holder = nxt
        key = path[-1]
    if operator == "=":
        holder[key] = value
        return
    current = holder.get(key)
    try:
        holder[key] = current + value if operator == "+=" else current - value
    except TypeError as exc:
        msg = f"cannot apply [{operator}] to [{current!r}]"
        raise PainlessError(msg) from exc


def _remove(document: dict, field: str) -> None:
    """``ctx._source.remove('field')``."""
    document.pop(field, None)
