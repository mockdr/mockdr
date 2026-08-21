"""Deciding which differences are real.

Two responses to the same request will always differ. A real Splunk generates
its own session ids and timestamps; mockdr seeds fixed ones. Comparing raw
bodies would bury one genuine finding under a hundred meaningless ones, and a
report nobody reads finds nothing.

So the comparison is over a *skeleton*: the shape of the response, the types
at each path, and the values of the few keys whose values carry meaning. What
is left after that is either a real difference in behaviour or a gap in these
rules — and the second kind is worth knowing about too, which is why volatile
values are masked to a marker rather than dropped.
"""
from __future__ import annotations

import re
from typing import Any

#: Values that differ on every request and mean nothing when compared.
#: Ordered most-specific first: the first pattern to match wins, so a Splunk
#: SID is reported as a SID rather than as the epoch it happens to start with.
_VOLATILE: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("<sid>", re.compile(r"^\d{10}\.[0-9a-f]+(_[0-9A-F-]+)?$", re.I)),
    ("<uuid>", re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I,
    )),
    ("<timestamp>", re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")),
    ("<epoch>", re.compile(r"^\d{10}(\.\d+)?$")),
    ("<version>", re.compile(r"^\d+\.\d+\.\d+([.\-+][\w.\-]+)?$")),
    ("<hex>", re.compile(r"^[0-9a-f]{12,}$", re.I)),
    ("<url>", re.compile(r"^https?://")),
)

#: Header names worth comparing. Everything else is transport noise that says
#: nothing about whether the two servers agree.
#:
#: Deliberately excludes security headers. mockdr sets `X-Content-Type-Options`
#: and friends where a stock Elasticsearch does not, and that is mockdr being
#: stricter than the thing it mocks — a difference no client can observe as a
#: behavioural one, and not a defect to be fixed by removing the header.
SIGNIFICANT_HEADERS: frozenset[str] = frozenset({
    "content-type", "www-authenticate",
})


def strip_prefix(value: Any, prefix: str) -> Any:
    """Remove a mount prefix from strings inside a response body.

    mockdr serves Elasticsearch under `/elastic`, so it echoes that prefix
    back in error messages where the real product echoes a bare path. The
    difference is an artefact of hosting eight products on one port, not a
    disagreement about behaviour, and reporting it would bury the findings
    that matter under one per error message.
    """
    if not prefix:
        return value
    if isinstance(value, str):
        return value.replace(prefix, "")
    if isinstance(value, dict):
        return {k: strip_prefix(v, prefix) for k, v in value.items()}
    if isinstance(value, list):
        return [strip_prefix(v, prefix) for v in value]
    return value


def mask(value: str) -> str:
    """Reduce a volatile string to a marker, leaving stable strings alone."""
    for marker, pattern in _VOLATILE:
        if pattern.match(value):
            return marker
    return value


def type_name(value: Any) -> str:
    """Name a JSON value's type the way the report should read."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object"


def skeleton(
    body: Any,
    significant_keys: frozenset[str],
    path: str = "$",
    depth: int = 0,
) -> dict[str, str]:
    """Flatten a response body to ``{json path: type or significant value}``.

    Array elements collapse onto a single ``[*]`` path. Length differences
    between a seeded mock and an empty real install are the norm and say
    nothing; a *type* that appears in one array and not the other says a lot.

    Keys named in ``significant_keys`` carry their value instead of their
    type, because for those the value is the behaviour — a Splunk error is
    only meaningful as ``code 16`` rather than as "an int".
    """
    if depth > 40:  # a cycle, or a document too deep to be worth comparing
        return {path: "<truncated>"}

    out: dict[str, str] = {}
    if isinstance(body, dict):
        out[path] = "object"
        for key, value in body.items():
            child = f"{path}.{key}"
            if key in significant_keys and not isinstance(value, (dict, list)):
                out[child] = f"={mask(str(value))}"
            else:
                out.update(skeleton(value, significant_keys, child, depth + 1))
    elif isinstance(body, list):
        out[path] = "array"
        for item in body:
            out.update(skeleton(item, significant_keys, f"{path}[*]", depth + 1))
    else:
        out[path] = type_name(body)
    return out
