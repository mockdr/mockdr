"""Rendering a Splunk response as the CSV splunkd would return.

``output_mode=csv`` is real, but only on four paths: a job's ``results`` and
``events``, the job itself, and the job collection. Everywhere else splunkd
answers ``Output mode 'csv' is not supported for this endpoint.`` — which is
what :mod:`api.middleware.splunk_output_mode` sends for the rest.

The quoting is not RFC 4180's. splunkd writes a token bare only when it is
purely alphanumeric, and quotes everything else — a dot, a dash, a space, a
colon, a leading underscore, an empty string. A multivalue field becomes one
quoted cell whose members are separated by newlines. A field a row has no
value for is empty, without quotes. All of it measured against Splunk 10.4.2.
"""
from __future__ import annotations

import re
from typing import Any

#: Written bare; anything else is quoted. Deliberately narrower than the
#: rule a CSV writer needs — it is the rule splunkd uses.
_BARE = re.compile(r"[A-Za-z0-9]+")

#: The order each endpoint puts its columns in, measured per endpoint:
#: results keep the order the search produced, events sort by name, and a job
#: entry keeps splunkd's own key order — which is neither, and not derivable
#: from outside, so mockdr keeps its own.
_ALPHABETICAL = "alphabetical"
_AS_GIVEN = "as-given"


def render_splunk_csv(payload: object, *, sort_columns: bool = False) -> str:
    """Render a Splunk JSON response body as CSV.

    Args:
        payload:      Decoded JSON body produced by a Splunk router.
        sort_columns: Sort the columns by name, as the ``events`` endpoint
                      does. ``results`` keeps the order the search produced.

    Returns:
        The CSV document, or an empty string when there is nothing to render
        — which is what splunkd answers with, as ``text/plain``.
    """
    rows, columns = _rows_and_columns(payload)
    if not rows:
        return ""
    if sort_columns:
        columns = sorted(columns)
    lines = [",".join(_cell(name) for name in columns)]
    lines.extend(
        ",".join(_cell(row.get(name)) for name in columns) for row in rows
    )
    return "\n".join(lines) + "\n"


def _rows_and_columns(payload: object) -> tuple[list[dict], list[str]]:
    """Read the rows and their column names out of a Splunk response body."""
    if not isinstance(payload, dict):
        return [], []

    results = payload.get("results")
    if isinstance(results, list):
        rows = [r for r in results if isinstance(r, dict)]
        declared = [
            str(f.get("name")) for f in payload.get("fields") or []
            if isinstance(f, dict) and f.get("name")
        ]
        return rows, declared or _keys_in_order(rows)

    entries = payload.get("entry")
    if isinstance(entries, list):
        rows = [
            e["content"] for e in entries
            if isinstance(e, dict) and isinstance(e.get("content"), dict)
        ]
        return rows, _keys_in_order(rows)

    return [], []


def _keys_in_order(rows: list[dict]) -> list[str]:
    """Every key the rows carry, first-seen first."""
    columns: list[str] = []
    for row in rows:
        for key in row:
            if key not in columns:
                columns.append(key)
    return columns


def _cell(value: Any) -> str:
    """One CSV cell, quoted the way splunkd quotes it."""
    if value is None:
        # A field this row has no value for: nothing at all, not `""`.
        return ""
    if isinstance(value, (list, tuple)):
        # A multivalue field is one cell whose members are newline-separated.
        return _quote("\n".join(_scalar(v) for v in value))
    text = _scalar(value)
    return text if _BARE.fullmatch(text) else _quote(text)


def _scalar(value: Any) -> str:
    """A value as its text, the way the JSON body already carries it.

    A boolean keeps its JSON spelling — `typeahead` writes `true` in the
    `operator` column, not `1` (measured).
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _quote(text: str) -> str:
    """Wrap in quotes, doubling the quotes inside."""
    return '"' + text.replace('"', '""') + '"'
