"""Splunk REST API response envelope builders.

Splunk wraps all REST responses in an Atom-style JSON envelope with ``entry[]``,
``paging``, ``links``, and ``generator`` fields.  Search results use a simpler
``{"results": [...], "fields": [...]}`` envelope.
"""
from __future__ import annotations

import time

_SPLUNK_VERSION = "9.4.0"
_SPLUNK_BUILD = "a1b2c3d4e5f6"

# ---------------------------------------------------------------------------
# Atom-style envelope (used by /services/* endpoints)
# ---------------------------------------------------------------------------


def build_splunk_entry(
    name: str,
    content: dict,
    *,
    id_path: str = "",
    updated: str = "",
) -> dict:
    """Build a single Splunk ``entry`` object.

    Args:
        name:     Entry name / identifier.
        content:  The actual data payload.
        id_path:  Optional full URL-like ID path.
        updated:  ISO-8601 timestamp; defaults to now.

    Returns:
        A dict matching the Splunk entry structure.
    """
    if not updated:
        updated = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
    return {
        "name": name,
        "id": id_path or f"https://localhost:8089/services/{name}",
        "updated": updated,
        "content": content,
    }


def build_splunk_envelope(
    entries: list[dict],
    *,
    total: int | None = None,
    offset: int = 0,
    per_page: int = 30,
    origin: str = "",
) -> dict:
    """Build the full Splunk JSON response envelope.

    Args:
        entries:  List of entry dicts.
        total:    Total number of matching entries (defaults to len(entries)).
        offset:   Pagination offset.
        per_page: Page size.
        origin:   Origin URL for the response.

    Returns:
        Complete Splunk REST API JSON response.
    """
    if total is None:
        total = len(entries)
    return {
        "links": {},
        "origin": origin or "https://localhost:8089/services",
        "updated": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
        "generator": {"build": _SPLUNK_BUILD, "version": _SPLUNK_VERSION},
        "entry": entries,
        "paging": {"total": total, "perPage": per_page, "offset": offset},
    }


def build_splunk_single(name: str, content: dict) -> dict:
    """Build a Splunk envelope with a single entry."""
    entry = build_splunk_entry(name, content)
    return build_splunk_envelope([entry], total=1)


# ---------------------------------------------------------------------------
# Search results envelope (used by /search/v2/jobs/{sid}/results)
# ---------------------------------------------------------------------------


def build_search_results(
    results: list[dict],
    *,
    fields: list[str] | None = None,
    init_offset: int = 0,
    messages: list[dict[str, str]] | None = None,
) -> dict:
    """Build a Splunk search results response.

    Args:
        results:     List of result dicts.
        fields:      Field names for the results.
        init_offset: Starting offset.
        messages:    Optional messages (info, warn, error).

    Returns:
        Search results envelope dict.
    """
    if fields is None:
        if results:
            fields = list(results[0].keys())
        else:
            fields = []
    return {
        "results": results,
        "fields": [{"name": f} for f in fields],
        "init_offset": init_offset,
        "messages": messages or [],
    }


# ---------------------------------------------------------------------------
# Error response
# ---------------------------------------------------------------------------


def build_splunk_error(status: int, message: str) -> dict:
    """Build a Splunk error response body.

    Args:
        status:  HTTP status code.
        message: Error message.

    Returns:
        Splunk error envelope dict.
    """
    return {
        "messages": [{"type": "ERROR", "text": message}],
    }


# ---------------------------------------------------------------------------
# Simple key-value response (used by auth/login)
# ---------------------------------------------------------------------------


def build_auth_response(session_key: str) -> dict:
    """Build the auth login response.

    Args:
        session_key: The generated session token.

    Returns:
        Response dict with ``sessionKey``.
    """
    return {"sessionKey": session_key}
