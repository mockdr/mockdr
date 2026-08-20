"""Splunk REST API response envelope builders.

Splunk wraps all REST responses in an Atom-style JSON envelope with ``entry[]``,
``paging``, ``links``, and ``generator`` fields.  Search results use a simpler
``{"results": [...], "fields": [...]}`` envelope.
"""
from __future__ import annotations

import time
from urllib.parse import quote

_SPLUNK_VERSION = "9.4.0"
_SPLUNK_BUILD = "a1b2c3d4e5f6"
_BASE_URL = "https://localhost:8089"

# splunkd reports an ACL on every entry; splunklib exposes it as
# ``Entity.access``.
_DEFAULT_ACL: dict[str, object] = {
    "app": "search",
    "can_list": True,
    "can_write": True,
    "modifiable": True,
    "owner": "nobody",
    "perms": {"read": ["*"], "write": ["admin"]},
    "removable": True,
    "sharing": "app",
}


def _rel_path(entry_id: str) -> str:
    """The path portion of an entry id, which is what links carry."""
    return entry_id[len(_BASE_URL):] if entry_id.startswith(_BASE_URL) else entry_id

# ---------------------------------------------------------------------------
# Atom-style envelope (used by /services/* endpoints)
# ---------------------------------------------------------------------------


def build_splunk_entry(
    name: str,
    content: dict,
    *,
    id_path: str = "",
    collection: str = "",
    updated: str = "",
) -> dict:
    """Build a single Splunk ``entry`` object.

    Args:
        name:       Entry name / identifier.
        content:    The actual data payload.
        id_path:    Optional full URL-like ID path.
        collection: REST path of the owning collection, e.g.
                    ``authentication/users``. Without it the id defaulted to
                    ``/services/{name}``, so a user entry claimed to live at
                    ``/services/admin`` rather than under its collection.
        updated:    ISO-8601 timestamp; defaults to now.

    Returns:
        A dict matching the Splunk entry structure.
    """
    if not updated:
        updated = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
    prefix = f"{_BASE_URL}/services/{collection}" if collection else f"{_BASE_URL}/services"
    entry_id = id_path or f"{prefix}/{quote(name, safe='')}"
    return {
        "name": name,
        "id": entry_id,
        "updated": updated,
        # splunklib reads `state.links.alternate` for every entity in a
        # collection (client.py: `parse.unquote(state.links.alternate)`), so an
        # entry without links raised AttributeError on every `.list()` call.
        "links": {
            "alternate": _rel_path(entry_id),
            "list": _rel_path(entry_id),
            "edit": _rel_path(entry_id),
            "remove": _rel_path(entry_id),
        },
        # `_parse_atom_metadata` hoists these into Entity.access / Entity.fields;
        # Splunk's own reference says they apply to all endpoints.
        "author": "nobody",
        "acl": _DEFAULT_ACL,
        "fields": {"required": [], "optional": [], "wildcard": []},
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
        "links": {"create": "/services", "_reload": "/services/_reload"},
        "origin": origin or f"{_BASE_URL}/services",
        "updated": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
        "generator": {"build": _SPLUNK_BUILD, "version": _SPLUNK_VERSION},
        "entry": entries,
        # perPage must describe the page actually returned; it was hardcoded to
        # 30 and contradicted responses carrying 48 entries.
        "paging": {
            "total": total,
            "perPage": per_page if per_page else len(entries),
            "offset": offset,
        },
        "messages": [],
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


#: splunkd does not label every failure the same way, and the label does not
#: track severity: an authentication failure ships as ``WARN`` even though a
#: permission failure ships as ``ERROR``. A client filtering on ``type`` sees
#: the difference, so the status has to pick the label. Only 401 is mapped —
#: splunkd is reported to use ``FATAL`` for an unknown search id, but its own
#: ``messages.conf`` declares that stanza ``severity = error``, so the label
#: there is left alone rather than guessed at.
_SPLUNK_MSG_TYPES: dict[int, str] = {
    401: "WARN",
}


def build_splunk_error(status: int, message: str) -> dict:
    """Build a Splunk error response body.

    Args:
        status:  HTTP status code.
        message: Error message.

    Returns:
        Splunk error envelope dict.
    """
    return {
        "messages": [
            {"type": _SPLUNK_MSG_TYPES.get(status, "ERROR"), "text": message},
        ],
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


#: HEC's own status→code table, from Splunk's documented error codes. HEC is a
#: separate service from splunkd and does not share its ``messages`` envelope.
_HEC_CODES: dict[int, int] = {
    400: 6,   # Invalid data format
    401: 2,   # Token is required
    403: 4,   # Invalid token
    404: 6,   # nothing more specific exists; the body still names the failure
    500: 8,   # Internal server error
    503: 9,   # Server is busy
}


def build_hec_error(status: int, message: str) -> dict:
    """Build a Splunk HTTP Event Collector error body.

    HEC answers with ``{"text": ..., "code": ...}`` where splunkd's management
    API answers with ``{"messages": [...]}``. They share a mount but not a
    format, so a client written against HEC cannot parse the other.

    Args:
        status:  HTTP status code.
        message: Human-readable error description.

    Returns:
        HEC error envelope dict.
    """
    return {"text": message, "code": _HEC_CODES.get(status, 8)}
