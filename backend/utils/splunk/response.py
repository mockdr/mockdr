"""Splunk REST API response envelope builders.

Splunk wraps all REST responses in an Atom-style JSON envelope with ``entry[]``,
``paging``, ``links``, and ``generator`` fields.  Search results use a simpler
``{"results": [...], "fields": [...]}`` envelope.
"""
from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path
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


_SELF_LINKS = frozenset({"alternate", "list", "edit", "remove"})

_FIXTURES = Path(__file__).resolve().parents[2] / "infrastructure" / "fixtures" / "splunk"
_FIXTURE_CACHE: dict[str, dict] = {}


def _fixture(fixture: str) -> dict:
    path = _FIXTURES / f"{fixture}.json"
    return json.loads(path.read_text()) if path.exists() else {}


def fixture_links(fixture: str) -> tuple[str, ...]:
    """The link relations a real entry of this collection carries."""
    return tuple(_fixture(fixture).get("links") or ())


def fixture_top_links(fixture: str) -> dict[str, str]:
    """The top-level links a real list of this collection carries."""
    return dict(_fixture(fixture).get("top_links") or {})


def complete(content: dict, fixture: str) -> dict:
    """Fill a content block out to every key the real collection carries.

    A real saved search has 217 content keys, an index 113, a job 34;
    mockdr's builders produce a dozen. The rest come from a recorded entry
    (``infrastructure/fixtures/splunk/<fixture>.json``, taken from Splunk
    10.4.2 with volatile values neutralised), and the mock's own values win
    wherever it has one. A client that reads ``defaultTTL`` or
    ``maxTotalDataSizeMB`` finds the key, with a type-correct value.
    """
    if fixture not in _FIXTURE_CACHE:
        path = _FIXTURES / f"{fixture}.json"
        _FIXTURE_CACHE[fixture] = json.loads(path.read_text())["content"] if path.exists() else {}
    return {**_FIXTURE_CACHE[fixture], **content}


def build_splunk_entry(
    name: str,
    content: dict,
    *,
    id_path: str = "",
    collection: str = "",
    updated: str = "",
    links: tuple[str, ...] = ("alternate", "list", "edit", "remove"),
    fields: dict | None | bool = True,
    acl_extra: dict | None = None,
    acl: dict | None = None,
    published: str | None = None,
) -> dict:
    """Build a single Splunk ``entry`` object.

    ``links``, ``fields`` and ``acl_extra`` exist because splunkd is not
    uniform: ``server/info`` carries only ``alternate`` and ``list`` and no
    ``fields`` block; an app carries ``_reload`` and ``package`` and four
    extra ``can_share_*`` ACL members. The defaults are what most
    collections use, and what every existing caller got before.

    Args:
        name:       Entry name / identifier.
        content:    The actual data payload.
        id_path:    Optional full URL-like ID path.
        collection: REST path of the owning collection, e.g.
                    ``authentication/users``. Without it the id defaulted to
                    ``/services/{name}``, so a user entry claimed to live at
                    ``/services/admin`` rather than under its collection.
        updated:    ISO-8601 timestamp; defaults to now.
        links:      Which link relations the entry offers. ``_reload`` and
                    ``package`` get their own path suffix, as on splunkd.
        fields:     ``True`` for the empty default block, ``False`` for none,
                    or an explicit block.
        acl_extra:  Members merged over the default ACL.
        acl:        A complete ACL, for collections whose members differ (jobs).
        published:  Creation timestamp; only jobs carry one.

    Returns:
        A dict matching the Splunk entry structure.
    """
    if not updated:
        updated = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
    prefix = f"{_BASE_URL}/services/{collection}" if collection else f"{_BASE_URL}/services"
    entry_id = id_path or f"{prefix}/{quote(name, safe='')}"
    entry: dict = {
        "name": name,
        "id": entry_id,
        "updated": updated,
        **({"published": published} if published else {}),
        # splunklib reads `state.links.alternate` for every entity in a
        # collection (client.py: `parse.unquote(state.links.alternate)`), so an
        # entry without links raised AttributeError on every `.list()` call.
        # Four relations point at the entity itself; every other one — control,
        # events, results, dispatch, disable, embed, history, move, _reload,
        # package — is a sub-path named after itself (measured across eight
        # collections on 10.4.2).
        "links": {
            rel: _rel_path(entry_id) + ("" if rel in _SELF_LINKS else f"/{rel}")
            for rel in links
        },
        # `_parse_atom_metadata` hoists these into Entity.access / Entity.fields;
        # Splunk's own reference says they apply to all endpoints.
        "author": "nobody",
        "acl": acl if acl is not None else {**_DEFAULT_ACL, **(acl_extra or {})},
        "content": content,
    }
    if fields is True:
        entry["fields"] = {"required": [], "optional": [], "wildcard": []}
    elif fields:
        entry["fields"] = fields
    return entry


def build_splunk_envelope(
    entries: list[dict],
    *,
    total: int | None = None,
    offset: int = 0,
    per_page: int = 30,
    origin: str = "",
    links: dict[str, str] | None = None,
    paging: bool = True,
    messages: bool = True,
) -> dict:
    """Build the full Splunk JSON response envelope.

    ``paging`` and ``messages`` are not universal: ``server/status`` carries
    no paging block and the job list no messages array (measured on 10.4.2).

    ``links`` replaces the default ``create``/``_reload`` pair when a
    collection does not offer them — ``server/info`` has ``{}``.

    Args:
        entries:  List of entry dicts.
        total:    Total number of matching entries (defaults to len(entries)).
        offset:   Pagination offset.
        per_page: Page size.
        origin:   Origin URL for the response.
        links:    Top-level link relations; ``None`` for the default pair.
        paging:   Emit the ``paging`` block.
        messages: Emit the ``messages`` array.

    Returns:
        Complete Splunk REST API JSON response.
    """
    if total is None:
        total = len(entries)
    envelope: dict = {
        "links": (
            {"create": "/services", "_reload": "/services/_reload"} if links is None else links
        ),
        "origin": origin or f"{_BASE_URL}/services",
        "updated": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
        "generator": {"build": _SPLUNK_BUILD, "version": _SPLUNK_VERSION},
        "entry": entries,
        # perPage must describe the page actually returned; it was hardcoded to
        # 30 and contradicted responses carrying 48 entries.
    }
    if paging:
        envelope["paging"] = {
            "total": total,
            "perPage": per_page if per_page else len(entries),
            "offset": offset,
        }
    if messages:
        envelope["messages"] = []
    return envelope


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

    The envelope splunkd sends depends on whether there are rows: a page with
    results carries ``fields`` and ``highlighted``, an empty one carries
    ``post_process_count`` instead and neither of those. ``preview`` is always
    there and always false for a finished search — splunklib's
    ``JSONResultsReader`` asserts on it, and it was absent here entirely.
    """
    rendered = [_render_row(row) for row in results]
    envelope: dict = {
        "preview": False,
        "init_offset": init_offset,
        "messages": messages or [],
        "results": rendered,
    }
    if rendered:
        if fields is None:
            fields = list(results[0].keys())
        envelope["fields"] = [{"name": f} for f in fields]
        envelope["highlighted"] = {}
    else:
        envelope["post_process_count"] = 0
    return envelope


def _render_row(row: dict) -> dict:
    """Render a result row the way splunkd does — every value a string.

    Splunk results are strings, or lists of strings for multivalue fields;
    JSON numbers and booleans leaked the mock's internal types through, so a
    client doing ``int(row["count"])`` worked here and a client comparing
    ``row["count"] == "38"`` — which is what real Splunk returns — did not.
    """
    # A search over 600 events renders ~13 000 fields; most of them are
    # already strings, so that case skips the type ladder entirely.
    out: dict[str, str | list[str]] = {}
    for key, value in row.items():
        if key == "_time":
            out[key] = _render_time(value)
        elif type(value) is str:
            out[key] = value
        elif isinstance(value, (list, tuple)):
            out[key] = _multivalue(value)
        else:
            out[key] = _scalar(value)
    return out


def _render_time(value: object) -> str:
    """Render ``_time`` the way splunkd's JSON writer does.

    ``2026-08-23T15:46:40.000+00:00``, not the epoch the pipeline sorts on.
    Every SIEM integration parses this field, and an epoch float here against
    an ISO-8601 string in production is the kind of difference that only
    shows up once the client is pointed at the real thing.
    """
    try:
        moment = datetime.fromtimestamp(float(str(value)), tz=UTC)
    except (TypeError, ValueError, OSError, OverflowError):
        return _scalar(value)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}+00:00"


def _multivalue(value: list | tuple) -> str | list[str]:
    """Render a multivalue field as splunkd's JSON writer does.

    A field holding one value is a plain string there, not a one-element
    array — `stats values(user)` over a group with a single user comes back
    as `"alice"`. A client reading it as a string worked against splunkd and
    got `["alice"]` here.
    """
    rendered = [_scalar(v) for v in value]
    return rendered[0] if len(rendered) == 1 else rendered


def _render_value(value: object) -> str | list[str]:
    if isinstance(value, (list, tuple)):
        return _multivalue(value)
    return _scalar(value)


def _scalar(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


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
