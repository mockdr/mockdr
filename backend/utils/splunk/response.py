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

#: Which app owns each collection's entries, and under which user. Measured
#: on Splunk 10.4.2 by reading one entry per collection: an entry whose ACL
#: names an app is served with a *namespaced* id —
#: ``/servicesNS/{owner}/{app}/{collection}/{name}`` — and its links carry the
#: same prefix. mockdr rendered every id in the plain ``/services`` form, so a
#: client that parses the owner and app out of an id (splunklib's
#: ``Entity.path`` does, and so does every tool that decides where to write a
#: change back) found neither.
_NAMESPACES: dict[str, tuple[str, str]] = {
    "admin/macros": ("nobody", "search"),
    "alerts/fired_alerts": ("nobody", "search"),
    "apps/local": ("nobody", "system"),
    "data/indexes": ("nobody", "system"),
    "data/indexes-extended": ("nobody", "system"),
    "data/inputs/http": ("nobody", "splunk_httpinput"),
    "data/inputs/monitor": ("nobody", "system"),
    "data/inputs/tcp/raw": ("nobody", "system"),
    "data/lookup-table-files": ("nobody", "search"),
    "data/props/extractions": ("nobody", "system"),
    "data/transforms/lookups": ("nobody", "system"),
    "saved/eventtypes": ("nobody", "search"),
    "saved/searches": ("nobody", "search"),
    "saved/sourcetypes": ("nobody", "system"),
    "storage/collections/config": ("nobody", "system"),
}

#: Of those, the ones whose entries are *knowledge objects*: splunkd reports
#: four extra ACL members saying who may re-share them. A configuration
#: object — an index, a monitored file — carries none of the four.
_SHAREABLE: frozenset[str] = frozenset({
    "admin/macros", "apps/local", "data/inputs/http", "data/lookup-table-files",
    "data/props/extractions", "data/transforms/lookups", "saved/eventtypes",
    "saved/searches", "saved/sourcetypes",
})

#: ``sharing`` follows the app — an object in ``system`` is shared system-wide
#: and one in an app is shared app-wide — with a single measured exception:
#: an installed app is itself an app-level object whatever app it lives in.
_SHARING_EXCEPTIONS: dict[str, str] = {"apps/local": "app"}

#: The rest are the instance's own: splunkd reports them owned by ``system``
#: with no app at all, and their ids stay in the plain ``/services`` form.
#: ``search/jobs`` is the measured exception — a job's ACL names the user who
#: ran it and the app they ran it in, and its id is still not namespaced.
_SYSTEM_ACL: dict[str, object] = {
    "app": "", "owner": "system", "sharing": "system",
    "modifiable": False, "removable": False,
}
_NOT_NAMESPACED_WITH_AN_APP = frozenset({"search/jobs"})


def _scoped_acl(collection: str, acl: dict, overrides: dict) -> dict:
    """The ACL splunkd reports for an entry of this collection.

    A collection the instance owns is ``system``-scoped with no app; one that
    lives in an app carries that app and the user who owns the entry. What
    the caller passed in ``acl_extra`` still wins — a system index says so
    itself.
    """
    namespace = _NAMESPACES.get(collection)
    if namespace is None:
        return {**acl, **_SYSTEM_ACL, **overrides}
    owner, app = namespace
    scoped: dict[str, object] = {
        **acl, "owner": owner, "app": app,
        "sharing": _SHARING_EXCEPTIONS.get(
            collection, "system" if app == "system" else "app"),
        # A knowledge object is edited in place and unlinked from its app
        # rather than deleted; splunkd reports it modifiable and not
        # removable. An index says otherwise for itself, through `acl_extra`.
        "modifiable": True,
        "removable": False,
    }
    if collection in _SHAREABLE:
        scoped |= {
            "can_change_perms": True, "can_share_app": True,
            "can_share_global": True, "can_share_user": False,
        }
    return {**scoped, **overrides}


def _entry_id(collection: str, name: str, acl: dict) -> str:
    """An entry's id, namespaced when splunkd namespaces it.

    The namespace comes from the entry's own ACL rather than from the request
    path: asking for ``/servicesNS/nobody/search/data/indexes/main`` still
    answers with ``/servicesNS/nobody/system/…``, because that is where the
    index lives.
    """
    if not collection:
        return f"{_BASE_URL}/services/{quote(name, safe='')}"
    app = str(acl.get("app") or "")
    if not app or collection in _NOT_NAMESPACED_WITH_AN_APP:
        return f"{_BASE_URL}/services/{collection}/{quote(name, safe='')}"
    owner = str(acl.get("owner") or "nobody")
    return (f"{_BASE_URL}/servicesNS/{quote(owner, safe='')}/{quote(app, safe='')}"
            f"/{collection}/{quote(name, safe='')}")


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


#: What splunkd sends as an entity's `updated` when nothing has changed it.
_EPOCH = "1970-01-01T00:00:00+00:00"


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
        updated:    ISO-8601 timestamp for the *entity's* last change. It
                    defaults to the epoch, which is what splunkd sends for an
                    entity nothing has changed through the REST layer —
                    measured on 10.4.2 for `saved/searches` and `apps/local`,
                    while `data/indexes` and `authentication/users` carry a
                    real one. It used to default to *now*, so every entry
                    reported having just been updated, on every read: the
                    body changed once a second while nothing in it did, and
                    the ETag over it could never be revalidated.
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
        updated = _EPOCH
    entry_acl = acl if acl is not None else {**_DEFAULT_ACL, **(acl_extra or {})}
    if acl is None and collection:
        entry_acl = _scoped_acl(collection, entry_acl, acl_extra or {})
    entry_id = id_path or _entry_id(collection, name, entry_acl)
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
        "acl": entry_acl,
        "content": content,
    }
    if fields is True:
        entry["fields"] = {"required": [], "optional": [], "wildcard": []}
    elif fields:
        entry["fields"] = fields
    return entry


def _origin_of(entries: list[dict]) -> str:
    """The collection an envelope's entries belong to.

    splunkd names the collection here — ``…/services/data/indexes`` — and
    mockdr named ``…/services`` for every one of them, so a client reading
    `origin` to find out what it had asked for learned nothing. The entries
    know: their ids are that collection plus a name, and the namespaced form
    is reduced back to the plain one, which is what `origin` carries.
    """
    if not entries:
        return f"{_BASE_URL}/services"
    first = entries[0].get("id", "") if isinstance(entries[0], dict) else ""
    if not isinstance(first, str) or "/services" not in first:
        return f"{_BASE_URL}/services"
    path = first.split("/services", 1)[1]
    if path.startswith("NS/"):
        # /servicesNS/{owner}/{app}/{collection}/{name}
        parts = path[len("NS/"):].split("/")[2:]
    else:
        parts = path.lstrip("/").split("/")
    return f"{_BASE_URL}/services/" + "/".join(parts[:-1]) if len(parts) > 1 else (
        f"{_BASE_URL}/services")


def _default_top_links(origin: str) -> dict[str, str]:
    """Where a collection says a new member is created.

    splunkd points at the collection's own `_new` — `/services/messages/_new`
    for messages, `/services/authorization/roles/_new` for roles (measured
    across seventeen collections on 10.4.2). mockdr answered
    `{"create": "/services", "_reload": "/services/_reload"}` for every one
    of them: a create target that exists nowhere in splunkd, and a `_reload`
    most collections do not offer. A collection that offers more relations —
    `_reload`, `_acl`, `_validate` — or none at all names them itself.
    """
    path = origin.split("/services", 1)[-1] if "/services" in origin else ""
    path = path.rstrip("/")
    if not path or path == "/":
        return {}
    return {"create": f"/services{path}/_new"}


def build_splunk_envelope(
    entries: list[dict],
    *,
    total: int | None = None,
    offset: int = 0,
    per_page: int = 30,
    origin: str = "",
    collection: str = "",
    links: dict[str, str] | None = None,
    paging: bool = True,
    messages: bool = True,
) -> dict:
    """Build the full Splunk JSON response envelope.

    ``paging`` and ``messages`` are not universal: ``server/status`` carries
    no paging block and the job list no messages array (measured on 10.4.2).

    ``links`` replaces the derived ``create`` link when a collection offers
    more relations than that, or none — ``server/info`` has ``{}``.

    Args:
        entries:  List of entry dicts.
        total:    Total number of matching entries (defaults to len(entries)).
        offset:   Pagination offset.
        per_page: Page size.
        origin:   Origin URL for the response.
        collection: REST path of the collection, e.g. ``messages``. An empty
                  listing has no entry to read the collection off, so
                  without this it named neither its origin nor its links.
        links:    Top-level link relations; ``None`` to derive ``create``
                  from the collection the entries belong to.
        paging:   Emit the ``paging`` block.
        messages: Emit the ``messages`` array.

    Returns:
        Complete Splunk REST API JSON response.
    """
    if total is None:
        total = len(entries)
    origin_url = origin or (
        f"{_BASE_URL}/services/{collection.strip('/')}" if collection else _origin_of(entries)
    )
    envelope: dict = {
        "links": _default_top_links(origin_url) if links is None else links,
        "origin": origin_url,
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


# ---------------------------------------------------------------------------
# Search results envelope (used by /search/v2/jobs/{sid}/results)
# ---------------------------------------------------------------------------


def build_search_results(
    results: list[dict],
    *,
    fields: list[str] | list[dict] | None = None,
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
        envelope["fields"] = [
            dict(f) if isinstance(f, dict) else {"name": f} for f in fields
        ]
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
