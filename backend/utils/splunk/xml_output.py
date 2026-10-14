"""Atom/XML rendering for the Splunk REST API.

splunkd answers in Atom XML unless the caller asks for ``output_mode=json``.
The SDKs always ask, which is why JSON feels like the default — but a client
built on plain HTTP, or one that forgets the parameter, gets XML from the real
server. Serving JSON regardless would let such a client pass here and fail in
production.

The routers build JSON, and this module renders that same structure as the XML
splunkd would have produced, so both output modes stay in step by construction.
"""
from __future__ import annotations

from xml.sax.saxutils import escape, quoteattr

_ATOM_NS = (
    'xmlns="http://www.w3.org/2005/Atom" '
    'xmlns:s="http://dev.splunk.com/ns/rest" '
    'xmlns:opensearch="http://a9.com/-/spec/opensearch/1.1/"'
)

_HEADER = '<?xml version="1.0" encoding="UTF-8"?>\n'


def render_splunk_xml(payload: object, *, bare_entry: bool = False) -> str:
    """Render a Splunk JSON response body as the XML splunkd would return.

    Args:
        payload:    Decoded JSON body produced by a Splunk router.
        bare_entry: Render a one-entry feed as the ``<entry>`` document
                    splunkd answers a single search job with.

    Returns:
        XML document string.
    """
    if isinstance(payload, dict):
        if "sessionKey" in payload:
            return _render_session_key(str(payload["sessionKey"]))
        entries = payload.get("entry")
        if bare_entry and isinstance(entries, list) and len(entries) == 1:
            return _render_bare_entry(entries[0])
        if "entry" in payload:
            return _render_feed(payload)
        # The results envelope always carries a `messages` key, so testing for
        # messages first matched it here and rendered an empty <messages/> —
        # discarding every row in XML, which is splunkd's default output mode.
        if "results" in payload:
            return _render_results(payload)
        if "messages" in payload:
            return _render_messages(payload["messages"])
        if set(payload) == {"sid"}:
            return _render_sid(str(payload["sid"]))
    return _HEADER + f"<response>{_render_value(payload)}</response>"


# ---------------------------------------------------------------------------
# Document shapes
# ---------------------------------------------------------------------------

def _render_session_key(session_key: str) -> str:
    """Render the ``/services/auth/login`` response."""
    return _HEADER + f"<response>\n  <sessionKey>{escape(session_key)}</sessionKey>\n</response>"


def _render_sid(sid: str) -> str:
    """Render a dispatched job's ``<response><sid>`` document.

    splunkd answers ``POST /services/search/jobs`` with ``<response><sid>…
    </sid></response>``, and splunklib's ``Jobs.create`` reads it as
    ``_load_sid(response)`` -> ``_load_atom(response).response.sid``. The
    generic renderer wrapped the sid in ``<s:dict>`` -- under a prefix the
    document never declares, so the answer was not even well-formed XML and
    every ``jobs.create()`` died in the parser.
    """
    return _HEADER + f"<response>\n  <sid>{escape(sid)}</sid>\n</response>"


def _render_messages(messages: object) -> str:
    """Render a bare ``<response><messages>`` document."""
    rendered = []
    for message in messages if isinstance(messages, list) else []:
        if not isinstance(message, dict):
            continue
        msg_type = escape(str(message.get("type", "INFO")))
        text = escape(str(message.get("text", "")))
        rendered.append(f'    <msg type="{msg_type}">{text}</msg>')
    body = "\n".join(rendered)
    return _HEADER + f"<response>\n  <messages>\n{body}\n  </messages>\n</response>"


def _render_feed(payload: dict) -> str:
    """Render the Atom feed used by every ``entry``-shaped endpoint."""
    paging = payload.get("paging") or {}
    generator = payload.get("generator") or {}
    parts = [
        _HEADER,
        f"<feed {_ATOM_NS}>\n",
        f"  <id>{escape(str(payload.get('origin', '')))}</id>\n",
        f"  <updated>{escape(str(payload.get('updated', '')))}</updated>\n",
    ]
    if generator:
        build = quoteattr(str(generator.get("build", "")))
        version = quoteattr(str(generator.get("version", "")))
        parts.append(f"  <generator build={build} version={version}/>\n")
    if paging:
        parts.append(
            f"  <opensearch:totalResults>{int(paging.get('total', 0))}"
            f"</opensearch:totalResults>\n"
            f"  <opensearch:itemsPerPage>{int(paging.get('perPage', 0))}"
            f"</opensearch:itemsPerPage>\n"
            f"  <opensearch:startIndex>{int(paging.get('offset', 0))}"
            f"</opensearch:startIndex>\n",
        )
    for entry in payload.get("entry") or []:
        parts.append(_render_entry(entry))
    parts.append("</feed>")
    return "".join(parts)


def _render_bare_entry(entry: object) -> str:
    """Render one entry as a document of its own, the root ``<entry>``.

    That is how splunkd answers ``GET /services/search/jobs/{sid}`` in XML,
    and splunklib's ``Job`` depends on it: it overrides
    ``_load_atom_entry`` with ``_load_atom(response).entry``, which reads the
    *root* element's name, where every other entity searches a feed for its
    entries (``splunklib/client.py``, ``Job._load_atom_entry``). Served as a
    feed, every ``job.is_done()`` raised ``AttributeError: entry`` -- a job
    could be dispatched and never polled.
    """
    body = _render_entry(entry)
    if not body:
        return _HEADER + "<entry/>"
    inner = body.removeprefix("  <entry>\n").removesuffix("  </entry>\n")
    return _HEADER + f"<entry {_ATOM_NS}>\n" + inner + "</entry>"


def _render_entry(entry: object) -> str:
    """Render one Atom ``<entry>``.

    splunkd's entry carries its ``<link>``s, the ``alternate`` first and the
    ``<author>`` after it, and the entity's ACL inside its content as
    ``eai:acl`` -- the JSON form lifts that out to ``acl`` and leaves
    ``eai:acl`` null in the content. This rendered title, id, updated and
    content alone, and splunklib, which reads Atom unless told otherwise,
    could not list a single collection: ``Collection.list()`` builds every
    entity from ``state.links.alternate`` (``splunklib/client.py``,
    ``_entity_path``) and raised ``AttributeError: alternate`` on the first.
    """
    if not isinstance(entry, dict):
        return ""
    raw = entry.get("content", {})
    acl = entry.get("acl")
    if isinstance(raw, dict) and isinstance(acl, dict) and not raw.get("eai:acl"):
        raw = {**raw, "eai:acl": acl}
    content = _render_value(raw)
    links = entry.get("links")
    links = links if isinstance(links, dict) else {}
    ordered = sorted(links.items(), key=lambda item: item[0] != "alternate")
    rendered_links = [
        f"    <link href={quoteattr(str(href))} rel={quoteattr(str(rel))}/>\n"
        for rel, href in ordered
    ]
    author = entry.get("author")
    head = rendered_links[:1] if ordered and ordered[0][0] == "alternate" else []
    tail = rendered_links[len(head):]
    return (
        "  <entry>\n"
        f"    <title>{escape(str(entry.get('name', '')))}</title>\n"
        f"    <id>{escape(str(entry.get('id', '')))}</id>\n"
        f"    <updated>{escape(str(entry.get('updated', '')))}</updated>\n"
        + "".join(head)
        + (f"    <author>\n      <name>{escape(str(author))}</name>\n    </author>\n"
           if author else "")
        + "".join(tail)
        + f'    <content type="text/xml">{content}</content>\n'
        "  </entry>\n"
    )


#: The results document has a declaration of its own: single-quoted, with a
#: blank line under it. splunkd writes it that way, and a client comparing
#: bytes — or a test fixture recorded from the real thing — sees the
#: difference.
_RESULTS_HEADER = "<?xml version='1.0' encoding='UTF-8'?>\n\n"


def _render_results(payload: dict) -> str:
    """Render search results in the ``<results>`` shape splunkd uses.

    The document names its fields once in a ``<meta>`` block, numbers each
    result with the offset a client pages by, and repeats ``<value>`` for a
    multivalue field. mockdr wrote none of that — no meta, no offsets — so a
    reader built on the real document found no fields at all.
    """
    results = payload.get("results")
    rows = [row for row in (results if isinstance(results, list) else []) if isinstance(row, dict)]
    if not rows:
        # Nothing to show is an empty element, not an empty document.
        return _RESULTS_HEADER + "<results preview='0'/>"

    names = [
        str(field.get("name")) for field in payload.get("fields") or []
        if isinstance(field, dict) and field.get("name")
    ] or list(dict.fromkeys(key for row in rows for key in row))

    parts = [_RESULTS_HEADER, "<results preview='0'>\n<meta>\n<fieldOrder>\n"]
    parts += [f"<field>{escape(name)}</field>\n" for name in names]
    parts.append("</fieldOrder>\n</meta>\n")
    for offset, row in enumerate(rows):
        parts.append(f"\t<result offset='{offset}'>\n")
        for key, value in row.items():
            parts.append(f"\t\t<field k={_single_quoted(str(key))}>\n")
            for one in value if isinstance(value, list) else [value]:
                parts.append(f"\t\t\t<value><text>{escape(str(one))}</text></value>\n")
            parts.append("\t\t</field>\n")
        parts.append("\t</result>\n")
    parts.append("</results>\n")
    return "".join(parts)


def _single_quoted(text: str) -> str:
    """An attribute value in single quotes, which is how splunkd writes them."""
    return "'" + escape(text, {"'": "&apos;"}) + "'"


# ---------------------------------------------------------------------------
# Value rendering (s:dict / s:list)
# ---------------------------------------------------------------------------

def _render_value(value: object) -> str:
    """Render an arbitrary JSON value as Splunk's ``s:`` typed markup."""
    if isinstance(value, dict):
        keys = "".join(
            f"<s:key name={quoteattr(str(k))}>{_render_value(v)}</s:key>"
            for k, v in value.items()
        )
        return f"<s:dict>{keys}</s:dict>"
    if isinstance(value, list):
        items = "".join(f"<s:item>{_render_value(v)}</s:item>" for v in value)
        return f"<s:list>{items}</s:list>"
    if value is None:
        return ""
    if isinstance(value, bool):
        return "1" if value else "0"
    return escape(str(value))
