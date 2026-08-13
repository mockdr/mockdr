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


def render_splunk_xml(payload: object) -> str:
    """Render a Splunk JSON response body as the XML splunkd would return.

    Args:
        payload: Decoded JSON body produced by a Splunk router.

    Returns:
        XML document string.
    """
    if isinstance(payload, dict):
        if "sessionKey" in payload:
            return _render_session_key(str(payload["sessionKey"]))
        if "messages" in payload and "entry" not in payload:
            return _render_messages(payload["messages"])
        if "entry" in payload:
            return _render_feed(payload)
        if "results" in payload:
            return _render_results(payload["results"])
    return _HEADER + f"<response>{_render_value(payload)}</response>"


# ---------------------------------------------------------------------------
# Document shapes
# ---------------------------------------------------------------------------

def _render_session_key(session_key: str) -> str:
    """Render the ``/services/auth/login`` response."""
    return _HEADER + f"<response>\n  <sessionKey>{escape(session_key)}</sessionKey>\n</response>"


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


def _render_entry(entry: object) -> str:
    """Render one Atom ``<entry>``."""
    if not isinstance(entry, dict):
        return ""
    content = _render_value(entry.get("content", {}))
    return (
        "  <entry>\n"
        f"    <title>{escape(str(entry.get('name', '')))}</title>\n"
        f"    <id>{escape(str(entry.get('id', '')))}</id>\n"
        f"    <updated>{escape(str(entry.get('updated', '')))}</updated>\n"
        f'    <content type="text/xml">{content}</content>\n'
        "  </entry>\n"
    )


def _render_results(results: object) -> str:
    """Render search results in the ``<results>`` shape splunkd uses."""
    rows = []
    for row in results if isinstance(results, list) else []:
        if not isinstance(row, dict):
            continue
        fields = "".join(
            f"    <field k={quoteattr(str(key))}><value><text>{escape(str(value))}"
            f"</text></value></field>\n"
            for key, value in row.items()
        )
        rows.append(f"  <result>\n{fields}  </result>\n")
    return _HEADER + f'<results preview="0">\n{"".join(rows)}</results>'


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
