"""Middleware honouring Splunk's ``output_mode`` query parameter.

splunkd serves Atom XML by default and JSON only on request. The routers build
JSON — the SDKs ask for it, and it is far easier to work with — so this
middleware renders that body as XML whenever the caller did *not* ask for JSON,
which is what the real server would have done.

HEC (``/services/collector``) is exempt: it is a separate service that always
answers in JSON and ignores ``output_mode``.

Pure ASGI: a request outside ``/splunk`` never reaches the body-collecting
path, and a Splunk request that asked for JSON is passed straight through.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qs
from xml.sax.saxutils import escape

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from api.middleware.json_rewrite import rewrite_json_body
from utils.splunk.csv_output import render_splunk_csv
from utils.splunk.xml_output import render_splunk_xml

_SPLUNK_PREFIX = "/splunk"
_HEC_PREFIX = "/splunk/services/collector"
# The KV Store *data* API is JSON-only in real Splunk — output_mode does not
# apply to it. splunklib proves it: KVStoreCollectionData.query() calls
# json.loads on the body and never sends output_mode. Rendering Atom XML
# here broke every SDK KV Store call unconditionally.
_KVSTORE_DATA_MARKER = "/storage/collections/data/"
_FORM_TYPE = b"application/x-www-form-urlencoded"

#: The modes splunkd knows. A value outside them — including an empty one —
#: is `Invalid output mode specified (x).`; one it knows but the handler does
#: not serve is a WARN naming it. Both always render as XML, because the mode
#: it was asked to answer in is the thing it could not use (measured on
#: 10.4.2).
_KNOWN_OUTPUT_MODES = frozenset({"json", "xml", "csv", "atom", "raw"})

#: What this mock renders.
_OUTPUT_MODES = frozenset({"json", "xml", "csv"})

#: Where `output_mode=csv` is answered rather than refused: a job's results
#: and events, the job itself, and the job collection. Every other endpoint
#: refuses it, in splunkd's own words for a mode it knows but will not serve
#: there (all measured on 10.4.2).
_CSV_COLLECTION = "/splunk/services/search/jobs"

#: The `events` endpoint sorts its columns by name; `results` keeps the order
#: the search produced, and a job entry keeps splunkd's own key order — which
#: is neither, and not derivable from outside, so mockdr keeps its own.
_CSV_SORTED_SUFFIX = "/events"

#: A oneshot search puts a line for its messages before the header: empty
#: when it produced none, a single space when it did. A job's own `/results`
#: has no such line (measured on 10.4.2).
_CSV_MESSAGE_LINE = {True: " \n", False: "\n"}

#: A collection sorts one way or the other. mockdr took any word and sorted
#: the default way without saying so.
_SORT_DIRECTIONS = frozenset({"asc", "desc"})

#: Two handlers do not check the sort direction, because they do not sort:
#: `properties` is a flat config tree and `receivers/stream` is an ingest
#: socket (both measured).
_NO_SORT_CHECK = ("/splunk/services/properties", "/splunk/services/receivers/stream")

#: The job collection sorts on several keys at once, so it pairs each
#: `sort_key` with a `sort_dir` and refuses a mismatch rather than checking
#: the direction against an enum (measured on 10.4.2).
_PAIRED_SORT = "/splunk/services/search/jobs"
_SORT_MISMATCH = "Number of sort_key and sort_dir arguments do not match."

#: The arguments a collection handler declares. Anything else is refused by
#: name — which is how splunkd tells a client its parameter did nothing.
_COLLECTION_ARGS = frozenset({
    "count", "offset", "search", "sort_key", "sort_dir", "sort_mode", "f",
    "add_orphan_field", "output_mode",
})

#: The collections that refuse an argument they do not declare. The others
#: take anything: `search/jobs` and `data/inputs/http` have handlers of their
#: own, and `properties` and `configs/*` address a config tree by name (all
#: measured on 10.4.2).
_STRICT_COLLECTIONS = (
    "/splunk/services/saved/searches",
    "/splunk/services/data/indexes",
    "/splunk/services/apps/local",
    "/splunk/services/authentication/users",
    "/splunk/services/authorization/roles",
    "/splunk/services/alerts/fired_alerts",
    "/splunk/services/server/info",
    "/splunk/services/server/settings",
    "/splunk/services/data/ui/views",
    "/splunk/services/messages",
    "/splunk/services/cluster/config",
    "/splunk/services/licenser/licenses",
)


class SplunkOutputModeMiddleware:
    """Render Splunk responses as XML unless ``output_mode=json`` was given."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Convert a JSON Splunk response body to Atom XML when appropriate."""
        path = scope.get("path", "")
        if (
            scope["type"] != "http"
            or not path.startswith(_SPLUNK_PREFIX)
            or path.startswith(_HEC_PREFIX)
        ):
            await self.app(scope, receive, send)
            return

        query = parse_qs(scope.get("query_string", b"").decode("latin-1"), keep_blank_values=True)
        refusal = _refusal(path, query)
        if refusal is not None:
            await _send_refusal(send, *refusal)
            return
        mode = _values(query, "output_mode").lower()
        wants_json = mode == "json"
        if not wants_json and _is_form_post(scope):
            # splunklib's post() puts every parameter, output_mode included,
            # into the form body; reading only the query string rendered every
            # SDK form POST as Atom XML. The body is replayed to the route.
            body, receive = await _buffered_body(receive)
            form = parse_qs(body.decode("latin-1"))
            mode = _values(form, "output_mode").lower() or mode
            wants_json = mode == "json"

        if wants_json:
            await self.app(scope, receive, send)
            return

        if mode == "csv":
            oneshot = scope.get("method") == "POST" and path.rstrip("/") == _CSV_COLLECTION
            await rewrite_json_body(
                self.app, scope, receive, send,
                claims=lambda status, _headers: status < 400,
                rewrite=lambda payload: _csv_body(payload, path, oneshot=oneshot),
            )
            return

        def claims(status: int, _headers: dict[bytes, bytes]) -> bool:
            # Only the KV Store *data* itself is JSON-only. A refusal — no such
            # collection, a query that is not JSON — comes back as Atom XML on
            # splunkd like any other error (measured on 10.4.2).
            return not (_KVSTORE_DATA_MARKER in path and status < 400)

        await rewrite_json_body(
            self.app, scope, receive, send,
            claims=claims,
            rewrite=lambda payload: (
                render_splunk_xml(payload).encode(),
                "text/xml; charset=UTF-8",
            ),
        )


def _refusal(
    path: str, query: dict[str, list[str]],
) -> tuple[str, bool, str] | None:
    """What splunkd would refuse this request with, or ``None`` to serve it.

    Returns the message, whether it renders as JSON — an unreadable
    ``output_mode`` always renders as XML, because that is the thing it could
    not read — and the severity, which is FATAL for the one refusal the job
    collection raises and ERROR for the rest.
    """
    modes = query.get("output_mode")
    if modes is not None and (
        modes[0].lower() not in _OUTPUT_MODES
        or (modes[0].lower() == "csv" and not _serves_csv(path))
    ):
        if modes[0].lower() in _KNOWN_OUTPUT_MODES:
            return (
                f"Output mode '{modes[0]}' is not supported for this endpoint.",
                False, "WARN",
            )
        return f"Invalid output mode specified ({modes[0]}).", False, "ERROR"

    as_json = _values(query, "output_mode").lower() == "json"
    directions = query.get("sort_dir")
    if path.rstrip("/") == _PAIRED_SORT:
        if len(directions or ()) != len(query.get("sort_key") or ()):
            return _SORT_MISMATCH, as_json, "FATAL"
    elif (
        directions is not None
        and directions[0].lower() not in _SORT_DIRECTIONS
        and not path.startswith(_NO_SORT_CHECK)
    ):
        return f'Unknown sort order "{directions[0]}".', as_json, "ERROR"

    if path.rstrip("/").startswith(_STRICT_COLLECTIONS):
        for name in query:
            if name not in _COLLECTION_ARGS:
                return (
                    f'Argument "{name}" is not supported by this handler.',
                    as_json, "ERROR",
                )
    return None


async def _send_refusal(
    send: Send, message: str, as_json: bool, level: str,
) -> None:
    """Answer with splunkd's refusal, in the shape the caller asked for."""
    if as_json:
        body = json.dumps({"messages": [{"type": level, "text": message}]}).encode()
        content_type = b"application/json; charset=UTF-8"
    else:
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>\n<response>\n  <messages>\n'
            f'    <msg type="{level}">{escape(message)}</msg>\n'
            "  </messages>\n</response>\n"
        ).encode()
        content_type = b"text/xml; charset=UTF-8"
    await send({
        "type": "http.response.start", "status": 400,
        "headers": [(b"content-type", content_type),
                    (b"content-length", str(len(body)).encode())],
    })
    await send({"type": "http.response.body", "body": body})


def _csv_body(payload: object, path: str, *, oneshot: bool) -> tuple[bytes, str]:
    """The CSV document for this response, and the type splunkd sends with it.

    A oneshot search always answers as CSV, behind a line for its messages,
    even when it matched nothing. A job's own ``/results`` has no such line,
    and comes back empty as ``text/plain`` when there is nothing to render.
    """
    document = render_splunk_csv(
        payload, sort_columns=path.rstrip("/").endswith(_CSV_SORTED_SUFFIX),
    )
    if oneshot:
        messages = bool((payload or {}).get("messages")) if isinstance(payload, dict) else False
        return (_CSV_MESSAGE_LINE[messages] + document).encode(), "text/csv; charset=UTF-8"
    if not document:
        return b"", "text/plain; charset=UTF-8"
    return document.encode(), "text/csv; charset=UTF-8"


def _serves_csv(path: str) -> bool:
    """Whether this endpoint answers `output_mode=csv` at all."""
    return path.rstrip("/").startswith(_CSV_COLLECTION)


def _values(query: dict[str, list[str]], name: str) -> str:
    values = query.get(name)
    return values[0] if values else ""


def _is_form_post(scope: Scope) -> bool:
    if scope.get("method") != "POST":
        return False
    for name, value in scope.get("headers", []):
        if name.lower() == b"content-type":
            return bool(value.startswith(_FORM_TYPE))
    return False


async def _buffered_body(receive: Receive) -> tuple[bytes, Receive]:
    """Read the request body, and a ``receive`` that replays it to the route."""
    chunks: list[bytes] = []
    more = True
    while more:
        message = await receive()
        if message["type"] == "http.disconnect":
            break
        chunks.append(bytes(message.get("body", b"")))
        more = bool(message.get("more_body"))
    body = b"".join(chunks)
    replayed = False

    async def replay() -> Message:
        nonlocal replayed
        if replayed:
            return await receive()
        replayed = True
        return {"type": "http.request", "body": body, "more_body": False}

    return body, replay
