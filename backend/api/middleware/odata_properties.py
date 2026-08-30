"""Refuse an OData query that names a property the resource does not have.

`$select=notAField` answered a page of empty objects, `$filter=notAField eq
'x'` an empty collection and `$orderby=notAField` an unsorted one — three
`200`s a client reads as "nothing matched" rather than "your query names
something that does not exist". Both products answer `400`.

Only a route one of the vendored references speaks for is judged, which is
53 of the Graph routes this mock serves and four of Defender's; a route
neither speaks for keeps answering as it did, because a refusal has to be
able to say what the resource *does* carry.

Pure ASGI, because the check has to know which route was matched and the
mount's routers are included in a loop rather than declared one by one: the
reference's own route templates are compiled to patterns here and matched
against the path.
"""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl

from starlette.types import ASGIApp, Receive, Scope, Send

from utils.mde_odata import parse_odata_filter
from utils.vendor_errors import build_vendor_error, vendor_for_path
from utils.vendor_properties import properties_by_route

_FIRST = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*")

#: Names that are not properties of the resource: the wildcard, and the
#: annotations every OData payload may carry.
_NOT_A_PROPERTY = frozenset({"*"})


def _named(expression: str) -> str:
    """The property one clause of `$select` or `$orderby` names."""
    match = _FIRST.match(expression.strip())
    return match.group(0) if match else ""


def _filter_fields(filter_str: str) -> set[str]:
    """Every property a `$filter` names, as far as it can be parsed."""
    try:
        root = parse_odata_filter(filter_str)
    except ValueError:
        # A filter that cannot be parsed is already refused downstream, with
        # the message the parser has for it.
        return set()
    found: set[str] = set()

    def walk(node: object) -> None:
        field = getattr(node, "field", None)
        if isinstance(field, str):
            found.add(_named(field))
        for child in (getattr(node, "left", None), getattr(node, "right", None)):
            if child is not None:
                walk(child)
        for child in getattr(node, "clauses", None) or ():
            walk(child)

    if root is not None:
        walk(root)
    return found


def _patterns() -> list[tuple[re.Pattern[str], frozenset[str]]]:
    """Each reference route as a pattern, longest (most specific) first."""
    compiled = []
    for route, allowed in properties_by_route().items():
        pattern = re.sub(r"\{[^}]+\}", "[^/]+", re.escape(route).replace("\\{", "{").replace(
            "\\}", "}"))
        compiled.append((re.compile(f"^{pattern}$"), allowed))
    compiled.sort(key=lambda entry: -len(entry[0].pattern))
    return compiled


_ROUTES = _patterns()


def _allowed_for(path: str) -> frozenset[str]:
    """What the resource at `path` carries, empty when nothing speaks for it."""
    for pattern, allowed in _ROUTES:
        if pattern.match(path):
            return allowed
    return frozenset()


def unknown_property(path: str, query: str) -> str:
    """The first property a query names that the resource does not have."""
    allowed = _allowed_for(path)
    if not allowed:
        return ""
    named: set[str] = set()
    for key, value in parse_qsl(query):
        if key in ("$select", "$orderby") and value:
            named |= {_named(clause) for clause in value.split(",")}
        elif key == "$filter" and value:
            named |= _filter_fields(value)
    # Case-insensitively, because the reference's own casing is not reliable:
    # its `machine` table says `onboardingstatus`, `software` says `Vendor`
    # and `Weaknesses`, `investigation` says `ID` and `State`, while every
    # neighbouring name in the same list is camelCase and the products answer
    # camelCase. Refusing a real property over a docs typo is the worse error
    # of the two, and a name that appears in no spelling is still refused.
    folded = {name.lower() for name in allowed}
    for name in sorted(named - _NOT_A_PROPERTY):
        if name and name.lower() not in folded:
            return name
    return ""


class ODataPropertyMiddleware:
    """Answer a query naming an unknown property the way the product does."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Refuse before the handler runs, or pass the request on."""
        if scope["type"] != "http" or scope.get("method") != "GET":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        # A client percent-encodes `$select` as `%24select`, so the raw query
        # string cannot be searched for the dollar — it is parsed instead.
        query = scope.get("query_string", b"").decode("latin-1")
        name = unknown_property(path, query) if query else ""
        if not name:
            await self.app(scope, receive, send)
            return

        body = json.dumps(build_vendor_error(
            vendor_for_path(path), 400, f"Could not find a property named '{name}'.",
        )).encode()
        await send({
            "type": "http.response.start",
            "status": 400,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        })
        await send({"type": "http.response.body", "body": body})
