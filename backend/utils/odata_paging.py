"""The ``@odata.nextLink`` a Microsoft Graph or Defender page hands back.

Graph's paging contract is one sentence: "Use the entire URL in the
``@odata.nextLink`` property in a GET request to retrieve the next page of
results ... Any other query parameters that were present in the original
request are also encoded in this URL"
(https://learn.microsoft.com/en-us/graph/paging). Defender's collections
follow the same OData rule.

Both mounts built the link as a fixed string on the real production host --
``https://graph.microsoft.com/v1.0/users?$skip=100`` and
``https://api.securitycenter.microsoft.com/api/machines?$top=..&$skip=..`` --
so a client following it verbatim left the mock for Microsoft, and even
pointed back at the mock it asked a different question: ``$filter``,
``$select``, ``$orderby`` and ``$search`` were gone, and the second page of a
filtered query was the second page of the whole estate.

The link is now built from the URL the client actually called -- scheme,
host, mount and every query parameter -- with only the page cursor advanced,
the way the Sentinel mount already did (``utils/sentinel/pagination.py``).
The request URL reaches the query handlers through a context variable set by
a router dependency on both mounts, rather than through a ``request``
argument threaded into some forty handler signatures.
"""
from __future__ import annotations

import base64
import binascii
from contextvars import ContextVar

from fastapi import HTTPException, Request

from utils.next_link import with_cursor

#: The URL of the request being served on the Graph or Defender mount.
_request_url: ContextVar[str | None] = ContextVar("odata_request_url", default=None)

#: The two page cursors Graph uses. Directory objects page with an opaque
#: ``$skiptoken``; Outlook, the security APIs and Intune with ``$skip``.
SKIP = "$skip"
SKIPTOKEN = "$skiptoken"

_CURSORS = frozenset({SKIP.lower(), SKIPTOKEN.lower()})

#: Prefix that makes the token recognisably this service's own.
_TOKEN_PREFIX = "mockdr-page:"


async def remember_request_url(request: Request) -> None:
    """Router dependency: keep the request URL for the next link.

    Async on purpose: an async dependency runs in the request's own context,
    so the value is visible to the handler whether it is a coroutine or a
    plain function run in the thread pool (which copies the context).
    """
    _request_url.set(str(request.url))


def encode_skiptoken(offset: int) -> str:
    """An opaque ``$skiptoken`` for the page starting at ``offset``.

    Graph says not to read the token ("Don't try to extract the $skiptoken
    ... value and use it in a different request"), so it is not a bare
    number a client could be tempted to compute.
    """
    raw = f"{_TOKEN_PREFIX}{offset}".encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_skiptoken(token: str) -> int:
    """The offset a ``$skiptoken`` from :func:`encode_skiptoken` stands for.

    Raises:
        HTTPException: 400 when the token is not one this service issued.
            Graph documents no specific code for a forged token, so the
            general ``Request_BadRequest`` answers it.
    """
    try:
        padded = token + "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(padded.encode()).decode()
        if not raw.startswith(_TOKEN_PREFIX):
            raise ValueError(raw)
        offset = int(raw[len(_TOKEN_PREFIX):])
        if offset < 0:
            raise ValueError(raw)
    except (ValueError, binascii.Error, UnicodeDecodeError) as exc:
        from utils.graph_response import build_graph_error_response  # noqa: PLC0415
        raise HTTPException(status_code=400, detail=build_graph_error_response(
            "Request_BadRequest",
            f"The specified page token value '{token}' is invalid. Follow the "
            f"@odata.nextLink returned by the previous page.",
        )) from exc
    return offset


def page_link(
    next_offset: int, total: int, *, fallback: str, cursor: str = SKIP,
) -> str | None:
    """The ``@odata.nextLink`` for the page that starts at ``next_offset``.

    Args:
        next_offset: Where the next page starts (``skip + top``).
        total:       How many records the filtered query matched.
        fallback:    Absolute URL of the collection, used only when the call
                     did not come through an HTTP request (a unit test, an
                     internal caller), where there is no URL to follow.
        cursor:      ``$skip``, or ``$skiptoken`` for directory objects.

    Returns:
        The absolute URL of the next page, or None on the last page.
    """
    if next_offset >= total:
        return None
    value = encode_skiptoken(next_offset) if cursor == SKIPTOKEN else str(next_offset)
    # `safe="$"` keeps the option names readable (`$top`, not `%24top`), as
    # Graph writes them; both spellings decode to the same request.
    return with_cursor(
        _request_url.get() or fallback, cursor, value,
        replaces=lambda key: key.lower() in _CURSORS, safe="$",
    )


def directory_page_offset(request: Request) -> int:
    """Route dependency for a directory-object collection: where the page starts.

    Directory objects -- users, groups, applications, service principals,
    directory roles, administrative units, the organization -- page with a
    ``$skiptoken`` and refuse ``$skip``: "Directory objects such as user,
    group, and application don't support $skip"
    (https://learn.microsoft.com/en-us/graph/query-parameters#skip), and
    ``user-list`` and ``group-list`` both say "$skip isn't supported". The
    service answers ``400 Request_BadRequest`` with "'$skip' is not supported
    by the service." -- the body quoted verbatim in
    https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/1420 for
    ``GET /v1.0/groups?$top=999&$skip=1000``. The mock took ``$skip`` on every
    one of them, so a client could ship a pager that cannot work in production.

    Query option names are matched case-insensitively, as OData's are.

    Raises:
        HTTPException: 400 on ``$skip`` or on a token this service never issued.
    """
    token = ""
    for key, value in request.query_params.multi_items():
        lowered = key.lower()
        if lowered == SKIP:
            from utils.graph_response import build_graph_error_response  # noqa: PLC0415
            raise HTTPException(status_code=400, detail=build_graph_error_response(
                "Request_BadRequest", "'$skip' is not supported by the service.",
            ))
        if lowered == SKIPTOKEN:
            token = value
    return decode_skiptoken(token) if token else 0
