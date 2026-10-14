"""The URL of the next page: the one the client called, with the cursor moved.

Microsoft's paged APIs hand back an absolute link the client follows
verbatim -- Graph's and Defender's ``@odata.nextLink``
(:mod:`utils.odata_paging`) and ARM's ``nextLink`` (:mod:`utils.sentinel.pagination`).
Both rules are the same: keep the scheme, host, path and every query
parameter of the request, and replace only the page cursor. Each API spells
its cursor its own way, and that stays with the caller.
"""
from __future__ import annotations

from collections.abc import Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def with_cursor(
    url: str, cursor: str, value: str, *, replaces: Callable[[str], bool], safe: str = "",
) -> str:
    """*url* with every parameter *replaces* matches dropped and ``cursor=value`` appended.

    Args:
        url:      The URL of the current request, query string included.
        cursor:   The cursor's parameter name, as this API writes it.
        value:    Where the next page starts, as the cursor encodes it.
        replaces: Whether a query parameter name is a cursor of this API.
        safe:     Characters ``urlencode`` leaves unescaped.

    Returns:
        The absolute URL of the next page.
    """
    scheme, netloc, path, query, fragment = urlsplit(url)
    params = [
        (key, val) for key, val in parse_qsl(query, keep_blank_values=True)
        if not replaces(key)
    ]
    params.append((cursor, value))
    return urlunsplit((scheme, netloc, path, urlencode(params, safe=safe), fragment))
