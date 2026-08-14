"""ARM pagination helpers for the Sentinel mock.

Azure Resource Manager pages with an opaque ``$skipToken`` and returns an
absolute ``nextLink`` that a client is meant to follow verbatim. This mock
encodes the offset in the token, but the two rules that matter to a client
still hold: a token it did not receive is rejected rather than crashing the
request, and the link it gets back is one it can actually call.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi import HTTPException

from utils.sentinel.response import build_arm_error


def parse_skip_token(skip_token: str) -> int:
    """Decode a ``$skipToken`` into a record offset.

    Args:
        skip_token: Raw token from the query string; empty means the first page.

    Returns:
        Zero-based offset into the result set.

    Raises:
        HTTPException: 400 if the token is not one this service issued.
    """
    if not skip_token:
        return 0
    try:
        offset = int(skip_token)
    except ValueError:
        offset = -1
    if offset < 0:
        raise HTTPException(
            status_code=400,
            detail=build_arm_error(
                "InvalidSkipToken",
                f"The skip token '{skip_token}' is invalid. Follow the "
                f"nextLink returned by the previous page.",
            ),
        )
    return offset


def build_next_link(request_url: str, next_offset: int) -> str:
    """Build the absolute ``nextLink`` for the following page.

    Args:
        request_url: Full URL of the current request, query string included.
        next_offset: Offset the next page starts at.

    Returns:
        Absolute URL with ``$skipToken`` set to ``next_offset``, preserving
        every other query parameter (``api-version``, ``$filter``, ...).
    """
    scheme, netloc, path, query, fragment = urlsplit(request_url)
    params = [(k, v) for k, v in parse_qsl(query, keep_blank_values=True) if k != "$skipToken"]
    params.append(("$skipToken", str(next_offset)))
    return urlunsplit((scheme, netloc, path, urlencode(params), fragment))
