"""CrowdStrike offset/limit pagination utility.

CrowdStrike APIs use simple offset-based pagination rather than the
cursor-based pagination used by SentinelOne.
"""
from __future__ import annotations

import base64

from utils.cs_response import build_cs_error_response


def paginate_cs(
    items: list,
    offset: int = 0,
    limit: int = 100,
) -> tuple[list, int]:
    """Paginate items using CrowdStrike's offset/limit pattern.

    Args:
        items:  Full list of items to paginate.
        offset: Starting offset (zero-based index).
        limit:  Maximum number of items per page.

    Returns:
        ``(page, total)`` tuple where *page* is the sliced subset and
        *total* is the full item count before slicing.
    """
    total = len(items)
    page = items[offset: offset + limit]
    return page, total


#: What every token this mount issues begins with once decoded, so a token
#: from somewhere else is recognised as one rather than read as a number.
_TOKEN_PREFIX = "mockdr-cs:"


def encode_page_token(index: int) -> str:
    """An opaque continuation token for the record at *index*.

    Falcon's scroll ``offset`` and its ``after`` are tokens a client hands
    back unread — falconpy's scrolling samples say so ("This will be a
    token string") — and the mock issued the bare index, ``"100"``. A
    client that treats it as the opaque string it is works either way; one
    that builds on it, or a token from the real product replayed here, did
    not, and the mock's ``int(offset)`` turned the second into a 500.
    """
    raw = f"{_TOKEN_PREFIX}{index}".encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_page_token(token: str | None) -> int:
    """The index a token from :func:`encode_page_token` stands for.

    No token is the first page. Anything this mount did not issue is the
    caller's mistake and is refused with a 400 in Falcon's ``errors``
    envelope, not a 500: a 500 tells a client to retry the same request,
    which fails the same way for as long as it tries. How Falcon itself
    words this refusal is unmeasured.
    """
    if not token:
        return 0
    try:
        padded = token + "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(padded.encode()).decode()
        if not raw.startswith(_TOKEN_PREFIX):
            raise ValueError(token)
        index = int(raw[len(_TOKEN_PREFIX):])
        if index < 0:
            raise ValueError(token)
    except ValueError as exc:  # binascii.Error and UnicodeDecodeError are ValueErrors
        from fastapi import HTTPException  # noqa: PLC0415 - as in cs_response

        raise HTTPException(status_code=400, detail=build_cs_error_response(
            400, f"invalid pagination token: {token}",
        )) from exc
    return index
