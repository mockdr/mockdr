"""Refuse a conditional write whose `If-Match` does not match.

ARM's own common types declare the `If-Match` header — "the If-Match header
that makes a request conditional" — and point at the normal entity-tag
convention, which is RFC 9110 §13.1.1: when the condition fails, the origin
server answers `412 Precondition Failed` and does not perform the write.

mockdr answered `200` and wrote anyway. That is the lost update the header
exists to prevent: two clients read the same incident, both write, and the
second overwrites the first while the API tells it the condition it asked for
was met.
"""

from __future__ import annotations

from fastapi import HTTPException

from utils.sentinel.response import build_arm_error


def _tags(header: str) -> set[str]:
    """The entity tags of an `If-Match` header, quotes and weak marks aside."""
    tags = set()
    for raw in header.split(","):
        tag = raw.strip()
        if tag.startswith(("W/", "w/")):
            tag = tag[2:]
        tags.add(tag.strip('"'))
    return tags


def check_if_match(header: str | None, current: str) -> None:
    """Refuse the write when the caller's `If-Match` does not hold.

    Args:
        header:  The request's `If-Match`, or None when it sent none.
        current: The resource's current entity tag.

    Raises:
        HTTPException: 412 when the condition fails.
    """
    if header is None or not header.strip():
        return
    if "*" in header and current:
        # `*` holds for any existing resource, which is what it is for.
        return
    if current.strip('"') in _tags(header):
        return
    raise HTTPException(
        status_code=412,
        detail=build_arm_error(
            "PreconditionFailed",
            "The condition specified by the If-Match header was not met.",
        ),
    )
