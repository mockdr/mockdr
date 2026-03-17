"""Shared token expiry check used by S1, CrowdStrike, and MDE auth modules."""
from __future__ import annotations

from datetime import UTC, datetime


def is_token_expired(
    record: dict, key: str = "expiresAt", fmt: str = "%Y-%m-%dT%H:%M:%S.%fZ",
) -> bool:
    """Return True if the token's timestamp field is in the past or unparseable.

    Args:
        record: Token record dict.
        key: Dict key containing the ISO-8601 expiry timestamp.
        fmt: strptime format string for parsing.

    Returns:
        True if expired or the timestamp is missing/malformed, False if still valid.
    """
    expires_at = record.get(key)
    if not expires_at:
        # Fail-closed: missing or empty expiry is treated as expired.
        # This prevents tokens without an expiry from being accepted indefinitely.
        return True
    try:
        expiry = datetime.strptime(expires_at, fmt).replace(tzinfo=UTC)
        return datetime.now(UTC) > expiry
    except (ValueError, TypeError):
        return True
