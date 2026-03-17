"""Shared utility for stripping internal-only fields from domain record dicts."""

from __future__ import annotations


def strip_fields(record: dict, internal: frozenset[str]) -> dict:
    """Return *record* with every key listed in *internal* removed.

    Args:
        record: A flat dict produced by ``dataclasses.asdict``.
        internal: The set of field names that must not appear in API responses.

    Returns:
        A new dict containing only the public-facing keys.
    """
    return {k: v for k, v in record.items() if k not in internal}
