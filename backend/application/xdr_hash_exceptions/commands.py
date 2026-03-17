"""Cortex XDR Hash Exception command handlers (mutations)."""
from __future__ import annotations

from domain.xdr_hash_exception import XdrHashException
from infrastructure.seeders.xdr_shared import rand_epoch_ms, xdr_id
from repository.xdr_hash_exception_repo import xdr_hash_exception_repo
from utils.xdr_response import build_xdr_reply


def add_to_blocklist(hashes: list[dict]) -> dict:
    """Add hashes to the blocklist.

    Args:
        hashes: List of dicts with ``hash`` and optional ``comment``.

    Returns:
        XDR reply confirming success.
    """
    for h in hashes:
        hash_value = h.get("hash", "")
        xdr_hash_exception_repo.save(XdrHashException(
            exception_id=xdr_id("HEX"),
            hash=hash_value,
            list_type="blocklist",
            comment=h.get("comment", ""),
            created_at=rand_epoch_ms(0),
        ))

    return build_xdr_reply(True)


def remove_from_blocklist(hashes: list[str]) -> dict:
    """Remove hashes from the blocklist.

    Args:
        hashes: List of hash strings to remove.

    Returns:
        XDR reply confirming success.
    """
    for h in hashes:
        for entry in xdr_hash_exception_repo.list_all():
            if entry.hash == h and entry.list_type == "blocklist":
                xdr_hash_exception_repo.delete(entry.exception_id)
                break

    return build_xdr_reply(True)


def add_to_allowlist(hashes: list[dict]) -> dict:
    """Add hashes to the allowlist.

    Args:
        hashes: List of dicts with ``hash`` and optional ``comment``.

    Returns:
        XDR reply confirming success.
    """
    for h in hashes:
        hash_value = h.get("hash", "")
        xdr_hash_exception_repo.save(XdrHashException(
            exception_id=xdr_id("HEX"),
            hash=hash_value,
            list_type="allowlist",
            comment=h.get("comment", ""),
            created_at=rand_epoch_ms(0),
        ))

    return build_xdr_reply(True)


def remove_from_allowlist(hashes: list[str]) -> dict:
    """Remove hashes from the allowlist.

    Args:
        hashes: List of hash strings to remove.

    Returns:
        XDR reply confirming success.
    """
    for h in hashes:
        for entry in xdr_hash_exception_repo.list_all():
            if entry.hash == h and entry.list_type == "allowlist":
                xdr_hash_exception_repo.delete(entry.exception_id)
                break

    return build_xdr_reply(True)
