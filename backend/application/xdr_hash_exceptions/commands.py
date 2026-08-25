"""Cortex XDR Hash Exception command handlers (mutations)."""
from __future__ import annotations

from domain.xdr_hash_exception import XdrHashException
from infrastructure.seeders.xdr_shared import rand_epoch_ms, xdr_id
from repository.xdr_hash_exception_repo import xdr_hash_exception_repo
from utils.xdr_response import build_xdr_reply


def add_to_blocklist(hashes: list[str], comment: str = "", incident_id: object = None) -> dict:
    """Add hashes to the blocklist.

    ``hash_list`` is a list of SHA256 *strings*, and the comment is its
    sibling in ``request_data`` — not a member of each entry. Reading it the
    other way round turned the documented body into an ``AttributeError``
    and a plain-text 500.

    Args:
        hashes: SHA256 hashes to add.
        comment: The comment recorded against all of them.
        incident_id: The incident the change is attributed to, if any.

    Returns:
        XDR reply confirming success.
    """
    for hash_value in hashes:
        xdr_hash_exception_repo.save(XdrHashException(
            exception_id=xdr_id("HEX"),
            hash=str(hash_value),
            list_type="blocklist",
            comment=comment,
            created_at=rand_epoch_ms(0),
            incident_id=incident_id,
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


def add_to_allowlist(hashes: list[str], comment: str = "", incident_id: object = None) -> dict:
    """Add hashes to the allowlist.

    ``hash_list`` is a list of SHA256 *strings*, and the comment is its
    sibling in ``request_data`` — not a member of each entry. Reading it the
    other way round turned the documented body into an ``AttributeError``
    and a plain-text 500.

    Args:
        hashes: SHA256 hashes to add.
        comment: The comment recorded against all of them.
        incident_id: The incident the change is attributed to, if any.

    Returns:
        XDR reply confirming success.
    """
    for hash_value in hashes:
        xdr_hash_exception_repo.save(XdrHashException(
            exception_id=xdr_id("HEX"),
            hash=str(hash_value),
            list_type="allowlist",
            comment=comment,
            created_at=rand_epoch_ms(0),
            incident_id=incident_id,
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
