"""Cortex XDR Hash Exception query handlers (reads)."""
from __future__ import annotations

from dataclasses import asdict

from repository.xdr_hash_exception_repo import xdr_hash_exception_repo
from utils.xdr_response import build_xdr_list_reply


def get_blocklist() -> dict:
    """Return all blocklist hash exceptions.

    Returns:
        XDR list reply with blocklist entries.
    """
    all_items = xdr_hash_exception_repo.list_all()
    blocklist = [asdict(e) for e in all_items if e.list_type == "blocklist"]
    return build_xdr_list_reply(blocklist, total_count=len(blocklist))


def get_allowlist() -> dict:
    """Return all allowlist hash exceptions.

    Returns:
        XDR list reply with allowlist entries.
    """
    all_items = xdr_hash_exception_repo.list_all()
    allowlist = [asdict(e) for e in all_items if e.list_type == "allowlist"]
    return build_xdr_list_reply(allowlist, total_count=len(allowlist))
