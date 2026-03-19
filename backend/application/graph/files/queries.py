"""Read-side handlers for Microsoft Graph Files (OneDrive / SharePoint)."""
from __future__ import annotations

from dataclasses import asdict

from repository.graph.drive_item_repo import graph_drive_item_repo
from repository.graph.drive_repo import graph_drive_repo
from repository.graph.sharepoint_site_repo import graph_sharepoint_site_repo
from utils.graph_response import build_graph_list_response


def _strip_internal(record: dict) -> dict:
    """Remove internal underscore-prefixed fields from a dict."""
    return {k: v for k, v in record.items() if not k.startswith("_")}


def get_user_drive(user_id: str) -> dict | None:
    """Return the user's OneDrive.

    Args:
        user_id: The user's ``id``.

    Returns:
        Drive dict or ``None`` if not found.
    """
    for drive in graph_drive_repo.list_all():
        d = asdict(drive) if not isinstance(drive, dict) else dict(drive)
        if d.get("_user_id") == user_id:
            return _strip_internal(d)
    return None


def list_drive_children(drive_id: str, item_id: str = "root") -> dict:
    """Return children of a drive item.

    Args:
        drive_id: The drive's ``id``.
        item_id:  Parent item ``id`` (defaults to ``"root"``).

    Returns:
        OData list response dict.
    """
    all_items = graph_drive_item_repo.list_all()
    records: list[dict] = []
    for item in all_items:
        d = asdict(item) if not isinstance(item, dict) else dict(item)
        if d.get("_drive_id") != drive_id:
            continue
        parent_ref = d.get("parentReference", {})
        if parent_ref.get("id") == item_id:
            records.append(_strip_internal(d))

    return build_graph_list_response(
        value=records,
        context=f"https://graph.microsoft.com/v1.0/$metadata#drives('{drive_id}')/root/children",
    )


def list_sites() -> dict:
    """Return all SharePoint sites.

    Returns:
        OData list response dict.
    """
    records = [asdict(s) for s in graph_sharepoint_site_repo.list_all()]
    return build_graph_list_response(
        value=records,
        context="https://graph.microsoft.com/v1.0/$metadata#sites",
    )
