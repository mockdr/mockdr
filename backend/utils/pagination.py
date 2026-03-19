"""Cursor-based pagination utilities for mock API list responses.

Two modes are supported:
- **Keyset** (S1 format): pass a ``CursorSpec`` to ``paginate()``.  Cursor is a
  URL-safe base64-encoded JSON blob matching the real SentinelOne ``nextCursor``
  wire format, e.g.
  ``{"id_column":"AgentView.id","id_value":"123","id_sort_order":"asc",
     "sort_by_column":"AgentView.id","sort_by_value":"123","sort_order":"asc"}``.
  The ``=`` padding characters are URL-encoded as ``%3D``, exactly as S1 does.
- **Offset** (legacy): omit ``CursorSpec``.  Used for internal endpoints that
  have no direct S1 equivalent (Deep Visibility event pages, passphrases, …).
"""
import base64
import json
from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# CursorSpec — describes the keyset cursor for a given list endpoint
# ---------------------------------------------------------------------------

@dataclass
class CursorSpec:
    """Keyset cursor descriptor for one list endpoint.

    Attributes:
        id_column:       S1 view column name used as the row identity key,
                         e.g. ``"AgentView.id"``.
        id_field:        Key in the item dict that holds the identity value
                         (default ``"id"``).
        id_sort_order:   Sort direction of the identity column (``"asc"`` or
                         ``"desc"``).
        sort_by_column:  S1 view column used for the primary sort.  Defaults
                         to ``id_column`` when empty.
        sort_by_field:   Item dict key for the sort value.  Defaults to
                         ``id_field`` when empty.
        sort_order:      Sort direction of the primary sort column.
    """

    id_column: str
    id_field: str = "id"
    id_sort_order: str = "asc"
    sort_by_column: str = ""
    sort_by_field: str = ""
    sort_order: str = "asc"

    @property
    def _sort_by_column(self) -> str:
        return self.sort_by_column or self.id_column

    @property
    def _sort_by_field(self) -> str:
        return self.sort_by_field or self.id_field


# ---------------------------------------------------------------------------
# Pre-defined specs — one per real S1 list endpoint (confirmed from live API)
# ---------------------------------------------------------------------------

AGENT_CURSOR       = CursorSpec("AgentView.id")
THREAT_CURSOR      = CursorSpec("ThreatInfoView.id")
SITE_CURSOR        = CursorSpec("SiteView.id")
GROUP_CURSOR       = CursorSpec("Group.id")
EXCLUSION_CURSOR   = CursorSpec("ExclusionItemHashView.id")
RESTRICTION_CURSOR = CursorSpec("RestrictionHashView.id")
ACTIVITY_CURSOR    = CursorSpec("Activity.id")
USER_CURSOR        = CursorSpec("ManagementUser.id")
ALERT_CURSOR       = CursorSpec("CloudAlertView.id")
IOC_CURSOR         = CursorSpec("ThreatIntelligenceItem.id")
DEVICE_CTRL_CURSOR = CursorSpec("DeviceControlRule.id")
ACCOUNT_CURSOR     = CursorSpec("Account.id")
TAG_CURSOR         = CursorSpec("TagManagerView.id")

# Firewall is special: primary sort is by *order* ASC; identity column is
# created_at DESC (matching the real API cursor shape).
FIREWALL_CURSOR = CursorSpec(
    id_column="FirewallControlRule.created_at",
    id_field="createdAt",
    id_sort_order="desc",
    sort_by_column="FirewallControlRule.order",
    sort_by_field="order",
    sort_order="asc",
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _encode_keyset(item: dict, spec: CursorSpec) -> str:
    """Build a URL-safe S1 keyset cursor string from the given item."""
    id_val = item.get(spec.id_field)
    sort_val = item.get(spec._sort_by_field)
    payload = {
        "id_column": spec.id_column,
        "id_value": id_val,
        "id_sort_order": spec.id_sort_order,
        "sort_by_column": spec._sort_by_column,
        "sort_by_value": sort_val,
        "sort_order": spec.sort_order,
    }
    b64 = base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
    # S1 URL-encodes the base64 padding character
    return b64.replace("=", "%3D")


def _decode_keyset(cursor: str) -> Any:
    """Extract ``id_value`` from a URL-safe S1 keyset cursor string."""
    try:
        normalized = cursor.replace("%3D", "=")
        data = json.loads(base64.b64decode(normalized.encode()).decode())
        return data.get("id_value")
    except (ValueError, KeyError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _encode_offset(offset: int) -> str:
    """Encode a numeric offset as an opaque base64 cursor (legacy mode)."""
    return base64.b64encode(json.dumps({"offset": offset}).encode()).decode()


def _decode_offset(cursor: str) -> int:
    """Decode a legacy offset cursor; returns 0 on any error."""
    try:
        data = json.loads(base64.b64decode(cursor.replace("%3D", "=").encode()).decode())
        return int(data.get("offset", 0))
    except (ValueError, KeyError, json.JSONDecodeError, UnicodeDecodeError):
        return 0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def paginate(
    items: list,
    cursor: str | None,
    limit: int,
    spec: CursorSpec | None = None,
) -> tuple[list, str | None, int]:
    """Slice *items* into a single page and produce the next-page cursor.

    Args:
        items: Full ordered list of items to paginate.  Must already be sorted
               in the order the caller wants to expose.
        cursor: Opaque cursor from the previous response, or ``None`` for the
                first page.
        limit: Maximum number of items in the returned page.
        spec: ``CursorSpec`` for S1-format keyset cursors.  When ``None`` the
              legacy offset-based cursor is used instead.

    Returns:
        ``(page, next_cursor, total)`` where *next_cursor* is ``None`` on the
        last page and *total* is the full item count before slicing.
    """
    total = len(items)

    if spec is not None:
        # ── keyset mode ──────────────────────────────────────────────────────
        start = 0
        if cursor:
            id_value = _decode_keyset(cursor)
            if id_value is not None:
                id_str = str(id_value)
                found = False
                for i, item in enumerate(items):
                    if str(item.get(spec.id_field, "")) == id_str:
                        start = i + 1
                        found = True
                        break
                if not found:
                    # Cursor references an ID no longer present — stale cursor.
                    return [], None, total

        page = items[start: start + limit]
        if page and (start + len(page)) < total:
            next_cursor: str | None = _encode_keyset(page[-1], spec)
        else:
            next_cursor = None
    else:
        # ── legacy offset mode ───────────────────────────────────────────────
        offset = _decode_offset(cursor) if cursor else 0
        page = items[offset: offset + limit]
        next_cursor = _encode_offset(offset + limit) if (offset + limit) < total else None

    return page, next_cursor, total


def build_list_response(data: list, next_cursor: str | None, total: int) -> dict:
    """Build a standard S1 API list response envelope."""
    return {
        "data": data,
        "pagination": {"totalItems": total, "nextCursor": next_cursor},
    }


def build_single_response(data: Any) -> dict:
    """Wrap a single serialised domain object in the S1 API response envelope."""
    return {"data": data}
