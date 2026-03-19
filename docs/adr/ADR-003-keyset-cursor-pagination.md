# ADR-003: Keyset Cursor Pagination Matching S1 Wire Format

**Status**: Accepted
**Date**: 2026-03-11

## Context

The real SentinelOne API uses opaque base64-encoded cursor tokens for pagination. Clients that test against mockdr may pass real cursors obtained from a live S1 tenant, or may pass mock-generated cursors back to the mock. Both directions must work. Offset-based pagination is simpler to implement but would produce cursors that are structurally different from real S1 cursors, breaking any client that inspects or replays cursor values.

## Decision

Pagination is implemented in `backend/utils/pagination.py` using a `CursorSpec` dataclass that defines how to encode and decode a keyset cursor:

```python
@dataclass
class CursorSpec:
    id_column: str      # S1 view name, e.g. "AgentView.id"
    id_field: str = "id"
    id_sort_order: str = "asc"
    sort_by_column: str = ""
    sort_by_field: str = ""
    sort_order: str = "asc"
```

Cursor encoding matches the real S1 format exactly — a base64-encoded JSON payload with URL-encoded padding characters:

```python
def _encode_keyset(item: dict, spec: CursorSpec) -> str:
    payload = {
        "id_column": spec.id_column,
        "id_value": id_val,
        "id_sort_order": spec.id_sort_order,
        "sort_by_column": spec._sort_by_column,
        "sort_by_value": sort_val,
        "sort_order": spec.sort_order,
    }
    b64 = base64.b64encode(json.dumps(payload).encode()).decode()
    return b64.replace("=", "%3D")  # S1 URL-encodes the padding
```

Each endpoint declares its own `CursorSpec`:

```python
AGENT_CURSOR    = CursorSpec("AgentView.id")
THREAT_CURSOR   = CursorSpec("ThreatInfoView.id")
FIREWALL_CURSOR = CursorSpec(
    id_column="FirewallControlRule.created_at", id_field="createdAt",
    id_sort_order="desc",
    sort_by_column="FirewallControlRule.order", sort_by_field="order",
    sort_order="asc",
)
RESTRICTION_CURSOR = CursorSpec("BlackListView.id")
```

A **legacy offset mode** is also supported for internal dev endpoints that do not use the S1 cursor format:

```python
def _encode_offset(offset: int) -> str:
    return base64.b64encode(json.dumps({"offset": offset}).encode()).decode()
```

Standard response envelope:

```python
def build_list_response(data: list, next_cursor: str | None, total: int) -> dict:
    return {"data": data, "pagination": {"totalItems": total, "nextCursor": next_cursor}}
```

## Alternatives Considered

| Option | Rejected because |
|---|---|
| Offset pagination (`?page=N`) | Not what S1 uses; clients would fail to interoperate |
| Simple UUID-based cursors | Structurally different from real S1 cursors; breaks cursor passthrough tests |
| No pagination (return all) | Violates field parity goal; clients that rely on `nextCursor` being `null` on last page break |

## Consequences

- **Positive**: Clients can take a real S1 cursor and pass it to the mock (and vice versa) without structural errors
- **Positive**: Each endpoint's sort semantics are self-documenting in its `CursorSpec`
- **Positive**: The `paginate()` function is pure and unit-testable with no HTTP setup
- **Negative**: Keyset pagination requires keeping the full dataset in memory (no streaming); acceptable for mock-scale data (60 agents, 30 threats)
