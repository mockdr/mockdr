# ADR-007: Declarative FilterSpec System with Dot-Path Field Access

**Status**: Accepted
**Date**: 2026-03-11

## Context

Every list endpoint in the S1 API accepts a different combination of filter query parameters: some filter by comma-separated IDs, some by boolean flags, some by substring match, some by date range, some by full-text search across multiple fields. Implementing each filter inline per endpoint duplicates logic and makes it impossible to test filtering behaviour in isolation.

## Decision

Filtering is implemented in `backend/utils/filtering.py` using a `FilterSpec` dataclass that describes a single filter:

```python
@dataclass
class FilterSpec:
    param: str   # URL query parameter name (e.g. "siteIds")
    field: str   # dot-path to field in record dict (e.g. "threatInfo.classification")
    type: str    # filter strategy (see below)
```

Seven filter strategies are supported:

| Strategy | Behaviour |
|---|---|
| `"eq"` | Exact match (`record[field] == param_value`) |
| `"in"` | Comma-separated values → set membership (`param_value in {v1, v2, ...}`) |
| `"contains"` | Case-insensitive substring match |
| `"bool"` | Parse `"true"/"1"/"yes"` to `True`, `"false"/"0"/"no"` to `False` |
| `"gte_dt"` | ISO-8601 datetime — record value ≥ param value |
| `"lte_dt"` | ISO-8601 datetime — record value ≤ param value |
| `"full_text"` | OR search across pipe-separated field list (e.g. `"computerName\|localIp\|domain"`) |

Dot-path access traverses nested dicts:

```python
def _get_field(record: dict, path: str) -> Any:
    parts = path.split(".")
    val: Any = record
    for p in parts:
        if not isinstance(val, dict):
            return None
        val = val.get(p)
    return val
```

Each domain's query module declares its own `FILTER_SPECS` list:

```python
# application/agents/queries.py
FILTER_SPECS = [
    FilterSpec("ids",               "id",                          "in"),
    FilterSpec("siteIds",           "siteId",                      "in"),
    FilterSpec("groupIds",          "groupId",                     "in"),
    FilterSpec("isActive",          "isActive",                    "bool"),
    FilterSpec("computerName",      "computerName",                "contains"),
    FilterSpec("query",             "computerName|localIp|domain", "full_text"),
    FilterSpec("registeredAt__gte", "registeredAt",                "gte_dt"),
    FilterSpec("registeredAt__lte", "registeredAt",                "lte_dt"),
]
```

Filters compose with AND semantics: a record must match all active filter specs to appear in the result.

## Alternatives Considered

| Option | Rejected because |
|---|---|
| Inline `if param: filter(...)` per endpoint | Not reusable; cannot unit-test filter logic without HTTP |
| ORM query builder (SQLAlchemy etc.) | No database; adds dependency for no benefit |
| JSONPath / jmespath | Heavier dependency; dot-path covers all current cases |
| GraphQL | Significant interface change; overkill for a mock |

## Consequences

- **Positive**: `apply_filters()` is a pure function — unit-testable with a list of dicts, no HTTP, no repo
- **Positive**: Adding a new filter to any endpoint is a one-line `FilterSpec(...)` addition
- **Positive**: Dot-path access works transparently for both flat records and deeply nested dicts (e.g. `threatInfo.classification`)
- **Negative**: All records must be loaded into memory before filtering (no pushdown to storage); acceptable at mock scale
- **Negative**: Filter composition is AND-only; OR across different params is not supported (matches real S1 API behaviour)
