# ADR-004: Domain Objects Store Internal Fields; Query Layer Strips Before Response

**Status**: Accepted
**Date**: 2026-03-11

## Context

The mock needs to store fields that are useful internally (e.g. `siteId` for filter-by-site operations, `passphrase` for agent management, `_apiToken` for auth lookups) but must never expose those fields in API responses — matching the real S1 API which also does not return these fields. The challenge is doing the filter-then-strip correctly: filtering must happen on the raw domain dict (before stripping) so internal fields can be used as filter criteria.

## Decision

Domain objects (`@dataclass` in `backend/domain/`) carry internal fields alongside public fields. The query layer strips internal fields after filtering but before building the response.

**Internal field sets** are defined centrally in `backend/utils/internal_fields.py`:

```python
AGENT_INTERNAL_FIELDS: set[str] = {
    "passphrase", "localIp", "isInfected", "installedAt",
    "agentLicenseType", "cpuUsage", "memoryUsage",
}
USER_INTERNAL_FIELDS: set[str] = {"role", "accountId", "accountName", "_apiToken"}
FIREWALL_INTERNAL_FIELDS: set[str] = {"siteId"}
EXCLUSION_INTERNAL_FIELDS: set[str] = {"siteId"}
DEVICE_CONTROL_INTERNAL_FIELDS: set[str] = {"siteId"}
GROUP_INTERNAL_FIELDS: set[str] = {"siteName", "accountId", "accountName"}
SITE_INTERNAL_FIELDS: set[str] = {"location"}
```

**Strip function** (`backend/utils/strip.py`):

```python
def strip_fields(record: dict, internal: frozenset[str]) -> dict:
    return {k: v for k, v in record.items() if k not in internal}
```

**Correct order in every query**:

```python
def list_firewall_rules(params: dict, cursor: str | None, limit: int) -> dict:
    records = [asdict(r) for r in firewall_repo.list_all()]
    filtered = apply_filters(records, params, FILTER_SPECS)  # siteIds filter runs here on raw record
    page, next_cursor, total = paginate(filtered, cursor, limit, FIREWALL_CURSOR)
    stripped = [strip_fields(r, FIREWALL_INTERNAL_FIELDS) for r in page]  # siteId removed here
    return build_list_response(stripped, next_cursor, total)
```

If stripping happened before filtering, `siteIds` filter would silently match nothing.

## Alternatives Considered

| Option | Rejected because |
|---|---|
| Separate public/private domain classes | Doubles the domain model; synchronisation burden |
| Pydantic `response_model` exclusions | Couples API schema to domain model; breaks the DTO boundary |
| Strip in routers | Logic leaks into transport layer; each router author must remember to strip |
| Strip in repository on read | Cannot filter by internal fields after the fact |

## Consequences

- **Positive**: Single source of truth per domain — one `@dataclass` per entity, not two
- **Positive**: Internal field sets are testable in isolation; a unit test can assert the set contains the expected keys
- **Positive**: Adding a new internal field requires a one-line change in `internal_fields.py` — no router changes needed
- **Negative**: Developers must remember the filter-before-strip ordering rule; violated order silently produces wrong results (mitigated by integration tests that verify filtered responses exclude internal fields)
