# ADR-001: In-Memory Storage with Thread-Safe Singleton Store

**Status**: Accepted
**Date**: 2026-03-11

## Context

mockdr must serve concurrent HTTP requests without a real database. All state must reset cleanly between test runs, be deterministically re-seeded on startup, and require zero infrastructure to run. The storage layer must also support 19 distinct entity collections (agents, threats, sites, groups, users, iocs, etc.) with per-collection semantics (e.g. activities maintain insertion order; request logs cap at 500 entries).

## Decision

A single `InMemoryStore` singleton (`backend/repository/store.py`) holds all state in a `dict[str, dict[str, Any]]` keyed by collection name. Each collection is a `dict[str, Any]` keyed by entity ID.

```python
class InMemoryStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._collections: dict[str, dict[str, Any]] = {
            "agents": {}, "threats": {}, "sites": {}, ...  # 19 collections
        }
        self._activity_order: list[str] = []   # newest-first index
        self._request_log_order: list[str] = []  # capped at 500
```

Key properties:
- **Mutations acquire the lock** (`save`, `delete`, `append_activity`)
- **Reads do not acquire the lock** — an intentional consistency trade-off for performance in a single-process mock
- **Activity ordering** is maintained via a parallel `_activity_order` list (newest-first) rather than relying on dict insertion order
- **Request logs** self-purge oldest entries when the 500-entry cap is exceeded

All per-domain repositories delegate to this store via `Repository[T]` base class in `backend/repository/base.py`.

## Alternatives Considered

| Option | Rejected because |
|---|---|
| SQLite in-memory | Adds schema migration complexity, dependency weight, and SQL overhead for a mock |
| Redis | Requires a running service; violates zero-infrastructure goal |
| Per-repo dicts | No single `store.clear_all()` path; harder to instrument/observe |

## Consequences

- **Positive**: Zero infrastructure, instant startup, trivially resettable between test runs
- **Positive**: `store.clear_all()` in `seed.generate_all()` gives clean-slate seeding every restart
- **Negative**: Read operations are not linearisable under concurrent write; acceptable for a mock that is not a production database
- **Negative**: All state is lost on process restart (by design — the seeder repopulates)
