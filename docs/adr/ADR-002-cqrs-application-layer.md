# ADR-002: CQRS Application Layer

**Status**: Accepted
**Date**: 2026-03-11

## Context

S1 API endpoints split cleanly into two categories: read endpoints that return filtered/paginated data, and write endpoints that mutate state and return an outcome. Mixing both in the same module creates god files and makes it unclear whether a function has side effects. As the number of domains grows (currently 18), this problem compounds.

## Decision

Every domain under `backend/application/` has exactly two files:

```
backend/application/
  agents/
    commands.py   # state mutations: execute_action, isolate, reconnect, ...
    queries.py    # reads: list_agents, get_agent, count_agents, ...
  threats/
    commands.py
    queries.py
  ... (18 domains total)
```

**Queries** follow a fixed pipeline with no mutations:

```python
def list_agents(params: dict, cursor: str | None, limit: int) -> dict:
    records = [asdict(a) for a in agent_repo.list_all()]  # load
    filtered = apply_filters(records, params, FILTER_SPECS)  # filter
    filtered.sort(key=lambda r: r.get("lastActiveDate", ""), reverse=True)  # sort
    page, next_cursor, total = paginate(filtered, cursor, limit, AGENT_CURSOR)  # page
    stripped = [strip_fields(r, AGENT_INTERNAL_FIELDS) for r in page]  # strip
    return build_list_response(stripped, next_cursor, total)  # wrap
```

**Commands** resolve IDs, mutate domain objects, persist via repository, and return an outcome:

```python
def execute_action(action: str, body: dict, actor_user_id: str | None = None) -> dict:
    ids = _resolve_ids(body)
    for agent_id in ids:
        agent = agent_repo.get(agent_id)
        # mutate domain object fields
        agent_repo.save(agent)
    return {"data": {"affected": affected}}
```

Routers in `backend/api/routers/` import both modules explicitly:

```python
from application.agents import commands as agent_commands
from application.agents import queries as agent_queries
```

## Alternatives Considered

| Option | Rejected because |
|---|---|
| Single `service.py` per domain | Command/query mixing makes side-effect analysis harder |
| Fat routers (logic in FastAPI handlers) | Untestable without HTTP; business logic belongs in application layer |
| Shared `crud.py` with flags | Conditional logic obscures intent; violates single-responsibility |

## Consequences

- **Positive**: Any file named `commands.py` is known to mutate state; any file named `queries.py` is known to be read-only — zero ambiguity
- **Positive**: Queries are testable by calling the function directly with no HTTP setup
- **Positive**: Commands and queries can evolve independently without merge conflicts
- **Negative**: Two files per domain rather than one — acceptable overhead for 18 domains
