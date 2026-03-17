# ADR-008: Domain Objects as Python Dataclasses, Not Pydantic Models

**Status**: Accepted
**Date**: 2026-03-11

## Context

FastAPI natively integrates with Pydantic models for request/response validation and serialisation. Using Pydantic for domain objects would give automatic OpenAPI schema generation and built-in validation. However, the domain model of a mock API server has different requirements: the primary job is to store and return data in a shape that exactly matches an external spec (the real S1 API), not to validate input. Pydantic's strict validation would reject field values that mockdr must accept to preserve fidelity.

## Decision

All domain objects in `backend/domain/` are plain Python `@dataclass` classes, not Pydantic models:

```python
# backend/domain/agent.py
@dataclass
class Agent:
    id: str
    uuid: str
    computerName: str
    networkStatus: str
    isActive: bool
    # ... 90+ fields
    passphrase: str = ""          # internal field
    localIp: str = ""             # internal field
    tags: dict = field(default_factory=dict)
    networkInterfaces: list = field(default_factory=list)
```

Serialisation uses `dataclasses.asdict()` in the query layer, which recursively converts nested dataclasses and collections to plain dicts. The result is then filtered (`apply_filters`), paginated (`paginate`), stripped (`strip_fields`), and wrapped (`build_list_response`).

**Pydantic is used in one place only**: `backend/api/dto/playbook.py`, where the request body for playbook steps uses discriminated unions that Pydantic handles cleanly:

```python
class PlaybookStep(BaseModel):
    type: Literal["action"] | Literal["condition"] | Literal["delay"]
    ...
```

This is a DTO (data transfer object) at the API boundary, not a domain object.

## Alternatives Considered

| Option | Rejected because |
|---|---|
| Pydantic for all domain objects | Validation rejects valid S1 values that don't match declared types; `.model_dump()` vs `asdict()` inconsistency in the codebase |
| TypedDict | No default values; no `field(default_factory=...)`; no method support |
| Plain dicts | No type checking; no IDE completion; can't use `asdict()` reliably |
| attrs | Adds a dependency with no advantage over `@dataclass` for this use case |

## Consequences

- **Positive**: Dataclasses impose no validation constraints — mockdr can store any value the real S1 API would return, including `None`, empty strings, and unusual types
- **Positive**: `dataclasses.asdict()` provides deep recursive serialisation with no configuration
- **Positive**: Domain classes are zero-dependency; no Pydantic version constraints affect them
- **Positive**: Field defaults with `field(default_factory=...)` cover mutable defaults (lists, dicts) without boilerplate
- **Negative**: No automatic JSON schema generation from domain objects (not needed — the spec source of truth is `swagger_2_1.json`, not generated schema)
- **Negative**: Type errors in domain object construction are not caught at runtime without explicit validation (mitigated by the test suite and `mypy` static analysis configured in `pyproject.toml`)
