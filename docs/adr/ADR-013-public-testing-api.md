# ADR-013: Public Testing API — MockdrClient and mockdr_server Fixture

**Status**: Accepted
**Date**: 2026-03-17

## Context

External teams that integrate with real EDR APIs (SOAR engineers, SIEM
integrators, security automation developers) need to test their code against
mockdr in their own CI pipelines.  They should be able to point their existing
test suites at a running mockdr instance without understanding mockdr's
internals.

Two concerns drove this decision:

1. **Discoverability** — test code importing `httpx.Client` directly must
   manage auth headers, base URLs, and health-check waiting on every project
   that adopts mockdr.  A typed client wrapper eliminates that boilerplate.

2. **Lifecycle management** — starting a real server, waiting for it to be
   healthy, and tearing it down reliably is non-trivial.  A pytest fixture
   handles this once so consumers don't have to.

## Decision

A public `mockdr.testing` module is shipped alongside the server code inside
`backend/mockdr/testing.py`.  It exports two symbols:

```python
from mockdr.testing import MockdrClient, mockdr_server
```

**`MockdrClient`** wraps `httpx.Client` with:

- Auth headers baked in at construction time (no per-request boilerplate)
- Typed `get / post / put / delete` methods that return `dict[str, Any]` and
  raise `httpx.HTTPStatusError` on non-2xx responses
- Named shortcuts for DEV endpoints: `scenario`, `reset`, `export_state`,
  `import_state`
- A `_transport` constructor parameter (type: `httpx.BaseTransport | None`)
  for dependency injection in unit tests — callers pass `httpx.MockTransport`
  to exercise the client without a live server

**`mockdr_server`** is a `scope="session"` pytest fixture that:

1. Picks a free port via `_find_free_port()`
2. Starts uvicorn in a daemon thread (`_UvicornServer`)
3. Polls the `/web/api/v2.1/system/status` endpoint until healthy (30 s
   timeout)
4. Yields a `MockdrClient` configured to talk to that server
5. Closes the client and stops the server on session teardown

The fixture is named `mockdr_server` (not `client` or `server`) to avoid
colliding with the internal `client` fixture in `backend/tests/conftest.py`.

## Alternatives Considered

| Option | Rejected because |
|---|---|
| **FastAPI `TestClient`** | Uses ASGI in-process transport — does not test real TCP/HTTP stack, which is what external consumers care about |
| **Docker container in fixture** | Too slow to start in CI; requires Docker daemon; adds complexity for consumers who just want to run `pytest` |
| **Separate `mockdr-testing` PyPI package** | Unnecessary split; the testing utilities must stay in sync with the server — shipping them together guarantees no version skew |
| **Expose raw `httpx.Client`** | Forces every consumer to manage auth headers and URL construction; typed wrappers are the established pattern (boto3, google-cloud-*) |
| **`scope="function"` fixture** | Server startup takes ~1–3 s; function scope multiplies that cost across every test; session scope with explicit `reset()` calls is the right trade-off |

## Consequences

- **Positive**: External test suites need one import and one fixture — all
  server lifecycle and auth is handled transparently
- **Positive**: `_transport` parameter makes `MockdrClient` fully unit-testable
  without a running server (`httpx.MockTransport` handler)
- **Positive**: DEV shortcuts (`scenario`, `reset`) are part of the typed
  client — no string-based URL construction in consumer test files
- **Negative**: `mockdr.testing` depends on `pytest` and `uvicorn`, which
  become runtime (not dev-only) dependencies of the `mockdr` package; this
  is acceptable because the package is a testing tool by design
- **Negative**: `_transport` is a private-by-convention parameter (leading
  underscore); IDEs will not hide it but the underscore signals "test use only"
