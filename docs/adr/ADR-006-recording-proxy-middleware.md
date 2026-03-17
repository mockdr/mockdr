# ADR-006: Three-Mode Recording Proxy Middleware

**Status**: Accepted
**Date**: 2026-03-11

## Context

mockdr needs two distinct operational modes: a pure mock (for offline/CI use) and a bridge to a real S1 tenant (for validating field coverage and recording new responses). Switching modes at the process level (environment variables, separate binaries) would require redeployment. Operators also need a replay mode that serves recorded real responses without hitting the live tenant — useful for deterministic regression testing against real data.

## Decision

`backend/api/middleware/proxy.py` implements an ASGI middleware (`RecordingProxyMiddleware`) with three modes controlled at runtime via the `/_dev/proxy` API endpoint:

| Mode | Behaviour |
|---|---|
| `off` (default) | No-op; all requests fall through to mock handlers |
| `record` | Forwards request to real S1 tenant, persists the exchange (request + response), returns the real response to the caller |
| `replay` | Looks up a stored recording for the request method + path; serves it if found, falls through to mock if not |

The middleware sits innermost in the ASGI stack (added first in `main.py`, so it runs last during request processing):

```python
app.add_middleware(RecordingProxyMiddleware)  # innermost
app.add_middleware(RequestAuditMiddleware)
app.add_middleware(RateLimitMiddleware)        # outermost
```

Dev paths (`/_dev/`) always bypass proxy logic to prevent circular forwarding.

**Recording storage**: Exchanges are persisted in the in-memory store under `"request_logs"` / `"recordings"` and can be exported via the dev API.

**Credentials**: The real S1 tenant URL and API token are read from environment variables (`.env`, gitignored), never hardcoded.

## Alternatives Considered

| Option | Rejected because |
|---|---|
| Separate recording proxy process (mitmproxy, etc.) | Adds operational complexity; two processes to coordinate |
| Record mode only, no replay | Cannot run regression tests against real data offline |
| Env-var mode switching | Requires process restart to toggle; breaks dev workflow |
| Runtime toggle via header | Non-standard; leaks mode control into the API surface |

## Consequences

- **Positive**: A running mock can be switched to record mode, exercised against a real S1 tenant, then switched back to off — all without restart
- **Positive**: Recorded exchanges can be committed to the repo as fixtures for regression tests
- **Positive**: Replay mode enables deterministic testing against real S1 response shapes, not mock-generated ones
- **Negative**: Record mode requires a live S1 tenant and valid credentials; CI must run in `off` mode
- **Negative**: Recordings are in-memory only across restarts; export via dev API is required to persist them to disk
