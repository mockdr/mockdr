# ADR-011: Splunk REST API Mock Design

## Status

Accepted

## Context

mockdr already mocks five EDR vendors. Adding Splunk SIEM support requires
choosing how to authenticate requests and how much of the Splunk Processing
Language (SPL) to implement.

Splunk's real REST API supports three authentication mechanisms that are used
by different classes of clients:

1. **Basic Auth** (`Authorization: Basic <b64>`) -- used by admin tooling and
   one-off scripts.
2. **Bearer Token** (`Authorization: Bearer <session_key>`) -- obtained via
   `POST /services/auth/login`; used by SOAR connectors (XSOAR, Phantom).
3. **HEC Token** (`Authorization: Splunk <hec_token>`) -- used exclusively by
   HTTP Event Collector endpoints for event ingestion.

Additionally, SOAR playbooks execute SPL queries via the search job API
(`POST /services/search/jobs`, `GET /services/search/v2/jobs/{sid}/results`).

## Decision

### Authentication

All three auth schemes are supported:

- **Basic Auth** validates against pre-seeded user credentials (`admin`,
  `analyst`, `viewer`) stored in the `splunk_users` collection.
- **Bearer sessions** are created via `POST /services/auth/login` and stored
  in the `splunk_sessions` collection with a configurable TTL
  (`SPLUNK_SESSION_TTL_SECONDS`, default 8 hours).
- **HEC tokens** are stored in the `splunk_hec_tokens` collection and
  validated by a separate `require_hec_auth` dependency.

Role-based access mirrors the real Splunk RBAC model: `admin`, `sc_admin`,
and `user` roles with an `admin`-gated `require_splunk_admin` dependency.

### SPL Parser Scope

The mock implements a **subset** of SPL sufficient for SOAR integration
testing:

- `search index=<name> sourcetype=<name> <field>=<value>` -- basic field
  filtering against the in-memory event store.
- `| stats count by <field>` -- simple aggregation.
- `| table <fields>` -- field projection.
- `| head N` / `| tail N` -- result limiting.

Complex SPL (subsearches, lookups, macros, eval expressions, transaction,
tstats) is out of scope. Unsupported commands return an empty result set
with an informational message rather than an error, matching Splunk's
lenient parsing behaviour for unknown commands in saved searches.

### Endpoint Coverage

The mock covers the Splunk REST endpoints most commonly used by SOAR
connectors:

- Auth login, current-context, users, roles
- Search jobs (create, status, results, cancel)
- Saved searches (CRUD)
- KV Store collections (CRUD)
- Notable events (list, update)
- HEC (event, raw, batch, health, ack)
- Server info and health
- Fired alerts, indexes, inputs

## Alternatives Considered

1. **Bearer-only auth**: Rejected because real SOAR connectors (particularly
   XSOAR's SplunkPy) use Basic Auth for initial login and then switch to
   Bearer tokens. Supporting only one scheme would reduce test fidelity.

2. **Full SPL parser**: Rejected as disproportionate effort. SOAR playbooks
   use a narrow subset of SPL, and the mock's value comes from endpoint
   fidelity, not query language completeness.

3. **Separate Splunk port**: Rejected. All vendors share a single port with
   path-based routing (`/splunk/services/*`), consistent with the existing
   multi-vendor architecture.

## Consequences

- SOAR connectors (XSOAR SplunkPy, Phantom, custom scripts) can test against
  mockdr without modification.
- The EDR-to-Splunk event bridge automatically populates Splunk events when
  EDR domain events fire, enabling end-to-end SIEM integration testing.
- SPL queries beyond the supported subset silently return empty results,
  which may surprise users expecting full SPL support. This is documented
  in the integration guide.
