# Architecture Overview

## System Design

mockdr is a multi-protocol API mock server for security platform integration
testing: a SOAR or SIEM client should not be able to tell it from the real
product. It mocks eight vendor APIs on one port:

| Vendor | API Prefix | Auth Mechanism |
|--------|-----------|----------------|
| SentinelOne | `/web/api/v2.1` | ApiToken header |
| CrowdStrike Falcon | `/cs` | OAuth2 client credentials (Bearer) |
| Microsoft Defender for Endpoint | `/mde` | Entra client credentials (Bearer) |
| Microsoft Graph | `/graph` | Entra client credentials (Bearer), plan-gated |
| Microsoft Sentinel | `/sentinel` | Entra client credentials (Bearer), ARM resource paths |
| Cortex XDR | `/xdr/public_api/v1` | Advanced key auth (SHA-256 of key + nonce + timestamp) |
| Splunk | `/splunk` | Basic / session key / Bearer / HEC token; Atom XML unless `output_mode=json` |
| Elastic Security | `/elastic`, `/kibana` | Basic / ApiKey / Bearer |

The mock's own control surface (reset, scenarios, fault injection, webhook
subscriptions, the recording proxy) lives under `/web/api/v2.1/_dev/` and is
admin-gated; the real products have nothing there.

### Fidelity: measured, not typed

Every mounted route is compared against a public reference of the real
product, each used for what it can prove (see `data/vendor-specs/NOTICE.md`
for sources and licences):

- **Splunk, Elasticsearch, Kibana** — the conformance harness (`conformance/`)
  runs the real products in containers and compares mock and real answers
  key for key. Splunk entries are completed from fixtures captured from
  Splunk 10.4 (`backend/infrastructure/fixtures/splunk/`).
- **Sentinel, Graph** — `scripts/schema_drift.py` against the Azure REST API
  specs and the Graph v1.0/beta OpenAPI metadata.
- **SentinelOne** — `scripts/field_drift.py` against the 2.1 swagger (in CI);
  absence and surplus both count because the swagger is generated from the
  product's own schemas.
- **CrowdStrike** — the `gofalcon` SDK models (generated from the swagger,
  `omitempty`: only surplus counts).
- **Defender for Endpoint, Cortex XDR** — docs examples, recorded responses
  and transcriptions: presence only; surplus is listed as undocumented.

Response shapes are completed against per-route fixtures generated from
those references (`scripts/gen_*_fixtures.py` → `backend/infrastructure/fixtures/`),
so a field the real product always sends is present even when the seed has
no value for it.

### EDR → SIEM bridge (ADR-009, ADR-010)

Domain events (`domain/event_bus.py`) from the EDR mocks are bridged into
the Splunk and Sentinel mocks as the vendors' add-ons would index them:
one event per API object, under the add-on's sourcetype, dated by the
record's own timestamp (`application/splunk/edr_shapes.py`,
`application/splunk/commands/edr_bridge.py`, `application/sentinel/commands/edr_bridge.py`).
Seeders replay the seeded data through the same shapes.

## Backend Architecture

### Layer Diagram

```
HTTP Request
    │
    ▼
┌─────────────────────────┐
│   Middleware Stack       │  Body limit → HEAD → Logging → Rate Limit → Security
│                         │  Headers → Audit → Tenant Scope → Fault Injection → Proxy
│                         │  → Splunk namespace/output-mode/paging (Splunk routes)
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│   Router Layer          │  FastAPI routers per vendor + domain
│   (api/routers/)        │  Auth dependencies: require_auth, require_write, require_admin
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│   Application Layer     │  CQRS: commands/ (mutations) and queries/ (reads)
│   (application/)        │  See ADR-002
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│   Repository Layer      │  Domain-specific repos wrapping the store
│   (repository/)         │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│   In-Memory Store       │  Thread-safe singleton (one RLock, reads included);
│   (repository/store.py) │  traffic-written collections capped. See ADR-001
└─────────────────────────┘
```

### Key Patterns

- **CQRS** (ADR-002): Commands mutate state; queries are read-only
- **Domain dataclasses** (ADR-008): Not Pydantic — plain Python dataclasses
- **Internal field stripping** (ADR-004): Domain objects store internal fields; query layer strips before response
- **Keyset cursor pagination** (ADR-003): Matches real S1 wire format
- **Declarative filtering** (ADR-007): FilterSpec system with dot-path field access
- **Deterministic seeding** (ADR-005): `random.seed(42)` + `Faker.seed(42)` for reproducible data

### Directory Structure

```
backend/
├── main.py                  # FastAPI app, middleware, router registration
├── config.py                # Environment-driven configuration
├── api/
│   ├── auth.py              # S1 auth dependencies
│   ├── {cs,mde,graph,sentinel,xdr,splunk,es}_auth.py  # one auth scheme per vendor
│   ├── middleware/           # 14 ASGI middleware classes
│   ├── routers/             # ~70 router modules (graph/, splunk/, sentinel/ sub-packages)
│   └── dto/                 # Request/response DTOs
├── domain/                  # Dataclass models
├── application/             # CQRS command/query handlers
├── repository/              # Store wrappers per domain
├── infrastructure/
│   ├── seed.py              # Seed orchestrator
│   ├── seeders/             # ~60 domain-specific seeders (documentation-range IPs/domains)
│   ├── fixtures/            # per-route default shapes generated from the references
│   └── persistence.py       # Optional versioned JSON snapshot
└── utils/                   # Shared utilities: parsers (SPL, KQL, OData, FQL, ES DSL), completion helpers
```

## Frontend Architecture

- **Framework**: Vue 3 with Composition API + TypeScript
- **State**: Pinia stores (auth, agents, threats, dashboard)
- **HTTP**: Axios with per-vendor client instances
- **Routing**: Vue Router with auth guard
- **Styling**: Tailwind CSS with CSS custom properties

## Data Flow

1. Frontend sends HTTP request with auth header
2. Middleware stack processes (metrics, logging, rate limit, tenant scope, etc.)
3. Router dispatches to appropriate handler
4. Handler calls application layer (command or query)
5. Application layer interacts with repository
6. Repository reads/writes the in-memory store
7. Response flows back through middleware

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `CORS_ORIGINS` | `http://localhost:3000,http://localhost:8001,http://localhost:5001` | Allowed CORS origins |
| `SEED_COUNT_AGENTS` | `60` | Number of agents to seed |
| `SEED_COUNT_THREATS` | `30` | Number of threats to seed |
| `SEED_COUNT_ALERTS` | `20` | Number of alerts to seed |
| `MOCKDR_PERSIST` | (empty) | File path for JSON persistence |
| `MOCKDR_MAX_BODY_BYTES` | `16777216` | Request body ceiling (413 above) |

The full table, including the Splunk and tenant switches, is in README.md.

## Verification tooling

| Tool | What it proves | Where it runs |
|---|---|---|
| `backend/tests/` (pytest, 85 % gate) | Behaviour, including `-m critical` (internal fields never leak) | CI |
| `scripts/field_drift.py` | S1 responses vs the 2.1 swagger | CI |
| `scripts/schema_drift.py <platform>` | Sentinel, Graph, CrowdStrike, Defender, Cortex XDR, SentinelOne shapes vs their references | before a release |
| `conformance/` harness | Splunk, Elasticsearch, Kibana vs the real products | before a release |
| `scripts/hostile_probe.py`, `scripts/fuzz_parsers.py` | No crash path on hostile input | CI |
| `scripts/load_test.py` | p99 < 500 ms, errors < 1 % under concurrency | on demand |
| `scripts/*_spec.py`, `scripts/gen_*_fixtures.py` | Regenerate the reduced references and fixtures from upstream | when a vendor changes |
