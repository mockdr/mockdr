# Architecture Overview

## System Design

mockdr is a full-fidelity multi-protocol API mock server for security platform integration testing. It mocks five vendor APIs:

| Vendor | API Prefix | Auth Mechanism |
|--------|-----------|----------------|
| SentinelOne | `/web/api/v2.1` | ApiToken header |
| CrowdStrike | `/cs` | OAuth2 Bearer |
| Microsoft Defender | `/mde` | OAuth2 Bearer |
| Elastic Security | `/elastic`, `/kibana` | Basic / ApiKey / Bearer |
| Cortex XDR | `/xdr/public_api/v1` | HMAC-SHA256 |
| Splunk SIEM | `/splunk` | Basic / Bearer / HEC token |

## Backend Architecture

### Layer Diagram

```
HTTP Request
    │
    ▼
┌─────────────────────────┐
│   Middleware Stack       │  Metrics → Logging → Rate Limit → Security Headers
│                         │  → Audit → Tenant Scope → Fault Injection → Proxy
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
│   In-Memory Store       │  Thread-safe singleton (RLock)
│   (repository/store.py) │  See ADR-001
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
│   ├── cs_auth.py           # CrowdStrike auth
│   ├── mde_auth.py          # MDE auth
│   ├── es_auth.py           # Elastic auth
│   ├── middleware/           # 8 ASGI middleware classes
│   ├── routers/             # ~65 router modules
│   └── dto/                 # Request/response DTOs
├── domain/                  # Dataclass models
├── application/             # CQRS command/query handlers
├── repository/              # Store wrappers per domain
├── infrastructure/
│   ├── seed.py              # Seed orchestrator
│   ├── seeders/             # ~50 domain-specific seeders
│   └── persistence.py       # Optional file persistence
└── utils/                   # Shared utilities
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
| `CORS_ORIGINS` | `http://localhost:5173,http://localhost:8001` | Allowed CORS origins |
| `SEED_COUNT_AGENTS` | `60` | Number of agents to seed |
| `SEED_COUNT_THREATS` | `30` | Number of threats to seed |
| `SEED_COUNT_ALERTS` | `20` | Number of alerts to seed |
| `MOCKDR_PERSIST` | (empty) | File path for JSON persistence |
