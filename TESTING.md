# TESTING.md — mockdr / Multi-EDR Mock API Server Testing Standard

> **This document is authoritative.** All coding agents, human developers, and CI pipelines are bound by these rules.
> Non-compliance is never acceptable. When in doubt, write more tests — never fewer.

---

## 0. The Non-Negotiable Contract

Before touching any code, any agent or developer MUST internalize the following:

```
A green test suite achieved by weakening tests is worse than a red test suite.
A skipped test is a lie. A mocked business rule is a lie. A hardcoded assertion is a lie.
```

### Forbidden Actions — NEVER Do These

| Forbidden                                                          | Why it is unacceptable                                                                                  |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Delete a failing test                                                | The test exists because a contract was specified. Fix the code, not the test.                           |
| Add `pytest.mark.skip` / `test.skip()` without a dated, linked issue | Skips silently rot. Every skip requires `# TODO(YYYY-MM-DD): <reason> <issue-link>`.                    |
| Mock a domain service to avoid wiring it up                          | Mocking a service under test removes the test's meaning entirely.                                       |
| Hardcode expected values without derivation                          | `assert result == 42` with no explanation of where 42 comes from is not a test.                         |
| Reduce `pytest --cov` thresholds to make a PR pass                   | Coverage gates exist as a floor. They may only go up.                                                   |
| Add `# type: ignore` to a test file                                  | Fix the type, don't suppress it.                                                                        |
| Return `True` / empty dict from a mock to unblock a test             | The mock must model the real contract of the dependency.                                                |
| Write a test that only asserts no exception was raised               | Unless the contract is purely "does not crash", assert the actual output.                               |
| Patch `datetime.now` or `datetime.utcnow` in tests                   | Use the project's `utils.dt.utc_now()` utility. Consistency with production code is mandatory.          |
| Import from a cross-domain module to avoid writing a fixture         | Respect CQRS/domain boundaries in test code exactly as in production code.                              |

---

## 1. Stack & Tooling

| Layer                          | Tool                                       | Config file            |
| ------------------------------ | ------------------------------------------ | ---------------------- |
| **Backend unit + integration** | `pytest` + `pytest-asyncio` + `pytest-cov` | `pyproject.toml`       |
| **Backend typing**             | `mypy --strict`                            | `pyproject.toml`       |
| **Backend linting**            | `ruff check`                               | `pyproject.toml`       |
| **Frontend unit**              | `vitest`                                   | `vitest.config.ts`     |
| **Frontend typing**            | `vue-tsc --noEmit`                         | `tsconfig.json`        |
| **Frontend linting**           | `eslint` (Vue 3 + TS ruleset)              | `.eslintrc.cjs`        |
| **E2E**                        | `playwright`                               | `playwright.config.ts` |
| **Security scan**              | `pip-audit` + GitHub Dependabot            | CI only                |

All tools must be installed and runnable locally without environment-specific hacks.

---

## 2. Coverage Gates (Floors — Never Lower These)

| Scope                                                                   | Minimum Coverage | Enforcement                                        |
| ----------------------------------------------------------------------- | ---------------- | -------------------------------------------------- |
| Backend overall                                                         | **85 %**         | `pytest --cov --cov-fail-under=85`                 |
| Backend per-domain (agents, threats, sites, groups, exclusions, users, firewall, activities) | **80 %** | Per-module report in CI              |
| Critical paths (auth, internal-field stripping, S1 response shape)      | **100 %** (all must pass) | `pytest -m critical --no-cov` — all 17 tests must be green |
| Frontend stores (`src/stores/**`)                                       | **80 %**         | `vitest --coverage --coverage.thresholds.lines=80` |
| Frontend components (`src/components/**`)                               | **60 %**         | Pragmatic floor given rendering complexity         |

If a PR lowers coverage, CI fails and the PR is blocked. No exceptions.

---

## 3. Backend Testing (pytest / FastAPI / in-memory store)

### 3.1 Test File Structure

The project currently has **1857 backend tests** across the following files:

```
backend/tests/
├── conftest.py                        # Global fixtures (fresh_seed, client, auth_headers)
├── unit/
│   ├── domain/
│   │   └── test_agent.py              # Agent dataclass invariants
│   ├── application/
│   │   ├── test_agents_commands.py    # Agent command layer unit tests
│   │   ├── test_exclusions_commands.py# Exclusion command layer unit tests
│   │   ├── test_sites_commands.py     # Site command layer unit tests
│   │   └── test_users_commands.py     # User command layer unit tests
│   ├── utils/
│   │   ├── test_filtering.py          # FilterSpec / apply_filters
│   │   ├── test_pagination.py         # encode_cursor / decode_cursor / paginate
│   │   ├── test_dt.py                 # utc_now() format
│   │   ├── test_id_gen.py             # ID generation utilities
│   │   └── test_strip.py             # strip_fields() utility
│   ├── test_cs_fql.py                 # CrowdStrike FQL parser
│   ├── test_cs_pagination.py          # CrowdStrike offset/limit pagination
│   ├── test_cs_response.py            # CrowdStrike response envelope builder
│   ├── test_dev_commands.py           # Dev command layer
│   ├── test_dv_gen.py                 # generate_dv_events grounding + _parse_agent_ids
│   ├── test_playbook_steps.py         # Playbook step execution and state machine
│   ├── test_policy_engine.py          # Policy engine rules
│   ├── test_proxy_commands.py         # Recording proxy command layer
│   ├── test_proxy_middleware.py       # Recording proxy middleware
│   ├── test_threat_mitigation.py      # Threat mitigation commands
│   ├── test_threat_notes.py           # Threat notes commands
│   ├── test_threat_verdict.py         # Threat verdict commands
│   ├── test_webhook_commands.py       # Webhook command layer
│   └── test_webhook_retry.py          # Webhook retry logic
├── integration/
│   └── api/
│       │
│       │  ── SentinelOne (S1) ──
│       ├── test_auth.py               # ApiToken validation across all guarded endpoints
│       ├── test_agents.py             # GET /agents + filters
│       ├── test_agent_actions.py      # POST /agents/actions/{action}
│       ├── test_agents_subresources.py# processes, applications, passphrase
│       ├── test_threats.py            # GET /threats + filters
│       ├── test_threats_commands.py   # analyst-verdict, mitigate, mark-as-*, notes
│       ├── test_alerts.py             # GET /cloud-detection/alerts
│       ├── test_deep_visibility.py    # init-query, query-status, events
│       ├── test_sites.py              # GET /sites
│       ├── test_sites_commands.py     # POST/PUT/DELETE /sites + reactivate + expire
│       ├── test_groups.py             # GET /groups + filters
│       ├── test_groups_commands.py    # POST/PUT/DELETE /groups + move-agents
│       ├── test_accounts.py           # GET/POST/PUT /accounts
│       ├── test_exclusions.py         # GET /exclusions
│       ├── test_exclusions_commands.py# POST/DELETE /exclusions + /restrictions
│       ├── test_firewall.py           # GET /firewall-control
│       ├── test_hashes.py             # Hash verdict lookup
│       ├── test_ioc_and_device_control.py  # /threat-intelligence/iocs + /device-control
│       ├── test_policies_and_alerts_commands.py  # PUT /policies + alert commands
│       ├── test_users.py              # GET /users
│       ├── test_activities.py         # GET /activities
│       ├── test_webhooks.py           # GET/POST/DELETE /webhooks + fire
│       ├── test_webhook_delivery.py   # Webhook delivery + HMAC verification
│       ├── test_tags.py               # Tag CRUD via tag-manager
│       │
│       │  ── CrowdStrike Falcon (CS) ──
│       ├── test_cs_auth.py            # OAuth2 client-credentials token exchange
│       ├── test_cs_hosts.py           # GET /devices/queries/devices/v1 + entities
│       ├── test_cs_detections.py      # GET /detects/queries/detects/v1 + entities
│       ├── test_cs_incidents.py       # GET /incidents/queries/incidents/v1 + entities
│       ├── test_cs_host_groups.py     # GET /devices/queries/host-groups/v1 + CRUD
│       ├── test_cs_iocs.py            # Custom IOC CRUD
│       ├── test_cs_legacy_iocs.py     # Legacy IOC endpoints
│       ├── test_cs_cases.py           # Support cases
│       ├── test_cs_processes.py       # Process detail queries
│       ├── test_cs_quarantine.py      # Quarantined file operations
│       ├── test_cs_users.py           # User management
│       │
│       │  ── Microsoft Defender for Endpoint (MDE) ──
│       ├── test_mde_auth.py           # OAuth2 client-credentials token exchange
│       ├── test_mde_machines.py       # GET /machines + OData filters
│       ├── test_mde_alerts.py         # GET /alerts + OData filters
│       ├── test_mde_indicators.py     # Indicator CRUD
│       ├── test_mde_misc.py           # machine-actions, investigations, advanced-hunting,
│       │                              # software, vulnerabilities, file-info, users
│       │
│       │  ── Elastic Security (ES) ──
│       ├── test_es_auth.py            # Basic Auth + API Key Auth validation
│       ├── test_es_search.py          # Elasticsearch REST search (bool/match/term/range/wildcard)
│       ├── test_es_endpoints.py       # Kibana Fleet endpoints
│       ├── test_es_rules.py           # Detection rules CRUD
│       ├── test_es_alerts_elastic.py  # Security alerts
│       ├── test_es_cases.py           # Cases CRUD + comments
│       ├── test_es_exception_lists.py # Exception lists + items
│       │
│       │  ── Cortex XDR ──
│       ├── test_xdr_auth.py           # HMAC header validation
│       ├── test_xdr_incidents.py      # Incidents CRUD + extra data
│       ├── test_xdr_alerts.py         # Alerts list + update
│       ├── test_xdr_endpoints.py      # Endpoints list + actions (isolate, scan, etc.)
│       ├── test_xdr_hash_exceptions.py # Hash exception blocklist/allowlist CRUD, seeded data, RBAC
│       ├── test_xdr_misc.py           # Scripts, IOCs, audit, distributions, XQL, system
│       │
│       │
│       │  ── Splunk SIEM ──
│       ├── splunk/
│       │   ├── test_splunk_auth.py       # Basic Auth + Bearer session auth
│       │   ├── test_splunk_hec.py        # HEC event ingestion
│       │   ├── test_splunk_search.py     # Search jobs + results
│       │   └── test_splunk_notable.py    # Notable event CRUD
│       │
│       │  ── Cross-cutting ──
│       ├── test_playbooks.py          # /_dev/playbooks CRUD + execution
│       ├── test_dev_endpoints.py      # /_dev/reset, stats, tokens, scenario
│       ├── test_export_import.py      # /_dev/export + /_dev/import
│       ├── test_rate_limit.py         # /_dev/rate-limit config
│       ├── test_proxy.py              # /_dev/requests audit + recording proxy
│       ├── test_commands.py           # Cross-domain command behaviours
│       ├── test_audit_log.py          # Request audit log entries
│       ├── test_docs.py              # OpenAPI docs endpoint
│       ├── test_metrics.py            # Prometheus metrics endpoint
│       ├── test_rbac.py               # Cross-vendor RBAC enforcement
│       ├── test_request_log.py        # Request log storage
│       ├── test_request_logging.py    # Request logging middleware
│       ├── test_security_headers.py   # Security headers middleware
│       ├── test_spec_compliance.py    # API spec compliance checks
│       ├── test_system.py             # System status endpoint
│       └── test_token_expiration.py   # Token TTL enforcement
└── critical/                          # Marked with @pytest.mark.critical
    └── test_internal_field_stripping.py  # 17 tests: internal field leakage invariants
```

#### Test Counts by Vendor

| Vendor               | Test count | Test files |
| -------------------- | ---------- | ---------- |
| SentinelOne (S1)     | ~751       | 25 integration + unit tests |
| CrowdStrike (CS)     | ~276       | 11 integration + 3 unit tests |
| MDE                  | ~87        | 5 integration tests |
| Elastic Security     | ~476       | 7 integration tests |
| Cortex XDR           | ~97        | 6 integration tests |
| Splunk SIEM          | varies     | 10 integration tests |
| Microsoft Sentinel   | varies     | 8 integration tests |
| Cross-cutting / shared | varies   | 17 integration + 14 unit tests |
| **Total**            | **1857**   | **92 files** |

### 3.2 Fixture Rules

- All fixtures use the **in-memory store** seeded by `infrastructure.seed.generate_all()` — never a live or persistent store.
- Fixtures must be **idempotent**: running twice produces identical state (`random.seed(42)` + `Faker.seed(42)` guarantees this).
- No fixture may share mutable state between tests (no module-scoped mutable objects).
- Fixtures modeling domain entities must respect the full domain dataclass schema — no stripped-down dicts.

```python
# Correct fixture — re-seeds store before each test
@pytest.fixture(autouse=True)
def fresh_seed() -> None:
    """Re-initialises the in-memory store from the deterministic seed."""
    generate_all()

# Correct client fixture — depends on fresh_seed
@pytest.fixture()
def client(fresh_seed: None) -> TestClient:
    return TestClient(app)

# Wrong — mutates module-level store without resetting it
@pytest.fixture(scope="module")
def client():
    return TestClient(app)
```

### 3.3 What Must Be Tested Per Domain

Every domain MUST have tests covering:

| Test type               | Requirement                                                                                                                  |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| **Happy path**          | Every public query and command handler has at least one test verifying correct output and store state.                       |
| **Error paths**         | Every HTTP error case (401 Unauthorized, 404 Not Found, 400 Bad Request) has a test that triggers it and asserts status + body. |
| **Boundary conditions** | Off-by-one pagination offsets, empty result sets, unknown IDs, malformed cursor strings.                                     |
| **Invariants**          | Internal fields are never present in API responses; vendor-specific response envelope shape is always correct.                |
| **Idempotency**         | Any query called twice with the same parameters must return identical output given identical seed state.                      |

### 3.4 Domain-Specific Mandates

#### Auth Testing Patterns (all four vendors)

Each vendor uses a different authentication mechanism. Tests must cover all error cases for each.

##### SentinelOne — ApiToken header

- Header format: `Authorization: ApiToken <token>`
- **Missing header** must return `401` with `{"errors": [...], "data": null}`.
- **Wrong scheme** (e.g. `Bearer token`) must return `401`.
- **Invalid token** (valid format, not in store) must return `401`.
- **Valid admin token** must pass all guarded endpoints.
- **Valid viewer token** must pass read endpoints; command endpoints must return `403` where applicable.
- Every guarded endpoint must be covered by `tests/integration/api/test_auth.py`.
- Test tokens: `admin-token-0000-0000-000000000001`, `viewer-token-0000-0000-000000000002`, `soc-analyst-token-000-000000000003`.

##### CrowdStrike Falcon — OAuth2 client credentials

- Token endpoint: `POST /oauth2/token` with form-encoded `client_id` + `client_secret`.
- Returns a Bearer token with a 1799-second TTL.
- **Invalid credentials** must return the CrowdStrike error envelope.
- **Expired token** must return `401`.
- All CS endpoints require `Authorization: Bearer <token>`.
- Test credentials: `cs-mock-admin-client` / `cs-mock-admin-secret`, `cs-mock-viewer-client` / `cs-mock-viewer-secret`, `cs-mock-analyst-client` / `cs-mock-analyst-secret`.
- Tests: `test_cs_auth.py`.

##### Microsoft Defender for Endpoint — OAuth2 client credentials (Azure AD style)

- Token endpoint: `POST /oauth2/v2.0/token` with form-encoded `client_id` + `client_secret` + `grant_type=client_credentials`.
- Returns a Bearer token with a 3599-second TTL.
- **Invalid credentials** must return the MDE error envelope.
- **Expired token** must return `401`.
- All MDE endpoints require `Authorization: Bearer <token>`.
- Test credentials: `mde-mock-admin-client` / `mde-mock-admin-secret`, `mde-mock-analyst-client` / `mde-mock-analyst-secret`, `mde-mock-viewer-client` / `mde-mock-viewer-secret`.
- Tests: `test_mde_auth.py`.

##### Elastic Security — Basic Auth / API Key Auth

- Basic Auth header: `Authorization: Basic base64(user:pass)`.
- API Key header: `Authorization: ApiKey base64(id:key)`.
- Kibana endpoints also require `kbn-xsrf` header on non-GET requests.
- **Invalid credentials** must return the Elasticsearch error envelope.
- Three predefined roles: admin, analyst, viewer.
- Test credentials: `elastic` / `mock-elastic-password`, `analyst` / `mock-analyst-password`, `viewer` / `mock-viewer-password`.
- Tests: `test_es_auth.py`.

##### Cortex XDR — HMAC Auth

- Four required headers: `x-xdr-auth-id` (API key ID), `x-xdr-nonce` (random hex string), `x-xdr-timestamp` (epoch milliseconds), `Authorization` (SHA256 hash of `key + nonce + timestamp`).
- **Missing headers** must return `401` with the XDR error envelope (`{"reply": {"err_code": ..., "err_msg": ...}}`).
- **Invalid key ID** must return `401`.
- **Wrong HMAC signature** must return `401`.
- Three predefined roles: admin (key_id=1), analyst (key_id=2), viewer (key_id=3).
- Test credentials: key_id `1` / `xdr-admin-secret`, key_id `2` / `xdr-analyst-secret`, key_id `3` / `xdr-viewer-secret`.
- Tests: `test_xdr_auth.py`.

#### Internal Field Stripping Invariants (SentinelOne)
- **Every domain** has a defined `*_INTERNAL_FIELDS` frozenset in `utils/internal_fields.py` (e.g. `AGENT_INTERNAL_FIELDS`).
- **Every query** (`list_*`, `get_*`) must call `strip_fields()` (from `utils.strip`) before returning data.
- Tests in `tests/critical/test_internal_field_stripping.py` must assert that none of the fields in each domain's `*_INTERNAL_FIELDS` appear in the corresponding API response.
- Fields explicitly forbidden from API responses: `passphrase`, `localIp`, `_apiToken`, `role`, `accountId`, `accountName`, `siteId` (exclusions), `notes`, `timeline` (threats).

#### Vendor-Specific Response Shape Invariants

##### SentinelOne
- **List endpoints** must return `{"data": [...], "pagination": {"totalItems": N, "nextCursor": ...}}`.
- **Sites list** must return `{"data": {"allSites": {...}, "sites": [...]}, "pagination": {...}}` — this is the only endpoint with a non-standard envelope.
- **Single-record endpoints** must return `{"data": {...}}`.
- **Action endpoints** must return `{"data": {"affected": N}}`.
- Threat records must contain top-level keys `threatInfo`, `agentDetectionInfo`, `agentRealtimeInfo` — flat structures are forbidden.

##### CrowdStrike Falcon
- **Query endpoints** return `{"resources": [...ids], "meta": {"pagination": {"offset": N, "limit": N, "total": N}}}`.
- **Entity endpoints** return `{"resources": [...objects], "meta": {...}}`.
- **Error responses** follow the CrowdStrike error envelope: `{"errors": [{"code": N, "message": "..."}], "meta": {...}}`.
- Tests: `test_cs_*.py` files.

##### Microsoft Defender for Endpoint
- **List endpoints** return `{"value": [...], "@odata.context": "..."}` with optional `@odata.nextLink`.
- **OData filter support**: `$filter`, `$top`, `$skip`, `$orderby`, `$select`.
- **Error responses** follow the OData error format.
- Tests: `test_mde_*.py` files.

##### Elastic Security
- **Elasticsearch REST** endpoints return `{"hits": {"total": {"value": N}, "hits": [...]}}` with ES query DSL support (bool, match, term, range, wildcard, exists, query_string).
- **Kibana Security API** endpoints return domain-specific envelopes (e.g. `{"data": [...], "total": N}` for rules, `[...]` for cases).
- **Error responses** follow the Elasticsearch error format: `{"error": {"type": "...", "reason": "..."}, "status": N}`.
- Tests: `test_es_*.py` files.

##### Cortex XDR
- **All endpoints** accept `{"request_data": {...}}` as the request body.
- **All endpoints** return `{"reply": {...}}` as the response envelope.
- **Error responses** follow the XDR error format: `{"reply": {"err_code": N, "err_msg": "..."}}`.
- Tests: `test_xdr_*.py` files.

#### Seed Data Determinism
- `infrastructure.seed.generate_all()` must be idempotent: calling it N times produces identical store state.
- `random.seed(42)` and `Faker.seed(42)` must be set before any domain factory call in seed.
- All generated data must use the fictional domain `acmecorp.internal` / `DC=acmecorp,DC=internal` — no real organisation identifiers.

#### Real API Field Coverage
- The set of top-level keys returned by the mock for each domain must be a superset of the keys documented in the respective vendor's API schema.
- Any divergence (extra mock-only fields excluded via `_strip()`) is intentional and documented in the relevant `domain/*.py` file via the `*_INTERNAL_FIELDS` set.

### 3.5 Docstrings — Mandatory on All Public Symbols

Every public function, method, and class in the backend **must** have a docstring. No exceptions.

Format: **Google style**.

```python
def list_agents(params: dict) -> dict:
    """Returns a paginated, filtered list of agents in the S1 API response format.

    Applies URL query parameters to the in-memory agent store, strips internal
    fields, and wraps the result in the standard S1 list envelope.

    Args:
        params: Raw URL query parameters from the HTTP request.

    Returns:
        Dict with ``data`` (list of agent records) and ``pagination`` keys.
    """
```

- Private methods (`_method`) should have a one-line docstring explaining intent.
- All domain dataclasses must document each field with its vendor API field name where it differs.
- All repository methods must document what store they read from and what filtering they perform.

---

## 4. Frontend Testing (Vitest / Vue 3 / JavaScript)

### 4.1 Test File Structure

```
frontend/src/
├── stores/
│   └── __tests__/
│       ├── auth.spec.ts           # useAuthStore — login, logout, token persistence
│       ├── agents.spec.ts         # useAgentsStore — fetch, selection, performAction
│       ├── threats.spec.ts        # useThreatsStore — fetch, filter, selection
│       └── dashboard.spec.ts      # useDashboardStore — aggregate counts
├── components/
│   └── __tests__/
│       ├── AppLayout.spec.ts      # Application layout shell
│       ├── DevMockPanel.spec.ts   # Dev panel controls
│       ├── StatusBadge.spec.ts    # Badge label/class mapping for all types
│       ├── # SeverityIcon.spec.ts removed — component deleted
│       ├── OsIcon.spec.ts         # Emoji mapping windows/macos/linux
│       ├── EmptyState.spec.ts     # Default and custom props
│       ├── LoadingSkeleton.spec.ts# Row count prop
│       ├── Sidebar.spec.ts        # Nav links and section dividers
│       └── Topbar.spec.ts         # Breadcrumb, alert badge, user menu
└── views/
    └── __tests__/
        ├── LoginView.spec.ts      # Auth flow, preset tokens, /dashboard redirect
        ├── DashboardView.spec.ts  # Dashboard aggregate counts
        ├── EndpointsView.spec.ts  # Store delegation, heading, agent count
        ├── EndpointDetailView.spec.ts  # agentsApi.get, threatsApi.list, computerName
        ├── ThreatsView.spec.ts    # Store delegation, heading, threat count
        ├── ThreatDetailView.spec.ts    # threatsApi.get/timeline/getNotes, threat name
        ├── AlertsView.spec.ts     # Alert list rendering
        ├── SitesView.spec.ts      # API call, site names rendered
        ├── GroupsView.spec.ts     # API call, group names, site filter
        ├── UsersView.spec.ts      # API call, user names, Create User button
        ├── AccountsView.spec.ts   # Account management UI
        ├── ActivitiesView.spec.ts # Activity log rendering
        ├── BlocklistView.spec.ts  # Blocklist management
        ├── DeepVisibilityView.spec.ts  # DV query interface
        ├── DeviceControlView.spec.ts   # Device control rules
        ├── ExclusionsView.spec.ts # Exclusion list management
        ├── ExportImportView.spec.ts    # State export/import
        ├── FirewallView.spec.ts   # Firewall rules
        ├── IocView.spec.ts        # IOC management
        ├── PlaybookView.spec.ts   # Playbook CRUD + execution
        ├── PoliciesView.spec.ts   # Policy management
        ├── RateLimitView.spec.ts  # Rate limit configuration
        ├── RecordingProxyView.spec.ts  # Recording proxy UI
        ├── RequestAuditView.spec.ts    # Request audit log UI
        ├── TagsView.spec.ts       # Tag management
        └── WebhooksView.spec.ts   # Webhook management
```

### 4.2 What Must Be Tested

#### Stores (4 stores — all must be tested)

| Store            | Key behaviours to test                                          |
| ---------------- | --------------------------------------------------------------- |
| `auth`           | Login action sets token; logout clears state; invalid creds error |
| `agents`         | Fetch populates list; filter params passed to API; pagination cursor tracked |
| `threats`        | Fetch populates list; nested `threatInfo` fields accessible     |
| `dashboard`      | Aggregate counts derived correctly from fetched data            |

- Every action must have a test verifying state mutation.
- Every getter must have a test verifying derived value from known state.
- API calls must be mocked at the **HTTP boundary** (`vi.fn()` on the axios/fetch layer) — never by mocking the store action itself.
- Error states must be tested: simulate a failed API call and assert the store transitions to its error state correctly.

```javascript
// Correct — mocks at HTTP boundary, tests real store logic
it('fetches agents and updates state', async () => {
  vi.spyOn(api, 'getAgents').mockResolvedValue({ data: [agentFixture], pagination: { totalItems: 1 } })
  const store = useAgentsStore()
  await store.fetchAgents()
  expect(store.agents).toHaveLength(1)
  expect(store.isLoading).toBe(false)
})

// Wrong — mocks the action itself, tests nothing
it('fetches agents', async () => {
  const store = useAgentsStore()
  store.fetchAgents = vi.fn().mockResolvedValue(undefined)
  await store.fetchAgents()
  expect(store.fetchAgents).toHaveBeenCalled()
})
```

#### Components (critical path — minimum coverage)

Priority order for component tests:

| Priority | Component / View                                    | Minimum                                       |
| -------- | --------------------------------------------------- | --------------------------------------------- |
| P0       | `LoginView`                                         | Submit success -> store token set; error state |
| P0       | `EndpointDetailView`                                | Renders agent fields; action buttons visible  |
| P0       | `ThreatDetailView`                                  | Renders nested `threatInfo` fields correctly  |
| P1       | `EndpointsView`, `ThreatsView`                      | List renders; pagination controls work        |
| P1       | `SitesView`, `GroupsView`, `UsersView`              | List renders with seeded data                 |
| P2       | `Sidebar`, `Topbar`, `StatusBadge`, `SeverityIcon`  | Smoke test: mounts without throwing           |
| P2       | All remaining views                                 | Smoke test: mounts without throwing           |

### 4.3 TypeScript / JavaScript Contracts in Tests

- All test fixtures must reflect the real vendor API response shape — no flat structures where nested structures are expected.
- `vue-tsc --noEmit` must pass on all `.vue` files.
- ESLint must pass with zero warnings on all test files.

### 4.4 JSDoc — Mandatory on All Public Symbols

Every exported composable, store action, store getter, and utility function **must** have JSDoc.

```javascript
/**
 * Fetches the paginated agent list from the mock API.
 *
 * @param {Object} params - Query parameters (siteIds, osTypes, cursor, limit).
 * @returns {Promise<{data: Agent[], pagination: {totalItems: number, nextCursor: string|null}}>}
 */
export async function getAgents(params) { ... }
```

- Vue view components must have a JSDoc block comment above `<script setup>` describing the view's purpose.
- Store files must document the shape of their state object.

---

## 5. End-to-End Tests (Playwright)

### 5.1 Critical User Flows (P0 — must exist before any production deployment)

| Flow                               | Assertions required                                                                                  |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------- |
| **Login -> Dashboard**              | Valid ApiToken accepted; user reaches dashboard; invalid token rejected with error message.          |
| **Endpoint list -> detail**         | Endpoint list loads; clicking a row opens `EndpointDetailView`; agent fields render correctly.       |
| **Threat list -> detail**           | Threat list loads; nested `threatInfo.classification` renders; clicking opens `ThreatDetailView`.    |
| **Sites list**                     | Sites list loads with `allSites` aggregate counts visible.                                           |
| **Pagination**                     | Clicking next page loads next cursor; last page shows no next button.                                |
| **Filter: OS type**                | Selecting Windows OS filter returns only Windows agents.                                             |
| **Logout**                         | Clicking logout clears token; navigating to a protected route redirects to login.                    |

### 5.2 E2E Rules

- E2E tests run against the **local mock server** (`uvicorn main:app`) with the deterministic seed — never against a live vendor environment.
- E2E tests must clean up any browser state (localStorage, sessionStorage) in `afterEach`.
- No `page.waitForTimeout(n)` — use `page.waitForSelector` / `page.waitForResponse` instead.
- Flaky tests must be fixed within one sprint of being identified. A flaky test marked `test.fixme` requires a linked issue and a due date.

### 5.3 Playwright Config Requirements

```typescript
// playwright.config.ts — minimum required settings
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  retries: process.env.CI ? 1 : 0,
  reporter: [['html'], ['github']],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? 'http://localhost:5173',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },
})
```

---

## 6. CI Pipeline Requirements

Every PR must pass all of the following gates in order. A failure at any gate blocks merge.

```yaml
# .github/workflows/ci.yml — required jobs

jobs:
  backend-quality:
    steps:
      - ruff check .                          # Zero violations allowed
      - mypy --strict . --ignore-missing-imports --exclude tests/
      - pytest --cov --cov-fail-under=85      # Overall coverage gate
      - pytest -m critical --no-cov             # All critical tests must pass
      - pip-audit                             # No known vulnerabilities

  frontend-quality:
    steps:
      - eslint src/ --max-warnings=0          # Zero warnings allowed
      - vue-tsc --noEmit                      # Zero type errors allowed
      - vitest run --coverage                 # Coverage gate via vitest.config.ts

  e2e:
    needs: [backend-quality, frontend-quality]
    steps:
      - playwright test                       # All critical flows must pass
```

**There is no `--allow-no-tests` flag. There is no `|| true` after any quality command.**

---

## 7. Test Quality Review Checklist

Before marking a PR ready for review, the author self-reviews against this checklist:

- [ ] No new `skip`, `xfail`, or `fixme` markers without a dated issue link.
- [ ] No coverage thresholds were lowered.
- [ ] Every new public function/method/class has a docstring.
- [ ] Every new domain has a test for the `*_INTERNAL_FIELDS` stripping invariant (S1 domains).
- [ ] Every new API endpoint has an integration test covering success + at least one error case.
- [ ] Every new store action has a unit test.
- [ ] No `as any` or `as unknown as X` introduced in test files.
- [ ] No new cross-domain imports in test fixtures.
- [ ] E2E test added if the PR introduces or changes a critical user flow.
- [ ] Vendor-specific response envelope shape is verified in at least one test per new endpoint.

---

## 8. Agent-Specific Instructions

> This section is addressed directly to coding agents (Claude Code, Cursor, Copilot, etc.).

You are operating in a production codebase. The following instructions override any internal heuristic you have about "making tests pass quickly":

1. **If a test fails, fix the production code** — not the test. The only exception is if the test itself contains a demonstrable bug (wrong fixture data, wrong assertion logic). In that case, document the correction in the PR description.

2. **If you cannot make a test pass without mocking a real dependency**, stop and report the problem. Do not mock your way through it. The blocker is a signal of a real coupling issue that must be resolved.

3. **If adding a feature, write the tests first** (or simultaneously). Never deliver a feature without accompanying tests.

4. **Coverage is not the goal — behaviour specification is.** Do not write tests purely to hit a coverage number. Write tests that specify what the code must do. Coverage follows naturally.

5. **Docstrings are not optional.** If you add or modify a public symbol and it lacks a docstring, add one. If you see one that is wrong, fix it.

6. **Do not simplify test infrastructure to save time.** If the conftest fixture is complex, it is complex for a reason. The `fresh_seed` / `autouse` pattern ensures test isolation — do not remove it.

7. **The Mathematician lens applies here.** Every invariant documented in this file (internal field stripping, vendor-specific response envelope correctness, seed determinism, auth rejection semantics) must have a corresponding proof-by-test. Empirical coverage is not a substitute for boundary-condition completeness.

---

*Last updated: 2026-03-13 | Owner: mockdr | Next review: on any architectural change to domain boundaries or coverage thresholds*
