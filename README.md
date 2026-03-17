# mockdr — Multi-EDR Mock Server

[![CI](https://github.com/mockdr/mockdr/actions/workflows/ci.yml/badge.svg)](https://github.com/mockdr/mockdr/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-3776ab.svg)](https://www.python.org/)
[![TypeScript](https://img.shields.io/badge/typescript-5-3178c6.svg)](https://www.typescriptlang.org/)
[![Vue 3](https://img.shields.io/badge/vue-3-42b883.svg)](https://vuejs.org/)
[![Docker](https://img.shields.io/badge/docker-ready-2496ed.svg)](https://www.docker.com/)
[![mypy: strict](https://img.shields.io/badge/mypy-strict-success.svg)](https://mypy.readthedocs.io/)
[![ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/mockdr/mockdr)

A self-contained mock server for **SentinelOne**, **CrowdStrike Falcon**, **Microsoft Defender for Endpoint**, **Elastic Security**, **Cortex XDR**, **Splunk SIEM**, and **Microsoft Sentinel** -- seven security platforms in a single process with realistic seed data, real API paths, and real response envelopes.

SOAR playbooks, SIEM connectors, and automation scripts point at mockdr without modification -- endpoint paths, request/response formats, query parameters, and field names match each vendor's real API.

## Use Cases

| Who                          | What they test against mockdr                                                                                             |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| **SOAR engineers**           | Playbooks for alert triage, threat remediation, agent quarantine -- across all seven vendors without burning lab licences |
| **SIEM integrators**         | EDR log ingestion, field mapping, and parser validation with deterministic, repeatable data                               |
| **Security automation devs** | Python/Go/PowerShell scripts using vendor SDKs -- offline, no VPN, no rate limits                                         |
| **Pentesters / red teamers** | Validate EDR response tooling against realistic agent/threat/alert states before engaging a live tenant                   |
| **QA engineers**             | Regression tests for EDR-integrated products -- seed data resets to a known state on every run                            |

## Supported Platforms

| Platform                         | Prefix                 | Auth Method                                | Response Format                        |
| -------------------------------- | ---------------------- | ------------------------------------------ | -------------------------------------- |
| SentinelOne Singularity API v2.1 | `/web/api/v2.1`        | `ApiToken` header                          | `{"data": [...], "pagination": {...}}` |
| CrowdStrike Falcon               | `/cs`                  | OAuth2 client credentials                  | `{"resources": [...], "meta": {...}}`  |
| Microsoft Defender for Endpoint  | `/mde`                 | OAuth2 client credentials                  | `{"value": [...]}` (OData)             |
| Elastic Security                 | `/elastic` + `/kibana` | Basic Auth or API Key                      | Elasticsearch / Kibana JSON            |
| Cortex XDR                       | `/xdr/public_api/v1`   | HMAC (`x-xdr-auth-id` + nonce + timestamp) | `{"reply": {...}}`                     |
| Splunk SIEM                      | `/splunk`              | Basic Auth, Bearer, or HEC token           | Splunk REST JSON                       |
| Microsoft Sentinel               | `/sentinel`            | OAuth2 client credentials                  | Azure ARM JSON                         |

## Quick Start

### One command (no Docker)

```bash
./start.sh
```

- Frontend: http://localhost:3000
- API: http://localhost:8001
- Swagger: http://localhost:8001/web/api/v2.1/doc

### Docker

```bash
docker-compose up --build
```

Everything on a single port -- FastAPI serves both the API and the built frontend:

- App: http://localhost:5001
- API: http://localhost:5001/web/api/v2.1

### One-click cloud deploy

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/mockdr/mockdr)

Free tier -- no credit card required. Deploys the Docker image with default seed data.

### Manual

```bash
# Backend
cd backend
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
PYTHONPATH=. .venv/bin/uvicorn main:app --port 8001 --reload

# Frontend (separate terminal)
cd frontend
npm install && npm run dev
```

## Authentication

### SentinelOne

All S1 endpoints require `Authorization: ApiToken <token>`.

| Role        | Token                                 |
| ----------- | ------------------------------------- |
| Admin       | `admin-token-0000-0000-000000000001`  |
| Viewer      | `viewer-token-0000-0000-000000000002` |
| SOC Analyst | `soc-analyst-token-000-000000000003`  |

```bash
curl -H "Authorization: ApiToken admin-token-0000-0000-000000000001" \
  http://localhost:8001/web/api/v2.1/agents
```

### CrowdStrike Falcon

OAuth2 client credentials flow. POST to `/cs/oauth2/token` with `client_id` + `client_secret` to receive a Bearer token.

| Role    | Client ID                | Client Secret            |
| ------- | ------------------------ | ------------------------ |
| Admin   | `cs-mock-admin-client`   | `cs-mock-admin-secret`   |
| Analyst | `cs-mock-analyst-client` | `cs-mock-analyst-secret` |
| Viewer  | `cs-mock-viewer-client`  | `cs-mock-viewer-secret`  |

```bash
# Get token
TOKEN=$(curl -s -X POST http://localhost:8001/cs/oauth2/token \
  -d "client_id=cs-mock-admin-client&client_secret=cs-mock-admin-secret" | jq -r .access_token)

# Use token
curl -H "Authorization: Bearer $TOKEN" http://localhost:8001/cs/devices/queries/devices/v1
```

### Microsoft Defender for Endpoint

OAuth2 client credentials flow. POST to `/mde/oauth2/v2.0/token` with `client_id`, `client_secret`, and `grant_type=client_credentials`.

| Role    | Client ID                 | Client Secret             |
| ------- | ------------------------- | ------------------------- |
| Admin   | `mde-mock-admin-client`   | `mde-mock-admin-secret`   |
| Analyst | `mde-mock-analyst-client` | `mde-mock-analyst-secret` |
| Viewer  | `mde-mock-viewer-client`  | `mde-mock-viewer-secret`  |

```bash
TOKEN=$(curl -s -X POST http://localhost:8001/mde/oauth2/v2.0/token \
  -d "client_id=mde-mock-admin-client&client_secret=mde-mock-admin-secret&grant_type=client_credentials" \
  | jq -r .access_token)

curl -H "Authorization: Bearer $TOKEN" http://localhost:8001/mde/api/machines
```

### Elastic Security

Supports two auth methods: **Basic Auth** and **API Key Auth**. Kibana mutation endpoints also require a `kbn-xsrf` header.

**Basic Auth users:**

| Role    | Username  | Password                |
| ------- | --------- | ----------------------- |
| Admin   | `elastic` | `mock-elastic-password` |
| Analyst | `analyst` | `mock-analyst-password` |
| Viewer  | `viewer`  | `mock-viewer-password`  |

**API Keys** (use as `Authorization: ApiKey base64(id:key)`):

| Role    | Key ID               | API Key                   |
| ------- | -------------------- | ------------------------- |
| Admin   | `es-admin-key-001`   | `mock-es-admin-api-key`   |
| Analyst | `es-analyst-key-001` | `mock-es-analyst-api-key` |
| Viewer  | `es-viewer-key-001`  | `mock-es-viewer-api-key`  |

```bash
# Basic Auth
curl -u elastic:mock-elastic-password http://localhost:8001/elastic/_search

# API Key Auth (base64 of "es-admin-key-001:mock-es-admin-api-key")
curl -H "Authorization: ApiKey ZXMtYWRtaW4ta2V5LTAwMTptb2NrLWVzLWFkbWluLWFwaS1rZXk=" \
  http://localhost:8001/kibana/api/detection_engine/rules/_find
```

### Cortex XDR

HMAC-based authentication. Every request must include four headers: `x-xdr-auth-id`, `x-xdr-nonce`, `x-xdr-timestamp`, and `Authorization` (SHA256 hash of key + nonce + timestamp).

| Role    | API Key ID | Secret               |
| ------- | ---------- | -------------------- |
| Admin   | `1`        | `xdr-admin-secret`   |
| Analyst | `2`        | `xdr-analyst-secret` |
| Viewer  | `3`        | `xdr-viewer-secret`  |

```bash
# Generate HMAC auth headers and list incidents
NONCE=$(python3 -c "import secrets; print(secrets.token_hex(32))")
TIMESTAMP=$(date +%s%3N)
AUTH=$(python3 -c "
import hashlib
key = 'xdr-admin-secret'
print(hashlib.sha256(f'{key}{NONCE}{TIMESTAMP}'.encode()).hexdigest())
" NONCE="$NONCE" TIMESTAMP="$TIMESTAMP")

curl -X POST http://localhost:8001/xdr/public_api/v1/incidents/get_incidents \
  -H "x-xdr-auth-id: 1" \
  -H "x-xdr-nonce: $NONCE" \
  -H "x-xdr-timestamp: $TIMESTAMP" \
  -H "Authorization: $AUTH" \
  -H "Content-Type: application/json" \
  -d '{"request_data": {}}'
```

### Splunk SIEM

Supports three auth methods: **Basic Auth**, **Bearer Token** (session key from login), and **HEC Token** (`Authorization: Splunk <token>`) for HTTP Event Collector endpoints.

**Basic Auth users:**

| Role    | Username  | Password         |
| ------- | --------- | ---------------- |
| Admin   | `admin`   | `mockdr-admin`   |
| Analyst | `analyst` | `mockdr-analyst` |
| Viewer  | `viewer`  | `mockdr-viewer`  |

```bash
# Get session key
SESSION=$(curl -s -X POST http://localhost:8001/splunk/services/auth/login \
  -d "username=admin&password=mockdr-admin" | jq -r .sessionKey)

# Use session key
curl -H "Authorization: Bearer $SESSION" http://localhost:8001/splunk/services/server/info
```

**HEC Tokens** (use as `Authorization: Splunk <token>`):

| Name                   | Token                                  | Default Index |
| ---------------------- | -------------------------------------- | ------------- |
| mockdr-edr-sentinelone | `11111111-1111-1111-1111-111111111111` | `sentinelone` |
| mockdr-edr-crowdstrike | `22222222-2222-2222-2222-222222222222` | `crowdstrike` |
| mockdr-edr-general     | `33333333-3333-3333-3333-333333333333` | `main`        |

### Microsoft Sentinel

OAuth2 client credentials flow. POST to `/sentinel/oauth2/v2.0/token` with `client_id` + `client_secret` to receive a Bearer token.

| Client ID                 | Client Secret                 |
| ------------------------- | ----------------------------- |
| `sentinel-mock-client-id` | `sentinel-mock-client-secret` |

```bash
TOKEN=$(curl -s -X POST http://localhost:8001/sentinel/oauth2/v2.0/token \
  -d "client_id=sentinel-mock-client-id&client_secret=sentinel-mock-client-secret" \
  | jq -r .access_token)

curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8001/sentinel/subscriptions/mock-sub/resourceGroups/mock-rg/providers/Microsoft.OperationalInsights/workspaces/mock-ws/providers/Microsoft.SecurityInsights/incidents
```

## API Coverage

### SentinelOne (prefix: `/web/api/v2.1`)

| Domain          | Endpoints                                                                                                                                     |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Agents          | List, get, count, passphrases, tags, processes, applications, 20+ agent actions, fetch-files, file download                                   |
| Threats         | List, get, timeline, notes (single + bulk), analyst-verdict, incident, mitigate (kill/quarantine/remediate/rollback), mark-as-threat/resolved |
| Alerts          | List, get, analyst-verdict, incident                                                                                                          |
| Deep Visibility | init-query, query-status, events, events by type, cancel-query                                                                                |
| Accounts        | List, get, create, update                                                                                                                     |
| Sites           | List, get, create, update, delete, reactivate, expire-now                                                                                     |
| Groups          | List, get, create, update, delete, move-agents                                                                                                |
| Policies        | Get, update (scoped by siteId or groupId)                                                                                                     |
| Exclusions      | List, create, delete (single + bulk)                                                                                                          |
| Blocklist       | List, create, delete (single + bulk)                                                                                                          |
| Firewall Rules  | List, create, update, delete                                                                                                                  |
| Device Control  | List, create, update, delete                                                                                                                  |
| IOCs            | List, create, bulk-create, delete                                                                                                             |
| Tags            | List, get, create, update, delete, assign/unassign to agents                                                                                  |
| Users           | List, get, create, update, delete (single + bulk), generate-api-token, token-details, login-by-token                                          |
| Hashes          | Verdict lookup (checks blocklist)                                                                                                             |
| Activities      | List, types                                                                                                                                   |
| Webhooks        | List, get, create, delete, test fire                                                                                                          |
| System          | Status (public), info, configuration                                                                                                          |

### CrowdStrike Falcon (prefix: `/cs`)

| Domain      | Endpoints                                                    |
| ----------- | ------------------------------------------------------------ |
| Auth        | `POST /oauth2/token` (client credentials flow)               |
| Hosts       | List, get, actions (contain, lift_containment, hide, unhide) |
| Detections  | List, get, update status                                     |
| Incidents   | List, get, update, perform actions                           |
| IOCs        | CRUD (custom indicators)                                     |
| Legacy IOCs | Legacy indicator API                                         |
| Host Groups | CRUD + member management                                     |
| Users       | List, get                                                    |
| Processes   | Process detail lookup                                        |
| Quarantine  | List, get, actions                                           |
| Cases       | List, get, create, update                                    |

### Microsoft Defender for Endpoint (prefix: `/mde`)

| Domain           | Endpoints                                           |
| ---------------- | --------------------------------------------------- |
| Auth             | `POST /oauth2/v2.0/token` (client credentials flow) |
| Machines         | List, get, actions (isolate, unisolate, scan, more) |
| Alerts           | List, get, update, create                           |
| Indicators       | List, get, create, update, delete                   |
| Machine Actions  | List, get, submit actions                           |
| Investigations   | List, get, start, collect                           |
| Advanced Hunting | Run KQL queries                                     |
| Software         | List, get (TVM)                                     |
| Vulnerabilities  | List, get (TVM CVEs)                                |
| File Info        | File information lookup                             |
| Users            | List, get                                           |

### Elastic Security (prefixes: `/elastic` + `/kibana`)

| Domain          | Endpoints                                 |
| --------------- | ----------------------------------------- |
| Auth            | API key validation, basic auth            |
| Search          | `POST /_search` (Elasticsearch query DSL) |
| Endpoints       | List, get endpoint metadata               |
| Detection Rules | CRUD + enable/disable                     |
| Alerts          | List, get, update status                  |
| Cases           | CRUD + comments                           |
| Exception Lists | CRUD (lists + items)                      |

### Cortex XDR (prefix: `/xdr/public_api/v1`)

| Domain          | Endpoints                                                    |
| --------------- | ------------------------------------------------------------ |
| Auth            | HMAC header validation (`x-xdr-auth-id` + nonce + timestamp) |
| Incidents       | List, get, update, extra data                                |
| Alerts          | List, get, update, multi-events                              |
| Endpoints       | List, get, isolate, unisolate, scan, policy                  |
| Scripts         | List, get, execute, execution status/results                 |
| IOCs            | CRUD (indicators of compromise)                              |
| Actions         | Action center — list, get, status                            |
| Hash Exceptions | Allowlist/blocklist list + CRUD                              |
| Audit           | Management + agent audit logs                                |
| Distributions   | Distribution list                                            |
| XQL             | Start query, get results, quota                              |
| System          | Server info, health check                                    |

### Splunk SIEM (prefix: `/splunk`)

| Domain         | Endpoints                                           |
| -------------- | --------------------------------------------------- |
| Auth           | `POST /services/auth/login` (session key flow)      |
| Search         | Create, manage, and retrieve search jobs (full SPL) |
| Notable Events | List, get, update notable events (ES workflow)      |
| Saved Searches | CRUD + dispatch + history                           |
| Indexes        | List, get, create index metadata                    |
| Inputs         | List data inputs                                    |
| HEC            | Event, raw, health, ack (`/services/collector`)     |
| KV Store       | Full CRUD on collections + batch save               |
| Alerts         | List, get, delete fired alerts                      |
| Server         | Server info                                         |
| Users          | List, get users, roles, capabilities                |

#### SPL Search Engine

mockdr includes a **real SPL parser and execution engine** that runs queries against the in-memory event store. Supported pipeline commands:

| Command  | Example                                                           | Description                                    |
| -------- | ----------------------------------------------------------------- | ---------------------------------------------- |
| `search` | `search index=sentinelone sourcetype=sentinelone:channel:threats` | Filter by index, sourcetype, host, field=value |
| `where`  | `where severity="critical"`                                       | Field value filtering                          |
| `head`   | `head 20`                                                         | Limit to first N results                       |
| `tail`   | `tail 10`                                                         | Limit to last N results                        |
| `table`  | `table _time host classification`                                 | Project specific fields                        |
| `stats`  | `stats count by classification`                                   | Aggregate by field                             |
| `sort`   | `sort -count`                                                     | Sort ascending/descending                      |
| `rename` | `rename computerName as hostname`                                 | Rename fields                                  |
| `eval`   | `eval risk=severity*10`                                           | Evaluate expressions                           |

Time modifiers (`earliest=-24h@h latest=now`) and the `` `notable` `` macro are also supported.

```bash
# Run a one-shot search
curl -u admin:mockdr-admin -X POST \
  "http://localhost:8001/splunk/services/search/jobs/export" \
  -d 'search=search index=sentinelone sourcetype=sentinelone:channel:threats | stats count by classification | sort -count' \
  -d 'output_mode=json'
```

### Microsoft Sentinel (prefix: `/sentinel`)

| Domain              | Endpoints                                           |
| ------------------- | --------------------------------------------------- |
| Auth                | `POST /oauth2/v2.0/token` (Azure AD client creds)   |
| Incidents           | List, get, create, update, delete + comments        |
| Alert Rules         | List, get, create, update, delete (analytics rules) |
| Data Connectors     | List, get, create, delete                           |
| Watchlists          | List, get, create, update, delete + items           |
| Threat Intelligence | List, get, create, delete indicators                |
| Bookmarks           | List, get, create, update, delete                   |
| Log Analytics       | Run KQL queries                                     |
| Operations          | Get long-running operation status                   |

## Seed Data

Deterministic seed (`random.seed(42)` + `Faker.seed(42)`) -- same data every cold start. Reset at any time via the DEV panel or `POST /_dev/reset`.

### SentinelOne

- 1 account, 3 sites, 9 groups
- **60 agents** -- Windows/macOS/Linux; desktop/laptop/server; online/offline; tagged
- **30 threats** -- Emotet, TrickBot, Ryuk, WannaCry, LockBit, etc.
- **20 alerts** -- STAR/UAM alerts with all severity/verdict/status combinations
- 15 exclusions, 10 blocklist entries, 8 firewall rules, 6 device control rules, 20 IOCs
- 120 activity log entries spanning 90 days

### CrowdStrike Falcon

- **60 hosts** (mirrored from S1 agent fleet)
- **30 detections** with 1-3 behaviors each
- **15 incidents** grouping hosts and detections
- 5 host groups (3 dynamic, 2 static), 20 IOCs, 8 users, 15 quarantined files, 8 cases

### Microsoft Defender for Endpoint

- **60 machines** (mirrored from S1 agent fleet)
- **40 alerts** with evidence items and comments
- 20 indicators (FileSha256, IpAddress, DomainName)
- 15 machine actions, 10 automated investigations
- ~52 TVM software entries (corporate, EDR agents + outdated versions, EOL, torrent clients, dual-use tools)
- ~15 TVM vulnerability (CVE) records

### Elastic Security

- **60 endpoints** (mirrored from S1 agent fleet)
- **45 alerts** linked to rules and endpoints
- 25 detection rules (KQL, EQL, threshold)
- 8 cases with 2-5 comments each
- 5 exception lists with exception items

### Cortex XDR

- **60 endpoints** (mirrored from S1 agent fleet)
- **20 incidents** with linked alerts and endpoints
- **40 alerts** across multiple severity levels
- ~20 IOCs (hash, IP, domain), 10 hash exceptions (6 blocklist + 4 allowlist)
- 10 scripts with execution history, 15 action center entries
- 30 audit log entries, 5 distribution packages

### Splunk SIEM

All five EDR vendor data sets are **replayed into Splunk indexes** with realistic sourcetypes and field extractions -- the same data, indexed for SIEM analysis.

**Indexes (9):**

| Index              | Content                              | Sourcetypes                                                                                   |
| ------------------ | ------------------------------------ | --------------------------------------------------------------------------------------------- |
| `sentinelone`      | S1 threats, agents, activities       | `sentinelone:channel:threats`, `sentinelone:channel:agents`, `sentinelone:channel:activities` |
| `crowdstrike`      | CS detections, incidents             | `CrowdStrike:Event:Streams:JSON`                                                              |
| `msdefender`       | MDE alerts, machines                 | `ms:defender:endpoint:alerts`, `ms:defender:endpoint:machines`                                |
| `elastic_security` | Elastic alerts, endpoints            | `elastic:security:alerts`, `elastic:security:endpoints`                                       |
| `cortex_xdr`       | XDR incidents, alerts, endpoints     | `pan:xdr:incidents`, `pan:xdr:alerts`, `pan:xdr:endpoints`                                    |
| `notable`          | ES notable events from all 5 vendors | `stash`                                                                                       |
| `main`             | Default index                        | —                                                                                             |
| `_internal`        | Splunk internal logs                 | —                                                                                             |
| `_audit`           | Audit logs                           | —                                                                                             |

**Notable events** are auto-generated from EDR threat/detection/alert data with severity mapping, drilldown SPL queries, and status workflow (New → In Progress → Resolved → Closed).

**Saved searches (5):** One per EDR vendor -- "SentinelOne Threats - Last 24h", "CrowdStrike High Severity Detections", "All EDR Notable Events", "Microsoft Defender Alerts", "Cortex XDR Incidents".

**HEC tokens (3):** SentinelOne (`11111111-...`), CrowdStrike (`22222222-...`), General (`33333333-...`).

**KV Store collections (2):** `splunk_xsoar_users` (XSOAR↔Splunk user mapping), `incident_review_lookup` (notable event triage state).

**Users (3):** admin, analyst, viewer -- matching the auth table above.

**UI (6 views):** SPL search editor, SIEM dashboard with charts, notable event triage, notable detail with drilldown, index browser, HEC token management.

#### Training Examples

```bash
# List all SentinelOne threats by classification
search index=sentinelone sourcetype=sentinelone:channel:threats
  | stats count by classification | sort -count

# Find high-severity CrowdStrike detections
search index=crowdstrike sourcetype="CrowdStrike:Event:Streams:JSON"
  | where Severity>=4 | table _time ComputerName DetectName Severity

# Triage open notable events across all EDR vendors
search `notable` | where status="New"
  | table _time rule_name severity src dest owner

# Cross-vendor threat overview
search index=sentinelone OR index=crowdstrike OR index=msdefender
  | stats count by index | sort -count
```

### Microsoft Sentinel

- Incidents replayed from all 5 EDR vendor data (MDE, S1, CS, Elastic, XDR)
- 5 analytics rules (one per EDR vendor)
- 5 data connectors, 3 watchlists, 3 threat intelligence indicators
- Investigation bookmarks (first 3 incidents) and comments (first 5 incidents)

All data is **in-memory** by default -- mutations survive until server restart or `/_dev/reset`.

**Optional persistence:** set `MOCKDR_PERSIST=/path/to/state.json` to save state across restarts. The server debounces writes (2 s) and uses atomic file replacement to prevent corruption.

## Configuration

| Variable             | Default                                       | Description                                                                                        |
| -------------------- | --------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `SEED_COUNT_AGENTS`  | 60                                            | S1 agents to seed (CS/MDE/Elastic/XDR mirror this count; Splunk/Sentinel replay from all EDR data) |
| `SEED_COUNT_THREATS` | 30                                            | S1 threats to seed                                                                                 |
| `SEED_COUNT_ALERTS`  | 20                                            | S1 alerts to seed                                                                                  |
| `MOCKDR_PERSIST`     | (none)                                        | File path for JSON state persistence across restarts                                               |
| `CORS_ORIGINS`       | `http://localhost:5173,http://localhost:8001` | Comma-separated allowed CORS origins                                                               |

## Middleware Stack

Eight ASGI middleware layers run on every request (outermost first):

| Middleware       | Purpose                                                      |
| ---------------- | ------------------------------------------------------------ |
| Metrics          | Request timing, status code counters (`GET /metrics`)        |
| Request Logging  | Structured JSON logs for every request                       |
| Rate Limit       | Configurable per-minute rate limiting (`/_dev/rate-limit`)   |
| Security Headers | HSTS, X-Content-Type-Options, CSP, etc.                      |
| Request Audit    | Append to queryable audit log (`/_dev/requests`)             |
| Tenant Scope     | Non-admin tokens auto-scoped to their account                |
| Fault Injection  | Artificial latency + random errors (`/_dev/fault-injection`) |
| Recording Proxy  | Record/replay upstream API calls                             |

## DEV Mock Controls

Floating bug icon (bottom-right corner of the UI):

| Control            | Description                            |
| ------------------ | -------------------------------------- |
| Live stats         | Agent / threat / alert counts          |
| Role switcher      | Switch between the three preset tokens |
| Mass Infection     | Infect 20 random agents                |
| APT Campaign       | Targeted attack on 10 agents           |
| Agents Offline     | Take 30% of agents offline             |
| Quiet Day          | Resolve all threats, heal all agents   |
| Reset to Seed Data | Wipe mutations, restore original seed  |
| API Tokens         | Copy any preset token to clipboard     |

## DEV Endpoints

Non-standard endpoints for tooling, test automation, and mock control:

| Endpoint                        | Description                                                                         |
| ------------------------------- | ----------------------------------------------------------------------------------- |
| `POST /_dev/reset`              | Re-seed all data (all seven vendors)                                                |
| `POST /_dev/scenario`           | Trigger a scenario (`mass_infection`, `apt_campaign`, `agent_offline`, `quiet_day`) |
| `GET /_dev/stats`               | Collection counts                                                                   |
| `GET /_dev/tokens`              | All valid API tokens                                                                |
| `GET /_dev/requests`            | Request audit log                                                                   |
| `DELETE /_dev/requests`         | Clear request audit log                                                             |
| `GET /_dev/export`              | Export full store snapshot (JSON)                                                   |
| `POST /_dev/import`             | Import store snapshot                                                               |
| `GET /_dev/rate-limit`          | Get rate-limit configuration                                                        |
| `POST /_dev/rate-limit`         | Update rate-limit configuration                                                     |
| `GET /_dev/playbooks`           | List playbooks (built-in + custom)                                                  |
| `GET /_dev/playbooks/status`    | Current playbook execution status                                                   |
| `GET /_dev/playbooks/{id}`      | Playbook detail with all steps                                                      |
| `POST /_dev/playbooks/{id}/run` | Execute a playbook against an agent                                                 |
| `POST /_dev/playbooks`          | Create custom playbook                                                              |
| `PUT /_dev/playbooks/{id}`      | Update existing playbook                                                            |
| `DELETE /_dev/playbooks/{id}`   | Delete playbook                                                                     |
| `DELETE /_dev/playbooks/cancel` | Cancel active playbook execution                                                    |
| `GET /_dev/webhooks/deliveries` | Webhook delivery log (newest first)                                                 |
| `POST /_dev/webhook-sink`       | Capture incoming webhook (unauthenticated)                                          |
| `GET /_dev/webhook-sink`        | List captured webhooks                                                              |
| `DELETE /_dev/webhook-sink`     | Clear all captured webhooks                                                         |
| `GET /_dev/fault-injection`     | Get fault injection config                                                          |
| `POST /_dev/fault-injection`    | Update fault injection (delay, error rate)                                          |
| `DELETE /_dev/fault-injection`  | Reset fault injection to defaults                                                   |
| `GET /_dev/export/logs`         | Unified structured log export (SIEM-ready)                                          |

## Architecture

```
backend/
├── domain/              # Pure dataclasses — field names match each vendor's API
│   ├── sentinel/        # Microsoft Sentinel domain models
│   └── splunk/          # Splunk SIEM domain models
├── repository/          # Generic Repository[T] + thread-safe InMemoryStore
│   ├── sentinel/        # Sentinel repositories
│   └── splunk/          # Splunk repositories
├── application/
│   ├── <domain>/
│   │   ├── queries.py   # Read side (CQRS) — filter, strip internal fields, paginate
│   │   └── commands.py  # Write side (CQRS) — mutate store, emit activity log
│   ├── sentinel/        # Sentinel application logic
│   └── splunk/          # Splunk application logic
├── api/
│   ├── auth.py          # S1 ApiToken auth
│   ├── cs_auth.py       # CrowdStrike OAuth2 Bearer auth
│   ├── mde_auth.py      # MDE OAuth2 Bearer auth
│   ├── es_auth.py       # Elastic Basic Auth + API Key auth
│   ├── xdr_auth.py      # Cortex XDR HMAC auth
│   ├── splunk_auth.py   # Splunk Basic Auth + Bearer + HEC auth
│   ├── sentinel_auth.py # Sentinel Azure AD OAuth2 auth
│   ├── dto/             # Pydantic request models (HTTP boundary only)
│   └── routers/         # Thin FastAPI routers — one file per domain per vendor
│       ├── splunk/      # Splunk SIEM routers
│       └── sentinel/    # Microsoft Sentinel routers
└── infrastructure/
    ├── seed.py          # Orchestrator — calls per-domain seeders for all 7 vendors
    └── seeders/         # Per-domain Faker-based deterministic data generators (seed 42)
        ├── splunk/      # Splunk infrastructure + EDR event seeders
        └── sentinel/    # Sentinel infrastructure + incident seeders

frontend/                # Vue 3 + TypeScript — vue-tsc strict, ESLint zero-warnings
└── src/
    ├── api/             # Axios client + typed domain API modules (13 modules)
    ├── stores/          # Pinia stores
    ├── types/           # Shared interfaces mirroring each vendor API
    ├── components/      # Shared UI + DevMockPanel (scenarios, role switcher)
    └── views/           # One view per UI page
        ├── cs/          # CrowdStrike views
        ├── elastic/     # Elastic Security views
        ├── mde/         # Microsoft Defender views
        ├── xdr/         # Cortex XDR views
        ├── splunk/      # Splunk SIEM views
        └── sentinel/    # Microsoft Sentinel views
```

## Testing

See [TESTING.md](TESTING.md) for the full test standard.

## GitHub Action

Use mockdr as a service in your CI pipeline:

```yaml
- uses: mockdr/mockdr@main
  with:
    port: 5001
    api-token: admin-token-0000-0000-000000000001

- run: pytest --base-url http://localhost:5001
```

The action starts the server, waits for it to be healthy, and exposes `base-url` and `api-token` outputs. All seven vendor mocks are available on the same port.

## Docker

```bash
# Build and run
docker build -t mockdr .
docker run -p 5001:5001 mockdr

# With persistence
docker run -p 5001:5001 -e MOCKDR_PERSIST=/data/state.json -v mockdr-data:/data mockdr
```

The image uses a multi-stage build (Node 20 for frontend, Python 3.12-slim for runtime) with a built-in healthcheck.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code standards, and PR guidelines.

## License

mockdr is dual-licensed:

- **Open source** under the [GNU Affero General Public License v3.0](LICENSE) -- free for open-source projects, personal use, and any use that complies with AGPL-3.0 obligations (including making source available for network services).
- **Commercial license** available for organizations that need to use mockdr in proprietary products or cannot comply with AGPL-3.0. See [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md) for details.

Copyright (c) 2026 Guenter Weber. All rights reserved.
