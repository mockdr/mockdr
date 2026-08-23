# mockdr — Multi-EDR Mock Server

[![CI](https://github.com/mockdr/mockdr/actions/workflows/ci.yml/badge.svg)](https://github.com/mockdr/mockdr/actions/workflows/ci.yml)
[![License: BSL 1.1](https://img.shields.io/badge/License-BSL_1.1-orange.svg)](LICENSE.md)
[![Python 3.12](https://img.shields.io/badge/python-3.12-3776ab.svg)](https://www.python.org/)
[![TypeScript](https://img.shields.io/badge/typescript-5-3178c6.svg)](https://www.typescriptlang.org/)
[![Vue 3](https://img.shields.io/badge/vue-3-42b883.svg)](https://vuejs.org/)
[![Docker](https://img.shields.io/badge/docker-ready-2496ed.svg)](https://www.docker.com/)
[![mypy: strict](https://img.shields.io/badge/mypy-strict-success.svg)](https://mypy.readthedocs.io/)
[![ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/mockdr/mockdr)

A self-contained mock server for **SentinelOne**, **CrowdStrike Falcon**, **Microsoft Defender for Endpoint**, **Elastic Security**, **Cortex XDR**, **Splunk SIEM**, **Microsoft Sentinel**, and **Microsoft Graph API** (Entra ID, Intune, M365, Security) -- eight security platforms in a single process with realistic seed data, real API paths, and real response envelopes.

SOAR playbooks, SIEM connectors, and automation scripts point at mockdr without modification -- endpoint paths, request/response formats, query parameters, and field names match each vendor's real API.

## Use Cases

| Who                          | What they test against mockdr                                                                                             |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| **SOAR engineers**           | Playbooks for alert triage, threat remediation, agent quarantine -- across all eight vendors without burning lab licences |
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
| Cortex XDR                       | `/xdr/public_api/v1`   | API key or SHA-256 digest (`x-xdr-auth-id`) | `{"reply": {...}}`                     |
| Splunk SIEM                      | `/splunk`              | Basic Auth, Bearer, or HEC token           | Splunk REST JSON                       |
| Microsoft Sentinel               | `/sentinel`            | OAuth2 client credentials                  | Azure ARM JSON                         |
| Microsoft Graph API (Entra ID, Intune, M365, Security) | `/graph` | OAuth2 client credentials (plan-gated) | `{"value": [...]}` (OData)             |

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
cp .env.example .env   # VITE_* mock credentials, inlined at build time
npm install && npm run dev
```

`./start.sh` and the Docker build create `frontend/.env` from `.env.example`
automatically; only the manual path above needs the copy. Without it every
vendor client in the UI authenticates as `undefined`.

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

OAuth2 client credentials flow. POST to `/mde/oauth2/v2.0/token` with `client_id`, `client_secret`, and `grant_type=client_credentials`. The tenant-scoped URL real Entra uses — `/mde/{tenant}/oauth2/v2.0/token`, with tenant `a1b2c3d4-e5f6-7890-abcd-ef1234567890` or the verified domain `acmecorp.onmicrosoft.com` — is accepted too, so MSAL-shaped clients work unchanged. The same applies to `/graph` and `/sentinel`; see the [Graph integration guide](docs/graph-integration-guide.md) for tenant validation and `MOCKDR_STRICT_TENANT`.

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

Both Cortex XDR authentication levels are supported.

**Standard** — send the key itself: `x-xdr-auth-id` and `Authorization: <secret>`.

**Advanced** — the key never leaves the client; send `x-xdr-auth-id`, `x-xdr-nonce`, `x-xdr-timestamp` and `Authorization`, the latter being `SHA256(key + nonce + timestamp)` over the plain concatenation (no delimiter).

| Role    | API Key ID | Secret               |
| ------- | ---------- | -------------------- |
| Admin   | `1`        | `xdr-admin-secret`   |
| Analyst | `2`        | `xdr-analyst-secret` |
| Viewer  | `3`        | `xdr-viewer-secret`  |

```bash
# Standard auth — the key goes in the Authorization header
curl -X POST http://localhost:8001/xdr/public_api/v1/incidents/get_incidents/ \
  -H "x-xdr-auth-id: 1" \
  -H "Authorization: xdr-admin-secret" \
  -H "Content-Type: application/json" \
  -d '{"request_data": {}}'

# Advanced auth — hash key + nonce + timestamp instead
NONCE=$(python3 -c "import secrets; print(secrets.token_hex(32))")
TIMESTAMP=$(date +%s%3N)
AUTH=$(python3 -c "import hashlib,sys; print(hashlib.sha256(''.join(sys.argv[1:]).encode()).hexdigest())" \
  "xdr-admin-secret" "$NONCE" "$TIMESTAMP")

curl -X POST http://localhost:8001/xdr/public_api/v1/incidents/get_incidents/ \
  -H "x-xdr-auth-id: 1" \
  -H "x-xdr-nonce: $NONCE" \
  -H "x-xdr-timestamp: $TIMESTAMP" \
  -H "Authorization: $AUTH" \
  -H "Content-Type: application/json" \
  -d '{"request_data": {}}'
```

### Splunk SIEM

Supports **Basic Auth**, a **session key** from login (`Authorization: Splunk <key>`, or `Bearer <key>` in the JWT scheme), and **HEC Tokens** (`Authorization: Splunk <token>`) for HTTP Event Collector endpoints.

Like splunkd, responses are Atom XML unless you ask for JSON with `output_mode=json` — the Splunk SDKs always do. HEC is exempt and always answers JSON.

**Basic Auth users:**

| Role    | Username  | Password         |
| ------- | --------- | ---------------- |
| Admin   | `admin`   | `mockdr-admin`   |
| Analyst | `analyst` | `mockdr-analyst` |
| Viewer  | `viewer`  | `mockdr-viewer`  |

```bash
# Get session key (output_mode=json — the bare call returns XML, as splunkd does)
SESSION=$(curl -s -X POST "http://localhost:8001/splunk/services/auth/login?output_mode=json" \
  -d "username=admin&password=mockdr-admin" | jq -r .sessionKey)

# Use session key
curl -H "Authorization: Splunk $SESSION" \
  "http://localhost:8001/splunk/services/server/info?output_mode=json"
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

Management-plane requests require `?api-version=`, exactly as Azure Resource Manager does — a request without it is answered with `400 MissingApiVersionParameter`. The Log Analytics query endpoint (`/sentinel/v1/workspaces/...`) is not ARM and takes no api-version.

```bash
TOKEN=$(curl -s -X POST http://localhost:8001/sentinel/oauth2/v2.0/token \
  -d "client_id=sentinel-mock-client-id&client_secret=sentinel-mock-client-secret" \
  | jq -r .access_token)

WS=/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/mockdr-rg
WS=$WS/providers/Microsoft.OperationalInsights/workspaces/mockdr-workspace
WS=$WS/providers/Microsoft.SecurityInsights

curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8001/sentinel$WS/incidents?api-version=2024-03-01"
```

### Microsoft Graph API

OAuth2 client credentials flow with **plan-based feature gating**. POST to `/graph/oauth2/v2.0/token` with `client_id`, `client_secret`, and `grant_type=client_credentials`.

| Role | Client ID | Client Secret | Plan |
|---|---|---|---|
| Global Admin | `graph-mock-admin-client` | `graph-mock-admin-secret` | Plan 2 (E5) |
| Security Admin | `graph-mock-security-client` | `graph-mock-security-secret` | Plan 2 (E5) |
| SMB Admin | `graph-mock-smb-client` | `graph-mock-smb-secret` | Defender for Business |
| Plan 1 User | `graph-mock-p1-client` | `graph-mock-p1-secret` | Plan 1 (E3) |
| Intune Admin | `graph-mock-intune-client` | `graph-mock-intune-secret` | Plan 2 (Intune) |
| Mail Only | `graph-mock-mail-client` | `graph-mock-mail-secret` | None (E3) |

```bash
TOKEN=$(curl -s -X POST http://localhost:8001/graph/oauth2/v2.0/token \
  -d "client_id=graph-mock-admin-client&client_secret=graph-mock-admin-secret&grant_type=client_credentials&scope=https://graph.microsoft.com/.default" \
  | jq -r .access_token)

# Entra ID users
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8001/graph/v1.0/users?\$select=displayName,userPrincipalName,department"

# Intune managed devices
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8001/graph/v1.0/deviceManagement/managedDevices

# Plan gating: Plan 1 gets 403 on advanced hunting
P1_TOKEN=$(curl -s -X POST http://localhost:8001/graph/oauth2/v2.0/token \
  -d "client_id=graph-mock-p1-client&client_secret=graph-mock-p1-secret&grant_type=client_credentials" \
  | jq -r .access_token)
curl -X POST -H "Authorization: Bearer $P1_TOKEN" -H "Content-Type: application/json" \
  -d '{"Query":"DeviceProcessEvents | take 5"}' \
  http://localhost:8001/graph/v1.0/security/runHuntingQuery
# → 403 Forbidden
```

**Plan Comparison:**

| Feature | Plan 1 | Plan 2 | Defender for Business |
|---|---|---|---|
| Users, Groups, CA Policies | ✅ | ✅ | ✅ |
| Mail, Files, Teams | ✅ | ✅ | ✅ |
| Security Alerts & Incidents | ❌ | ✅ | ✅ |
| Advanced Hunting | ❌ | ✅ | ❌ |
| Identity Protection (Risky Users) | ❌ | ✅ | ❌ |
| Intune Device Management | ❌ | ✅ | ✅ |
| Attack Simulation | ❌ | ✅ | ❌ |

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
| IOCs        | CRUD (custom indicators)                                     |
| Host Groups | CRUD + member management                                     |
| Users       | Query ids, get by ids (`POST …/users/GET/v1`)                |
| Processes   | Process detail lookup                                        |
| Quarantine  | Query ids, get by ids (`POST …/GET/v1`), actions             |
| Cases       | Query ids, add/remove tags (the documented routes)           |

### Microsoft Defender for Endpoint (prefix: `/mde`)

| Domain           | Endpoints                                           |
| ---------------- | --------------------------------------------------- |
| Auth             | `POST /oauth2/v2.0/token` (client credentials flow) |
| Machines         | List, get, actions (isolate, unisolate, scan, more) |
| Alerts           | List, get, update, create                           |
| Indicators       | List, create, delete, batch delete                  |
| Machine Actions  | List, get, submit actions                           |
| Investigations   | List, get, start                                    |
| Advanced Hunting | Run KQL queries — evaluated, not canned              |
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
| Auth            | Standard API key or advanced SHA-256 digest (`x-xdr-auth-id`) |
| Incidents       | List, get, update, extra data                                |
| Alerts          | List by filter, original alerts, insert (parsed, CEF)        |
| Endpoints       | List, get, isolate, unisolate, scan, policy                  |
| Scripts         | List, get, execute, execution status/results                 |
| IOCs            | Insert (`tim_insert_jsons`)                                  |
| Actions         | Action center — list, get, status                            |
| Hash Exceptions | Allowlist/blocklist add, remove                              |
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

Commands run in the order you write them, so `| head 1 | sort _time` and `| sort _time | head 1` differ as they do in Splunk.

| Command        | Example                                                           | Description                                       |
| -------------- | ----------------------------------------------------------------- | ------------------------------------------------- |
| `search`       | `search index=sentinelone NOT sourcetype=stash`                   | Filter by index, sourcetype, host, field=value; supports `AND`/`OR`/`NOT`, parentheses and `*` wildcards |
| `where`        | `where severity="critical" AND count > 5`                         | Real comparison operators, not just equality      |
| `eval`         | `eval risk=severity*10, tier=if(risk>50,"high","low")`            | Arithmetic, `.` concatenation, `if`/`case`/`coalesce`/`upper` and friends |
| `stats`        | `stats count, avg(risk) as mean by classification`                | `count`/`sum`/`avg`/`min`/`max`/`dc`/`values`/`list`/`median`, with aliases |
| `timechart`    | `timechart span=1h count by sourcetype`                           | Bucket over time                                  |
| `top` / `rare` | `top 5 sourcetype`                                                | Ranked tables with `count` and `percent`          |
| `dedup`        | `dedup host sourcetype`                                           | First row per distinct key                        |
| `table`        | `table _time host classification`                                 | Project specific fields                           |
| `fields`       | `fields - _raw`                                                   | Include or exclude fields                         |
| `rex`          | `rex field=host "(?<site>^[a-z]+)"`                               | Extract named capture groups                      |
| `regex`        | `regex host="^wkstn"`                                             | Filter by regular expression                      |
| `sort`         | `sort sourcetype, -count`                                         | Several keys; numeric where the values are numbers |
| `head` / `tail`| `head 20`                                                         | First or last N results                           |
| `rename`       | `rename computerName as hostname`                                 | Rename fields                                     |
| `fillnull`     | `fillnull value=0 count`                                          | Replace empty values                              |

Time modifiers (`earliest=-24h@h latest=now`) and the `` `notable` `` macro are also supported. A command the engine does not implement is reported in the job's `messages` rather than silently ignored, so a query that cannot run does not look like one that returned nothing.

```bash
# Run a one-shot search
curl -u admin:mockdr-admin -X POST \
  "http://localhost:8001/splunk/services/search/jobs/export" \
  -d 'search=search index=sentinelone sourcetype=sentinelone:channel:threats | stats count by classification | sort -count' \
  -d 'output_mode=json'
```

#### Advanced Hunting (KQL)

`POST /mde/api/advancedqueries/run` evaluates the query against tables projected from the same seeded data the REST endpoints serve, so a hunting result cannot contradict `/api/machines` or `/api/alerts`.

Tables: `DeviceInfo`, `AlertInfo`, `AlertEvidence`, `DeviceTvmSoftwareInventory`, `DeviceTvmSoftwareVulnerabilities`.

Operators: `where`, `project`, `project-away`, `extend`, `summarize ... by`, `order by`, `take`/`limit`, `top`, `distinct`, `count` — with `==`, `!=`, `<`, `>`, `contains`, `startswith`, `endswith`, `has`, `in`, `matches regex`, combined with `and`/`or`/`not`.

```bash
curl -H "Authorization: Bearer $TOKEN" -X POST \
  "http://localhost:8001/mde/api/advancedqueries/run" \
  -d '{"Query":"DeviceInfo | where OSPlatform == \"Windows10\" | summarize Devices=count() by HealthStatus | order by Devices desc"}'
```

A query naming a table that does not exist, or an operator the engine does not implement, is answered with `400` rather than rows that were never asked for.

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

### Microsoft Graph API (prefix: `/graph`)

| Domain              | Endpoints                                                        |
| ------------------- | ---------------------------------------------------------------- |
| Auth                | `POST /oauth2/v2.0/token` (Azure AD, plan-gated)                |
| Organization        | Get tenant info                                                  |
| Users               | List, get, memberOf, mail rules (v1.0 + beta)                   |
| Groups              | List, get, members                                               |
| Directory Roles     | List, get members                                                |
| Auth Methods        | User registration details (MFA status)                           |
| Service Principals  | List with OData                                                  |
| Applications        | List with OData                                                  |
| Conditional Access  | Policies, named locations, admin units                           |
| Licenses            | subscribedSkus                                                   |
| Sign-In Logs        | List with $filter                                                |
| Audit Logs          | List with $filter                                                |
| Identity Protection | Risky users, risk detections (plan-gated)                        |
| Managed Devices     | List, get, $count, device actions (wipe, retire, sync, scan ...) |
| Detected Apps       | List, get devices per app                                        |
| Compliance          | Policies, device configurations                                  |
| Autopilot           | Devices, deployment profiles                                     |
| App Management      | MAM policies, mobile apps                                        |
| Update Rings        | Windows Update for Business configurations                       |
| Enrollment          | Restrictions, device categories                                  |
| Security Alerts v2  | List, get, patch                                                 |
| Incidents           | List, get with $expand=alerts                                    |
| Advanced Hunting    | Run KQL queries (plan-gated)                                     |
| Secure Scores       | List daily snapshots                                             |
| TI Indicators       | List, create, delete                                             |
| Mail                | Messages, folders, send mail                                     |
| Files               | OneDrive drives/items, SharePoint sites                          |
| Teams               | Teams, channels, messages                                        |
| Attack Simulation   | List simulations (plan-gated)                                    |
| Threat Assessment   | List, create                                                     |
| Service Health      | Health overviews                                                 |

## Seed Data

Deterministic seed (`random.seed(42)` + `Faker.seed(42)`) -- same data every cold start. Reset at any time via the DEV panel or `POST /_dev/reset`.

### SentinelOne

- 1 account, 3 sites, 9 groups
- **60 agents** -- Windows/macOS/Linux; desktop/laptop/server; online/offline; tagged; ~18% running EOL operating systems (Windows 8.1, Windows 10 1809, macOS Big Sur, CentOS 7)
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
| `msdefender`       | MDE alerts, machines                 | `ms:defender:atp:alerts`, `ms:defender:machines`                                |
| `elastic_security` | Elastic alerts, endpoints            | `elastic:security:alerts`, `elastic:security:endpoints`                                       |
| `cortex_xdr`       | XDR incidents, alerts, endpoints     | `pan:xdr:incident`, `pan:xdr:alert`, `pan:xdr:endpoint`                                    |
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

### Microsoft Graph API

- **28 Entra users** — 25 employees (mapped from MDE machine loggedOnUsers + Faker), 3 external guests (B2B contractors/partners); ~72% active, ~8% stale (enabled but no sign-in for 90+ days), ~20% disabled (former employees)
- **10 groups** (6 department, 1 M365, 1 Security, 2 dynamic)
- **8 directory roles** with real roleTemplateIds — 5 Global Admins (CIS violation: max 4), disabled users in privileged roles
- **25 MFA registration details** (~80% MFA registered); Security Administrator without MFA
- **4 mail forwarding rules** — former employee forwarding to `competitor.com` and `external-consulting.com`; active employee forwarding invoices to personal `gmail.com`
- **8 service principals** — 2 unverified apps with `Files.ReadWrite.All` scope
- **6 conditional access policies** (1 in report-only mode), 3 named locations, 2 admin units
- **5 license SKUs** — Intune P1 at 96% consumed (near-exhaustion warning)
- **200 sign-in logs** (30 days: ~70% success, ~15% MFA, ~10% failed, ~5% blocked by CA)
- **100 audit logs** (user/group/policy management activities)
- **5 risky users** (2 high, 2 medium, 1 dismissed) + **15 risk detections** (6 event types)
- **66 managed devices** — 60 mirrored from S1 fleet (same EOL OS visible across all vendors) + 6 mobile devices (3 company iOS/Android, 3 personal BYOD noncompliant)
- **30 detected apps** with device mappings
- **5 compliance policies**, 4 device configurations, 20 Autopilot devices, 3 profiles
- **4 MAM policies**, 12 mobile apps, 3 update rings
- **40 security alerts** (mapped from MDE), **15 incidents** (grouped), **30 secure scores**, **20 TI indicators**
- **75 mail messages**, 25 folders, 5 OneDrive drives, 40 drive items, 2 SharePoint sites
- **4 teams**, 10 channels, 25 channel messages
- **3 attack simulations**, 5 threat assessments, 6 service health entries

**Compliance violations baked into seed data:** former employees with admin roles and external mail forwarding, app tokens not revoked after offboarding, too many Global Admins, admin without MFA, stale accounts, unverified apps with broad permissions, EOL operating systems, BYOD devices, CA policies in report-only mode, license near-exhaustion. See [Graph Integration Guide](docs/graph-integration-guide.md) for the full findings table.

All data is **in-memory** by default -- mutations survive until server restart or `/_dev/reset`.

**Optional persistence:** set `MOCKDR_PERSIST=/path/to/state.json` to save state across restarts. The server debounces writes (2 s) and uses atomic file replacement to prevent corruption.

## Configuration

| Variable             | Default                                       | Description                                                                                        |
| -------------------- | --------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `SEED_COUNT_AGENTS`  | 60                                            | S1 agents to seed (CS/MDE/Elastic/XDR/Graph mirror this count; Splunk/Sentinel replay from all EDR data) |
| `SEED_COUNT_THREATS` | 30                                            | S1 threats to seed                                                                                 |
| `SEED_COUNT_ALERTS`  | 20                                            | S1 alerts to seed                                                                                  |
| `MOCKDR_PERSIST`     | (none)                                        | File path for JSON state persistence across restarts                                               |
| `CORS_ORIGINS`       | `http://localhost:3000,http://localhost:8001,http://localhost:5001` | Comma-separated allowed CORS origins                                                               |
| `MOCKDR_STRICT_TENANT` | `true`                                      | Require the tenant in an Entra token URL (`/{tenant}/oauth2/v2.0/token`) to match the mock tenant; set `false` to accept any tenant |
| `MOCKDR_SPLUNK_DISPATCH_SECONDS` | `0`                             | How long a Splunk search job takes to reach `DONE`. `0` completes immediately and keeps responses deterministic; set e.g. `5` to make `QUEUED` → `PARSING` → `RUNNING` → `FINALIZING` observable, so a client's `isDone` polling loop is actually exercised |
| `MOCKDR_SPLUNK_HEC_QUERY_STRING_AUTH` | `false`                 | Whether HEC honours its token as `?token=`, mirroring `inputs.conf`'s `allowQueryStringAuth`. Off by default because that is splunkd's default: a valid token sent this way is refused with `400 {"code": 16}` until the setting is on |
| `MOCKDR_MAX_BODY_BYTES` | `16777216` (16 MiB)                        | Largest request body accepted; a larger one answers `413` before any byte is read, as a reverse proxy in front of the real products would |
| `SPLUNK_SESSION_TTL_SECONDS` | `28800`                               | Lifetime of a Splunk session key from `/services/auth/login` |
| `ES_ADMIN_PASSWORD`, `ES_ANALYST_PASSWORD`, `ES_VIEWER_PASSWORD` | `mock-elastic-password`, `mock-analyst-password`, `mock-viewer-password` | Passwords of the three Elasticsearch users; the only credentials that can be changed without editing a seeder |

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
| Recording Proxy  | Record/replay real vendor API calls (all 8 vendors)          |

## DEV Mock Controls

Floating bug icon (bottom-right corner of the UI):

| Control              | Description                                               |
| -------------------- | --------------------------------------------------------- |
| Live stats           | Agent / threat / alert counts                             |
| Role switcher        | Switch between the three preset tokens                    |
| Mass Infection       | Infect 20 random agents                                   |
| APT Campaign         | Targeted attack on 10 agents                              |
| Agents Offline       | Take 30% of agents offline                                |
| Quiet Day            | Resolve all threats, heal all agents                      |
| Compliance Drift     | Mark ~30% of Graph managed devices non-compliant          |
| MFA Gap              | Disable MFA for ~40% of Graph users                       |
| Risky Sign-In Wave   | Generate 20 risky sign-in log entries in Graph            |
| License Exhaustion   | Exhaust all Graph license SKUs                            |
| Reset to Seed Data   | Wipe mutations, restore original seed                     |
| API Tokens           | Copy any preset token to clipboard                        |

## DEV Endpoints

Non-standard endpoints for tooling, test automation, and mock control:

| Endpoint                        | Description                                                                         |
| ------------------------------- | ----------------------------------------------------------------------------------- |
| `POST /_dev/reset`              | Re-seed all data (all eight vendors)                                                |
| `POST /_dev/scenario`           | Trigger a scenario (see [Scenarios](#scenarios) below)                              |
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
| `GET /_dev/proxy/config`        | Get recording proxy mode and per-vendor settings (secrets masked)                   |
| `POST /_dev/proxy/config`       | Set proxy mode and per-vendor upstream connections                                  |
| `GET /_dev/proxy/recordings`    | List all recorded exchanges (newest first)                                          |
| `DELETE /_dev/proxy/recordings` | Clear all recordings                                                                |
| `GET /_dev/proxy/vendors`       | List supported vendor keys, labels, and default auth types                          |

### Scenarios

`POST /_dev/scenario` with `{"scenario": "<name>"}`:

| Scenario | Vendor | Description |
|---|---|---|
| `mass_infection` | SentinelOne | Infect 20 random agents with threats |
| `apt_campaign` | SentinelOne | Targeted attack: compromise 10 agents |
| `agent_offline` | SentinelOne | Disconnect ~33% of agents |
| `quiet_day` | SentinelOne | Resolve all threats, heal all agents |
| `compliance_drift` | Microsoft Graph | Mark ~30% of managed devices non-compliant |
| `mfa_gap` | Microsoft Graph | Disable MFA for ~40% of users |
| `risky_signin_wave` | Microsoft Graph | Generate 20 risky sign-in log entries |
| `license_exhaustion` | Microsoft Graph | Exhaust all license SKUs |

## Recording Proxy

mockdr includes a built-in **recording proxy** that can forward requests to real vendor APIs, record the exchanges, and replay them later. This is useful for:

- Capturing real API responses to validate mock fidelity
- Building deterministic regression test fixtures from real data
- Offline testing against recorded real-world responses

### Supported Vendors

The proxy supports **all eight vendors** with vendor-appropriate authentication:

| Vendor | Auth Method | Example Base URL |
|---|---|---|
| SentinelOne | `ApiToken` header | `https://tenant.sentinelone.net` |
| CrowdStrike Falcon | OAuth2 client credentials | `https://api.crowdstrike.com` |
| Microsoft Defender | OAuth2 client credentials | `https://api.securitycenter.microsoft.com` |
| Elastic Security | Basic Auth / API Key | `https://elastic.example.com:9200` |
| Cortex XDR | API key (key ID + secret) | `https://api-tenant.xdr.paloaltonetworks.com` |
| Splunk SIEM | Basic Auth / Bearer | `https://splunk.example.com:8089` |
| Microsoft Sentinel | OAuth2 client credentials | `https://management.azure.com` |
| Microsoft Graph | OAuth2 client credentials | `https://graph.microsoft.com` |

### Three Modes

| Mode | Behavior |
|---|---|
| `off` (default) | No-op -- all requests served by mock |
| `record` | Forward to real vendor API, save the exchange, return the real response |
| `replay` | Serve from saved recordings (matched by vendor + method + path); fall back to mock if no match |

Dev paths (`/_dev/*`) always bypass the proxy.

### Configuration

Configure via the UI (Recording Proxy page) or the API:

```bash
# Configure CrowdStrike proxy
curl -X POST http://localhost:8001/web/api/v2.1/_dev/proxy/config \
  -H "Authorization: ApiToken admin-token-0000-0000-000000000001" \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "record",
    "vendors": [
      {
        "vendor": "crowdstrike",
        "base_url": "https://api.crowdstrike.com",
        "auth": {
          "type": "oauth2",
          "client_id": "YOUR_CLIENT_ID",
          "client_secret": "YOUR_CLIENT_SECRET",
          "token_url": "https://api.crowdstrike.com/oauth2/token"
        }
      },
      {
        "vendor": "s1",
        "base_url": "https://tenant.sentinelone.net",
        "auth": {
          "type": "api_token",
          "token": "YOUR_S1_TOKEN"
        }
      }
    ]
  }'

# Switch to replay mode
curl -X POST http://localhost:8001/web/api/v2.1/_dev/proxy/config \
  -H "Authorization: ApiToken admin-token-0000-0000-000000000001" \
  -H "Content-Type: application/json" \
  -d '{"mode": "replay"}'
```

Multiple vendors can be configured simultaneously -- each vendor's requests are routed independently based on URL prefix. Vendors without a configured `base_url` fall through to the mock.

### Persistence

- **Proxy config** (vendor connections) is included in the `MOCKDR_PERSIST` snapshot and survives restarts.
- **Proxy config** survives `/_dev/reset` (only mock data is re-seeded, not proxy settings).
- **Recordings** are in-memory only (max 1,000, circular buffer). Export via `GET /_dev/proxy/recordings` to persist externally.
- **OAuth2 token cache** is in-memory only -- tokens are short-lived and re-fetched as needed.

## Architecture

```
backend/
├── domain/                    # Pure dataclasses — field names match each vendor's API
│   ├── cs_*.py                # CrowdStrike domain models (host, detection, incident, ...)
│   ├── mde_*.py               # MDE domain models (machine, alert, indicator, ...)
│   ├── es_*.py                # Elastic domain models (endpoint, rule, alert, ...)
│   ├── xdr_*.py               # Cortex XDR domain models (incident, alert, endpoint, ...)
│   ├── graph/                 # Microsoft Graph models (30 files: user, device, alert, ...)
│   ├── sentinel/              # Microsoft Sentinel domain models
│   └── splunk/                # Splunk SIEM domain models
├── repository/                # Generic Repository[T] + thread-safe InMemoryStore
│   ├── store.py               # Thread-safe in-memory store (RLock, named collections)
│   ├── base.py                # Repository[T] generic base class
│   ├── *_repo.py              # S1, CS, MDE, Elastic, XDR per-domain repos
│   ├── graph/                 # Graph repositories (30 files)
│   ├── sentinel/              # Sentinel repositories
│   └── splunk/                # Splunk repositories
├── application/               # CQRS layer — one module per domain
│   ├── agents/                # S1 agents: queries.py + commands.py
│   ├── threats/               # S1 threats: queries.py + commands.py
│   ├── cs_*/                  # CrowdStrike modules (hosts, detections, incidents, ...)
│   ├── mde_*/                 # MDE modules (machines, alerts, indicators, hunting, ...)
│   ├── es_*/                  # Elastic modules (search, rules, alerts, cases, ...)
│   ├── xdr_*/                 # Cortex XDR modules (incidents, alerts, endpoints, xql, ...)
│   ├── graph/                 # Graph modules (20 submodules: users, devices, security, ...)
│   │   ├── users/             #   queries.py — Entra ID user queries
│   │   ├── device_management/ #   queries.py — Intune device queries
│   │   ├── security/          #   queries.py — alerts, incidents, hunting, scores, TI
│   │   ├── mail/              #   queries.py — messages, folders, send
│   │   └── ...                #   + groups, identity, files, teams, etc.
│   ├── sentinel/              # Sentinel application logic
│   ├── splunk/                # Splunk application logic
│   └── playbook/              # SOAR-like playbook engine
├── api/
│   ├── auth.py                # S1 ApiToken auth
│   ├── cs_auth.py             # CrowdStrike OAuth2 Bearer auth
│   ├── mde_auth.py            # MDE OAuth2 Bearer auth
│   ├── es_auth.py             # Elastic Basic Auth + API Key auth
│   ├── xdr_auth.py            # Cortex XDR API key auth
│   ├── splunk_auth.py         # Splunk Basic Auth + Bearer + HEC auth
│   ├── sentinel_auth.py       # Sentinel Azure AD OAuth2 auth
│   ├── graph_auth.py          # Graph Azure AD OAuth2 auth (plan-gated)
│   ├── dto/                   # Pydantic request models (HTTP boundary only)
│   ├── middleware/             # 8 ASGI middleware classes
│   └── routers/               # Thin FastAPI routers — one file per domain per vendor
│       ├── cs_*.py            # CrowdStrike routers (13 modules)
│       ├── mde_*.py           # MDE routers (11 modules)
│       ├── es_*.py            # Elastic routers (7 modules)
│       ├── xdr_*.py           # Cortex XDR routers (11 modules)
│       ├── graph/             # Microsoft Graph routers (24 modules)
│       ├── splunk/            # Splunk SIEM routers (10 modules)
│       └── sentinel/          # Microsoft Sentinel routers (9 modules)
├── utils/
│   ├── mde_odata.py           # OData v4 $filter parser (MDE)
│   ├── graph_odata.py         # Graph OData extensions ($count, $search, lambda)
│   ├── cs_fql.py              # CrowdStrike FQL parser
│   ├── graph_response.py      # Graph OData response envelope builder
│   └── ...                    # pagination, filtering, field stripping, etc.
└── infrastructure/
    ├── seed.py                # Orchestrator — calls per-domain seeders for all 8 vendors
    └── seeders/               # Per-domain Faker-based deterministic data generators (seed 42)
        ├── agents.py          # S1 agent seeder (base fleet: 60 agents)
        ├── cs_*.py            # CrowdStrike seeders (hosts mirrored from S1 fleet)
        ├── mde_*.py           # MDE seeders (machines mirrored from S1 fleet)
        ├── graph/             # Graph seeders (28 files: users, devices, security, mail, ...)
        ├── splunk/            # Splunk infrastructure + EDR event replay seeders
        └── sentinel/          # Sentinel infrastructure + incident correlation seeders

frontend/                      # Vue 3 + TypeScript — vue-tsc strict, ESLint zero-warnings
└── src/
    ├── api/                   # Axios client + typed domain API modules (14 modules)
    │   ├── crowdstrike.ts     # CrowdStrike API client
    │   ├── defender.ts        # MDE API client
    │   ├── elastic.ts         # Elastic Security API client
    │   ├── graph.ts           # Microsoft Graph API client (plan-aware, 10 namespaces)
    │   ├── sentinel.ts        # Sentinel API client
    │   ├── splunk.ts          # Splunk API client
    │   └── ...                # + S1, cortex, dev, system, agents, threats, alerts, tags
    ├── stores/                # Pinia stores
    ├── types/                 # Shared interfaces mirroring each vendor API
    │   ├── index.ts           # S1 + shared types
    │   └── graph.ts           # Microsoft Graph types (25+ interfaces)
    ├── components/            # Shared UI + DevMockPanel (scenarios, role switcher)
    └── views/                 # One view per UI page
        ├── cs/                # CrowdStrike views (5)
        ├── elastic/           # Elastic Security views (6)
        ├── graph/             # Microsoft Graph views (9: dashboard, users, devices, ...)
        ├── mde/               # Microsoft Defender views (6)
        ├── xdr/               # Cortex XDR views (6)
        ├── splunk/            # Splunk SIEM views (6)
        └── sentinel/          # Microsoft Sentinel views (6)
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

The action starts the server, waits for it to be healthy, and exposes `base-url` and `api-token` outputs. All eight vendor mocks are available on the same port.

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
 
mockdr is source-available under the **[Business Source License 1.1](LICENSE.md)**.
 
| Use case | License required? |
|---|---|
| Personal use, learning, hobby projects | ✅ Free |
| Evaluation / proof of concept (30 days) | ✅ Free |
| Open-source projects (OSI-approved license) | ✅ Free |
| Non-profit / educational internal use | ✅ Free |
| **Commercial use by for-profit companies** | **💼 Commercial license** |
| **Embedding in commercial products** | **💼 Commercial license** |
| **Offering as a hosted / managed service** | **💼 Commercial license** |
 
Each release converts to **Apache 2.0** four years after publication.
 
See [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md) for plans, pricing,
and FAQ — or contact **licensing@mockdr.io**.


Copyright (c) 2026 Guenter Weber. All rights reserved.
