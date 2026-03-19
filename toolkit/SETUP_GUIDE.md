# mockdr — Setup Guide

## Prerequisites

**Option A — Local (recommended for development)**
- Python 3.11+ (3.12 preferred)
- Node.js 18+ (for the management UI — optional)

**Option B — Docker**
- Docker 20+

---

## Quick Start (Local)

```bash
# From the project root:
./start.sh
```

This creates a Python venv, installs backend dependencies, installs frontend
dependencies, then starts both services:

| Service              | URL                                          |
|----------------------|----------------------------------------------|
| SentinelOne API      | http://localhost:8001/web/api/v2.1            |
| CrowdStrike API      | http://localhost:8001/ (e.g. `/oauth2/token`) |
| MDE API              | http://localhost:8001/ (e.g. `/api/machines`) |
| Elastic REST         | http://localhost:8001/elastic/               |
| Kibana Security      | http://localhost:8001/kibana/                |
| Cortex XDR API       | http://localhost:8001/xdr/public_api/v1      |
| Swagger              | http://localhost:8001/web/api/v2.1/doc        |
| Frontend             | http://localhost:3000                         |

Press `Ctrl+C` to stop both.

**Backend only** (no UI needed for integration testing):

```bash
cd backend
source .venv/bin/activate   # or: python3 -m venv .venv && pip install -r requirements.txt
PYTHONPATH=. uvicorn main:app --host 0.0.0.0 --port 8001 --reload
```

## Quick Start (Docker)

```bash
docker build -t mockdr .
docker run -p 8001:5001 mockdr
```

All vendor APIs are available from the same port.

---

## SentinelOne Setup

### Authentication

Header format:
```
Authorization: ApiToken <token>
```

### Available Test Tokens

All tokens are pre-seeded on startup. RBAC is enforced.

| Role         | Token                                      | Permissions            |
|--------------|--------------------------------------------|------------------------|
| **Admin**    | `admin-token-0000-0000-000000000001`       | Full read + write + admin |
| **Viewer**   | `viewer-token-0000-0000-000000000002`      | Read-only              |
| **SOC Analyst** | `soc-analyst-token-000-000000000003`    | Read + write (no admin) |

**RBAC behaviour:**
- GET endpoints accept any authenticated token.
- POST/PUT/DELETE (write) endpoints require Admin or SOC Analyst.
- Admin-only endpoints (sites CRUD, user management, `/_dev/*`) require the Admin token.
- Viewer token returns 403 on any mutation.

### Example curl

```bash
# List agents
curl http://localhost:8001/web/api/v2.1/agents \
  -H "Authorization: ApiToken admin-token-0000-0000-000000000001"

# Get system status (no auth required)
curl http://localhost:8001/web/api/v2.1/system/status
```

---

## CrowdStrike Falcon Setup

### Authentication

CrowdStrike uses OAuth2 client credentials. First obtain a Bearer token, then use it on all subsequent requests.

### Available Test Credentials

| Role         | Client ID                  | Client Secret              |
|--------------|----------------------------|----------------------------|
| **Admin**    | `cs-mock-admin-client`     | `cs-mock-admin-secret`     |
| **Viewer**   | `cs-mock-viewer-client`    | `cs-mock-viewer-secret`    |
| **Analyst**  | `cs-mock-analyst-client`   | `cs-mock-analyst-secret`   |

Token TTL: 1799 seconds (matches real CrowdStrike).

### Example curl

```bash
# Obtain a Bearer token
TOKEN=$(curl -s -X POST http://localhost:8001/oauth2/token \
  -d "client_id=cs-mock-admin-client&client_secret=cs-mock-admin-secret" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# List host IDs
curl http://localhost:8001/devices/queries/devices/v1 \
  -H "Authorization: Bearer $TOKEN"

# Get host details
curl "http://localhost:8001/devices/entities/devices/v2?ids=<host-id>" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Microsoft Defender for Endpoint Setup

### Authentication

MDE uses Azure AD-style OAuth2 client credentials. First obtain a Bearer token, then use it on all subsequent requests.

### Available Test Credentials

| Role         | Client ID                   | Client Secret                |
|--------------|-----------------------------|------------------------------|
| **Admin**    | `mde-mock-admin-client`     | `mde-mock-admin-secret`      |
| **Analyst**  | `mde-mock-analyst-client`   | `mde-mock-analyst-secret`    |
| **Viewer**   | `mde-mock-viewer-client`    | `mde-mock-viewer-secret`     |

Token TTL: 3599 seconds (matches real Azure AD).

### Example curl

```bash
# Obtain a Bearer token
TOKEN=$(curl -s -X POST http://localhost:8001/oauth2/v2.0/token \
  -d "client_id=mde-mock-admin-client&client_secret=mde-mock-admin-secret&grant_type=client_credentials" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# List machines
curl http://localhost:8001/api/machines \
  -H "Authorization: Bearer $TOKEN"

# List machines with OData filter
curl "http://localhost:8001/api/machines?\$filter=osPlatform%20eq%20'Windows10'" \
  -H "Authorization: Bearer $TOKEN"

# List alerts
curl http://localhost:8001/api/alerts \
  -H "Authorization: Bearer $TOKEN"
```

---

## Elastic Security Setup

### Authentication

Elastic Security supports two authentication mechanisms:

- **Basic Auth**: `Authorization: Basic base64(user:pass)`
- **API Key Auth**: `Authorization: ApiKey base64(id:key)`

Kibana endpoints also require `kbn-xsrf: true` header on non-GET requests.

### Available Test Credentials

| Role         | Username    | Password                  |
|--------------|-------------|---------------------------|
| **Admin**    | `elastic`   | `mock-elastic-password`   |
| **Analyst**  | `analyst`   | `mock-analyst-password`   |
| **Viewer**   | `viewer`    | `mock-viewer-password`    |

### Example curl — Elasticsearch REST

```bash
# Search endpoints (Basic Auth)
curl http://localhost:8001/elastic/.fleet-agents/_search \
  -u "elastic:mock-elastic-password" \
  -H "Content-Type: application/json" \
  -d '{"query": {"match_all": {}}}'

# Search with query DSL
curl http://localhost:8001/elastic/.fleet-agents/_search \
  -u "elastic:mock-elastic-password" \
  -H "Content-Type: application/json" \
  -d '{"query": {"bool": {"must": [{"term": {"status": "online"}}]}}}'
```

### Example curl — Kibana Security API

```bash
# List detection rules
curl http://localhost:8001/kibana/api/detection_engine/rules/_find \
  -u "elastic:mock-elastic-password"

# List security alerts
curl http://localhost:8001/kibana/api/detection_engine/alerts/_search \
  -u "elastic:mock-elastic-password" \
  -H "Content-Type: application/json" \
  -d '{"query": {"match_all": {}}}'

# Create a case (requires kbn-xsrf header)
curl -X POST http://localhost:8001/kibana/api/cases \
  -u "elastic:mock-elastic-password" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"title": "Test case", "description": "Created via curl", "tags": ["test"]}'
```

---

## Cortex XDR Setup

### Authentication

Cortex XDR uses HMAC-based authentication. Every request requires four headers:

| Header              | Value                                              |
|---------------------|----------------------------------------------------|
| `x-xdr-auth-id`    | API key ID (integer)                               |
| `x-xdr-nonce`      | Random hex string (unique per request)             |
| `x-xdr-timestamp`  | Current epoch time in milliseconds                 |
| `Authorization`     | SHA256 hash of `<api_key_secret><nonce><timestamp>` |

### Available Test Credentials

| Role         | API Key ID | Secret                |
|--------------|------------|-----------------------|
| **Admin**    | `1`        | `xdr-admin-secret`    |
| **Analyst**  | `2`        | `xdr-analyst-secret`  |
| **Viewer**   | `3`        | `xdr-viewer-secret`   |

### Example curl

```bash
# Generate HMAC auth headers
NONCE=$(python3 -c "import secrets; print(secrets.token_hex(32))")
TIMESTAMP=$(python3 -c "import int(time.time()*1000)") # epoch ms
KEY="xdr-admin-secret"
AUTH=$(python3 -c "
import hashlib, sys
key, nonce, ts = sys.argv[1], sys.argv[2], sys.argv[3]
print(hashlib.sha256((key + nonce + ts).encode()).hexdigest())
" "$KEY" "$NONCE" "$TIMESTAMP")

# List incidents
curl -X POST http://localhost:8001/xdr/public_api/v1/incidents/get_incidents \
  -H "x-xdr-auth-id: 1" \
  -H "x-xdr-nonce: $NONCE" \
  -H "x-xdr-timestamp: $TIMESTAMP" \
  -H "Authorization: $AUTH" \
  -H "Content-Type: application/json" \
  -d '{"request_data": {}}'

# Get alerts
curl -X POST http://localhost:8001/xdr/public_api/v1/alerts/get_alerts \
  -H "x-xdr-auth-id: 1" \
  -H "x-xdr-nonce: $NONCE" \
  -H "x-xdr-timestamp: $TIMESTAMP" \
  -H "Authorization: $AUTH" \
  -H "Content-Type: application/json" \
  -d '{"request_data": {}}'
```

### Request / Response format

All XDR endpoints use POST with a JSON body. Requests are wrapped in `request_data`, responses in `reply`:

```json
// Request
{"request_data": {"filters": [{"field": "severity", "operator": "in", "value": ["high"]}]}}

// Response
{"reply": {"total_count": 5, "result_count": 5, "incidents": [...]}}
```

---

## Configuring a SOAR Platform (e.g. Cortex XSOAR, Splunk SOAR)

Point your SOAR integration at the mock server. All four vendor APIs are served from the same host and port.

### Cortex XSOAR — SentinelOne example

1. Go to **Settings > Integrations > Servers & Services**.
2. Search for **SentinelOne v2** and click **Add instance**.
3. Fill in:

| Field              | Value                                          |
|--------------------|------------------------------------------------|
| **Server URL**     | `http://<host>:8001`                           |
| **API Token**      | `admin-token-0000-0000-000000000001`           |
| **API Version**    | `2.1`                                          |
| **Trust any cert** | Checked (mock uses plain HTTP)                 |
| **Use system proxy** | Unchecked (unless your proxy routes to mock) |

4. Click **Test** — it should return "ok" (the integration calls `GET /web/api/v2.1/system/status`).

### Cortex XSOAR — CrowdStrike example

1. Search for **CrowdStrike Falcon** and click **Add instance**.
2. Fill in:

| Field              | Value                                          |
|--------------------|------------------------------------------------|
| **Server URL**     | `http://<host>:8001`                           |
| **Client ID**      | `cs-mock-admin-client`                         |
| **Client Secret**  | `cs-mock-admin-secret`                         |
| **Trust any cert** | Checked                                        |

### Cortex XSOAR — MDE example

1. Search for **Microsoft Defender for Endpoint** and click **Add instance**.
2. Fill in:

| Field              | Value                                          |
|--------------------|------------------------------------------------|
| **Server URL**     | `http://<host>:8001`                           |
| **Client ID**      | `mde-mock-admin-client`                        |
| **Client Secret**  | `mde-mock-admin-secret`                        |
| **Trust any cert** | Checked                                        |

> If your SOAR runs in Docker and the mock runs on the host, use the Docker host
> IP (e.g., `host.docker.internal` on Docker Desktop or `172.17.0.1` on Linux).

---

## Key Differences from the Real Vendor APIs

| Aspect               | Mock behaviour                                              |
|----------------------|-------------------------------------------------------------|
| **Storage**          | In-memory only — all data resets on server restart           |
| **Seed data**        | 60 agents, 30 threats, 20 alerts auto-generated on startup  |
| **Deterministic**    | `random.seed(42)` + `Faker.seed(42)` — same data every run  |
| **`/_dev/` endpoints** | Non-vendor utilities: reset data, trigger scenarios, export/import state, request audit log |
| **Deep Visibility**  | Returns synthetic process/network events; query finishes in ~2 seconds |
| **Webhooks**         | Actually POSTs to subscribed URLs with HMAC signature        |
| **Rate limiting**    | Configurable via `/_dev/rate-limit` (off by default)         |
| **Pagination**       | Cursor-based (S1), offset/limit (CS), OData (MDE), ES standard (Elastic), search_after (XDR) — all matching real vendor formats |
| **Error format**     | Vendor-specific error envelopes preserved per vendor         |

---

## Seed Data Counts (configurable via env vars)

```bash
SEED_COUNT_AGENTS=60    # default
SEED_COUNT_THREATS=30   # default
SEED_COUNT_ALERTS=20    # default
```

Override at startup:
```bash
SEED_COUNT_AGENTS=200 SEED_COUNT_THREATS=100 uvicorn main:app --port 8001
```

---

## Supported Endpoint Domains

### SentinelOne (S1)

- **Agents** — list, get, count, actions (connect/disconnect/decommission/scan/uninstall), passphrase, processes, applications, fetch-files
- **Threats** — list, get, timeline, notes, analyst-verdict, incident, mitigate, mark-as-threat, mark-as-resolved, add-to-blacklist, fetch-file
- **Alerts** (Cloud Detection) — list, get, analyst-verdict, incident
- **Sites** — list, get, create, update, delete, reactivate, expire-now
- **Groups** — list, get, create, update, delete, move-agents
- **Users** — list, get, create, update, delete, bulk-delete, generate-api-token, login-by-token
- **Exclusions** — list, create, delete, bulk-delete
- **Restrictions (Blocklist)** — list, create, delete, bulk-delete
- **Firewall Control** — list, create, update, delete
- **Device Control** — list, create, update, delete
- **Threat Intelligence (IOCs)** — list, create, bulk-create, delete
- **Activities** — list, types
- **Deep Visibility** — init-query, query-status, events, events-by-type, cancel-query
- **Accounts** — list, get, create, update
- **Policies** — get, update
- **Tags** — list (via agents/tags), create, update, delete (via tag-manager)
- **Hashes** — verdict lookup
- **Webhooks** — list, get, create, delete, fire test event
- **System** — status (no auth), info, configuration

### CrowdStrike Falcon (CS)

- **Auth** — OAuth2 token exchange, token revoke
- **Hosts** — query IDs, get entities, host actions
- **Detections** — query IDs, get entities, update status
- **Incidents** — query IDs, get entities, perform actions
- **Host Groups** — query, get, create, update, delete, add/remove members
- **IOCs** — custom IOC CRUD
- **Legacy IOCs** — legacy IOC endpoints
- **Cases** — support case queries
- **Processes** — process detail queries
- **Quarantine** — quarantined file operations
- **Users** — user management

### Microsoft Defender for Endpoint (MDE)

- **Auth** — OAuth2 token exchange (Azure AD style)
- **Machines** — list, get, OData filters
- **Alerts** — list, get, create, update, OData filters
- **Indicators** — list, create, update, delete
- **Machine Actions** — isolate, release, run AV scan, collect investigation package
- **Investigations** — list, get
- **Advanced Hunting** — KQL query execution
- **Software** — software inventory
- **Vulnerabilities** — vulnerability list
- **File Info** — file statistics, related machines
- **Users** — user info, related machines

### Elastic Security (ES)

- **Auth** — Basic Auth, API Key Auth, token exchange
- **Elasticsearch REST** — `_search` with full query DSL (bool, match, term, range, wildcard, exists, query_string)
- **Endpoints** — Fleet agent list via Kibana
- **Detection Rules** — CRUD + enable/disable
- **Alerts** — search, status update
- **Cases** — CRUD + comments
- **Exception Lists** — CRUD + exception items

### Cortex XDR

- **Auth** — HMAC header validation
- **Incidents** — list, get, update, extra data
- **Alerts** — list, get, update, multi-events
- **Endpoints** — list, get, isolate, unisolate, scan, policy
- **Scripts** — list, get, execute, execution status/results
- **IOCs** — CRUD (indicators of compromise)
- **Actions** — action center list, get, status
- **Hash Exceptions** — allowlist/blocklist CRUD
- **Audit** — management + agent audit logs
- **Distributions** — distribution list
- **XQL** — start query, get results, quota
- **System** — server info, health check

---

## Tips for Integration Testing

### 1. Reset between test runs
```bash
curl -X POST http://localhost:8001/web/api/v2.1/_dev/reset \
  -H "Authorization: ApiToken admin-token-0000-0000-000000000001"
```

### 2. Inspect what your SOAR sent
```bash
# View the request audit log
curl http://localhost:8001/web/api/v2.1/_dev/requests \
  -H "Authorization: ApiToken admin-token-0000-0000-000000000001"
```

### 3. Trigger scenarios for testing playbooks
```bash
curl -X POST http://localhost:8001/web/api/v2.1/_dev/scenario \
  -H "Authorization: ApiToken admin-token-0000-0000-000000000001" \
  -H "Content-Type: application/json" \
  -d '{"scenario": "ransomware_outbreak"}'
```

### 4. Export / import snapshots
```bash
# Save current state
curl http://localhost:8001/web/api/v2.1/_dev/export \
  -H "Authorization: ApiToken admin-token-0000-0000-000000000001" > snapshot.json

# Restore it later
curl -X POST http://localhost:8001/web/api/v2.1/_dev/import \
  -H "Authorization: ApiToken admin-token-0000-0000-000000000001" \
  -H "Content-Type: application/json" \
  -d @snapshot.json
```

### 5. Use the Postman collection
Import `postman_collection.json` from this directory. It includes all endpoints
with pre-configured auth and example request bodies. Set the `baseUrl` variable
if your mock runs on a different host/port.

### 6. Simulate rate limiting
```bash
curl -X POST http://localhost:8001/web/api/v2.1/_dev/rate-limit \
  -H "Authorization: ApiToken admin-token-0000-0000-000000000001" \
  -H "Content-Type: application/json" \
  -d '{"enabled": true, "requestsPerMinute": 10}'
```
