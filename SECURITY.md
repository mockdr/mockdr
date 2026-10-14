# Security Policy

## Scope

mockdr is a **mock API server** for testing and development. It is not designed for production use. However, it may be deployed on shared networks or CI environments, so security defaults are hardened accordingly.

## Authentication

### SentinelOne (S1)
- **Mechanism**: `Authorization: ApiToken <token>` header
- **Roles**: Admin, SOC Analyst, Viewer
- **Tokens**: Pre-seeded deterministic tokens (see TESTING.md for values)

### CrowdStrike Falcon
- **Mechanism**: OAuth2 client credentials → Bearer token
- **Token endpoint**: `POST /cs/oauth2/token`
- **Token TTL**: 1799 seconds

### Microsoft Defender for Endpoint
- **Mechanism**: OAuth2 client credentials → Bearer token
- **Token endpoint**: `POST /mde/oauth2/v2.0/token`
- **Token TTL**: 3599 seconds

### Elastic Security
- **Mechanism**: Basic Auth or API Key Auth
- **Bearer tokens**: Supported via `POST /elastic/_security/oauth2/token`

### Cortex XDR
- **Mechanism**: HMAC-SHA256 header-based auth
- **Headers**: `x-xdr-auth-id`, `x-xdr-nonce`, `x-xdr-timestamp`, `Authorization`

## Running a shared or public instance

Every credential mockdr accepts is documented, the S1 admin token
(`admin-token-0000-0000-000000000001`) included. "Admin only" therefore
protects nothing on an instance others can reach: whoever can open the URL
holds every role. That is by design for the mocked APIs — changing mock data
is what a mock is for — but some control routes reach past the mock itself.

Set **`MOCKDR_PUBLIC=true`** on any instance reachable by people you do not
trust: a public demo, a shared lab host, a CI runner exposed on a network.
The Render blueprint (`render.yaml`) sets it. In public mode:

| Refused with `403` | Why |
|---|---|
| `POST /_dev/proxy/config` with a mode other than `off` | Record mode forwards *anonymous* requests to an upstream the caller names, with the configured credentials attached — an open proxy into the host's network |
| `POST /_dev/webhooks` | A subscription makes the mock POST to a caller-chosen URL on every matching event any visitor causes |
| `POST /_dev/import` | Replaces the whole store every visitor reads, and adds whatever API tokens the snapshot carries (the tokens already issued are kept) |
| `POST /_dev/rate-limit`, `POST /_dev/fault-injection` | Throttle or fail every visitor's requests |

and no outbound request is made at all: an existing webhook subscription
delivers nothing, the proxy forwards nothing. The mocked vendor APIs,
`/_dev/reset`, scenarios, playbooks and every read-only `/_dev` route keep
working. Visitors share one store, so one can still reset or rewrite the
mock data the others see; restart the instance (or let the free plan's idle
spin-down do it) to get the seed back.

Public mode is **off by default**, so a mock started in CI or on a
developer's machine keeps every route README and TESTING.md describe.

What an operator of a public instance should also do:

- Leave the recording proxy unconfigured and `MOCKDR_PERSIST` unset —
  persisted state is shared state.
- Keep `CORS_ORIGINS` at its default (the bundled console is same-origin);
  never combine `*` with real credentials.
- Put a reverse proxy with TLS and request-rate limits in front: the
  built-in limiter is per token, and every visitor shares the same tokens.

## Outbound requests

Two features make mockdr an HTTP client: the recording proxy (forwarding to
the real vendor and fetching its OAuth token) and outbound webhooks. Their
targets must be `http` or `https` with a host, and are never sent to a
link-local or cloud-metadata address (`169.254.0.0/16`, `fe80::/10`,
`fd00:ec2::254`, `100.100.100.200`). Host names are resolved again right
before each request, so a name re-pointed after configuration is caught.
Loopback and private ranges stay reachable on a non-public instance — a
test's receiver on `localhost` and a lab Splunk on `10.x` are what the
features are for. Webhook deliveries time out after 5 s, proxied requests
after 30 s; neither follows redirects.

**The recording proxy authenticates as you.** In `record` mode every request
under a configured vendor's prefix is forwarded with your real credentials,
whoever sends it. Record only on an instance bound to `127.0.0.1`.
`GET /_dev/proxy/config` and `GET /_dev/export` leave the upstream secrets
out; a `MOCKDR_PERSIST` file keeps them (created `0600`), so protect it.

## Resource limits

A single request cannot buy unbounded work: bodies are capped at
`MOCKDR_MAX_BODY_BYTES` (16 MiB) before they are read; query-language
parsers have nesting limits (KQL, OData, SPL expressions, Elasticsearch
`bool` depth 30); an Elasticsearch query holds at most 4,096 clauses
(Lucene's `maxClauseCount`); SPL `makeresults` generates at most 50,000 rows
(limits.conf `maxresultrows`), `mvexpand` at most 100,000, and `mvrange`
at most 50,000 values per call and 1,000,000 per search; client-supplied
regular expressions run under a ReDoS guard. Traffic-written collections
(tokens, sessions, logs) are capped.

## CORS

CORS origins are configurable via the `CORS_ORIGINS` environment variable (comma-separated).
Default: `http://localhost:5173,http://localhost:8001`.

Set `CORS_ORIGINS=*` to allow all origins (not recommended for network-accessible deployments).

## Rate Limiting

Per-token rate limiting is applied via middleware, off by default. Configure via `/_dev/rate-limit` (refused on a public instance). Only the `/_dev` control routes under `/web/api/v2.1/_dev/` are exempt.

## Security Headers

The following headers are set on all responses:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 0` (the legacy auditor is disabled, as OWASP recommends; CSP-era browsers ignore it)
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`

## Reporting Vulnerabilities

This is a mock/testing tool. If you find a security issue, please open a GitHub issue.

## Known Limitations

- All data is stored in-memory (no encryption at rest)
- Mock credentials are deterministic and publicly documented
- No TLS termination (use a reverse proxy for HTTPS)
- Request audit log is capped at 500 entries
