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

## CORS

CORS origins are configurable via the `CORS_ORIGINS` environment variable (comma-separated).
Default: `http://localhost:5173,http://localhost:8001`.

Set `CORS_ORIGINS=*` to allow all origins (not recommended for network-accessible deployments).

## Rate Limiting

Per-token rate limiting is applied via middleware. Configure via `/_dev/rate-limit`.

## Security Headers

The following headers are set on all responses:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`

## Reporting Vulnerabilities

This is a mock/testing tool. If you find a security issue, please open a GitHub issue.

## Known Limitations

- All data is stored in-memory (no encryption at rest)
- Mock credentials are deterministic and publicly documented
- No TLS termination (use a reverse proxy for HTTPS)
- Request audit log is capped at 500 entries
