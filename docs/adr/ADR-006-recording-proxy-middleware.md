# ADR-006: Three-Mode Recording Proxy Middleware

**Status**: Accepted (updated for multi-vendor support)
**Date**: 2026-03-11 (updated 2026-03-19)

## Context

mockdr needs two distinct operational modes: a pure mock (for offline/CI use) and a bridge to real vendor APIs (for validating field coverage and recording new responses). Switching modes at the process level (environment variables, separate binaries) would require redeployment. Operators also need a replay mode that serves recorded real responses without hitting the live tenant — useful for deterministic regression testing against real data.

As of the multi-vendor update, the proxy supports all eight vendors: SentinelOne, CrowdStrike Falcon, Microsoft Defender for Endpoint, Elastic Security, Cortex XDR, Splunk SIEM, Microsoft Sentinel, and Microsoft Graph API.

## Decision

`backend/api/middleware/proxy.py` implements an ASGI middleware (`RecordingProxyMiddleware`) with three modes controlled at runtime via the `/_dev/proxy` API endpoint:

| Mode | Behaviour |
|---|---|
| `off` (default) | No-op; all requests fall through to mock handlers |
| `record` | Detects the vendor from the URL prefix, forwards the request to the configured real upstream with vendor-appropriate auth headers, persists the exchange (tagged by vendor), returns the real response to the caller |
| `replay` | Looks up a stored recording for the vendor + request method + path; serves it if found, falls through to mock if not |

The middleware sits innermost in the ASGI stack (added first in `main.py`, so it runs last during request processing):

```python
app.add_middleware(RecordingProxyMiddleware)  # innermost
app.add_middleware(RequestAuditMiddleware)
app.add_middleware(RateLimitMiddleware)        # outermost
```

Dev paths (`/_dev/`) always bypass proxy logic to prevent circular forwarding.

### Multi-Vendor Architecture

**Vendor detection** (`application/proxy/vendor_routing.py`): A pure function maps URL prefixes to vendor names:

| Prefix | Vendor |
|---|---|
| `/web/api/v2.1` | `s1` |
| `/cs/` | `crowdstrike` |
| `/mde/` | `mde` |
| `/elastic/`, `/kibana/` | `elastic` |
| `/xdr/public_api/v1` | `cortex_xdr` |
| `/splunk/` | `splunk` |
| `/sentinel/` | `sentinel` |
| `/graph/` | `graph` |

**Per-vendor auth** (`application/proxy/auth_headers.py`): Each vendor uses its native auth mechanism:

| Vendor | Auth Strategy |
|---|---|
| SentinelOne | `Authorization: ApiToken <token>` |
| CrowdStrike, MDE, Sentinel, Graph | OAuth2 client credentials → Bearer token (cached) |
| Elastic, Splunk | Basic Auth or API Key |
| Cortex XDR | HMAC (key_id + nonce + timestamp → SHA256) |

**OAuth2 token cache** (`application/proxy/token_cache.py`): Client-credentials vendors (CS, MDE, Sentinel, Graph) cache Bearer tokens in memory with automatic refresh 30 seconds before expiry. Async lock prevents thundering herd on concurrent requests.

**Path stripping**: When forwarding, the mockdr prefix (e.g., `/cs`) is stripped from the path before appending to the vendor's `base_url`. Exception: SentinelOne paths are forwarded as-is since the real API uses the same `/web/api/v2.1` prefix.

**Recording storage**: Exchanges are persisted in the in-memory proxy state and tagged with the vendor name. Recordings are matched by vendor + method + path to prevent cross-vendor collisions.

**Credentials**: Per-vendor upstream URLs and auth credentials are configured at runtime via `POST /_dev/proxy/config` or the UI. The config is included in `MOCKDR_PERSIST` snapshots and survives restarts and `/_dev/reset`.

## Configuration API

```
POST /_dev/proxy/config
{
  "mode": "record",
  "vendors": [
    {
      "vendor": "crowdstrike",
      "base_url": "https://api.crowdstrike.com",
      "auth": {
        "type": "oauth2",
        "client_id": "...",
        "client_secret": "...",
        "token_url": "https://api.crowdstrike.com/oauth2/token"
      }
    }
  ]
}
```

Secrets are masked in `GET /_dev/proxy/config` responses.

## Alternatives Considered

| Option | Rejected because |
|---|---|
| Separate recording proxy process (mitmproxy, etc.) | Adds operational complexity; two processes to coordinate |
| Record mode only, no replay | Cannot run regression tests against real data offline |
| Env-var mode switching | Requires process restart to toggle; breaks dev workflow |
| Runtime toggle via header | Non-standard; leaks mode control into the API surface |
| Single base_url for all vendors | Each vendor has different auth, prefixes, and base URLs |

## Consequences

- **Positive**: A running mock can be switched to record mode, exercised against any real vendor API, then switched back to off — all without restart
- **Positive**: Recorded exchanges can be committed to the repo as fixtures for regression tests
- **Positive**: Replay mode enables deterministic testing against real response shapes, not mock-generated ones
- **Positive**: All eight vendors can be proxied simultaneously with vendor-specific auth handling
- **Positive**: OAuth2 token caching avoids unnecessary token exchanges on every request
- **Negative**: Record mode requires valid vendor credentials; CI must run in `off` mode
- **Negative**: Recordings are in-memory only across restarts (config is persisted, recordings are not); export via dev API is required to persist recordings to disk
