# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security

- Splunk index creation, HEC token management and KV Store collection
  management now require an administrator role. `require_splunk_admin` existed
  but was never applied, so the seeded `viewer` could create indexes and mint
  HEC tokens. `sc_admin` counts as an administrator, as it does in Splunk Cloud.

### Added

- EDR→SIEM bridging is live (ADR-009): the Splunk and Sentinel bridges are
  registered at startup and EDR mutations publish to the event bus, so a
  Defender alert or a triggered scenario now appears in the SIEMs. Both bridges
  and the bus were previously unreachable code.
- MDE list endpoints support `$count=true`, returning `@odata.count`.

### Changed

- The Graph, MDE and Sentinel token endpoints return OAuth 2.0 errors —
  `{"error": "...", "error_description": "AADSTS...", "error_codes": [...]}` —
  instead of the OData envelope of the API they sit in front of. MSAL and other
  OAuth clients read those keys.
- `GET /graph/v1.0/me` returns `400 Request_BadRequest` under app-only
  authentication, as real Graph does, instead of returning the first seeded user.
- Splunk endpoints now answer in Atom XML unless `output_mode=json` is
  requested, as splunkd does. HEC still always answers JSON.
- Sentinel management-plane requests now require `?api-version=`, as Azure
  Resource Manager does. The Log Analytics query endpoint is unaffected.
- Graph `$count=true` now requires `ConsistencyLevel: eventual` instead of being
  answered regardless.

### Fixed

- Cortex XDR advanced authentication now uses the documented scheme —
  `SHA256(key + nonce + timestamp)` over the plain concatenation — instead of an
  HMAC over `nonce:timestamp`, which rejected every client built to Palo Alto's
  specification. Standard authentication (the API key in `Authorization`) is
  supported as well.
- Request-validation failures are returned in the mocked vendor's error envelope
  with the status that vendor uses, instead of FastAPI's `422 {"detail": [...]}`,
  which no mocked API emits.
- `POST /mde/api/indicators` now rejects a body missing `indicatorValue`,
  `indicatorType`, `action` or `title` with `400 BadRequest` instead of creating
  an indicator with empty fields.
- Authorization scheme names are matched case-insensitively for Sentinel and
  Splunk, per RFC 7235.
- Splunk accepts a session key in its own `Authorization: Splunk <key>` scheme,
  not only as `Bearer`.
- Graph reports a missing resource with the code its sub-API uses:
  `Request_ResourceNotFound` for directory objects, `ErrorItemNotFound` for
  Outlook mail, `itemNotFound` for drive items and `notFound` for the security
  API.
- A state snapshot now covers every seeded collection. Graph, Sentinel, Splunk
  and hash exceptions were absent from the registry, and because loading a
  snapshot skips seeding, restarting with `MOCKDR_PERSIST` left those vendors
  permanently empty. A coverage test now fails if a new collection is missed.
- Sentinel rejects a `$skipToken` it did not issue with `400 InvalidSkipToken`
  instead of raising `ValueError` and returning a 500, and `nextLink` is now the
  absolute, followable URL ARM returns rather than a bare `?$skipToken=`.
- `POST /iocs/bulk` accepts a single indicator sent as an object instead of
  silently discarding it and reporting success.
- Activity records evicted from the bounded order deque are deleted with it, so
  `count()` and `list_activities()` no longer diverge past 10,000 activities.
- The Webhooks UI reads `eventTypes` and `createdAt`, the field names the API
  actually returns; it previously read snake_case and threw while rendering.
- `frontend/.env` is created from `.env.example` by `start.sh` and the Docker
  build. Vite inlines `VITE_*` at build time, so without it every vendor client
  in the UI authenticated as `undefined`.
- `xdr_api_key_repo.get_by_key_id` is a single dict lookup instead of rebuilding
  an index on every call, matching what its docstring already claimed.

- Graph, MDE and Sentinel token endpoints now accept the tenant-scoped URL real
  Entra ID uses (`/{tenant}/oauth2/v2.0/token`) in addition to the bare path, so
  clients that mirror the Microsoft authority shape no longer fall through to
  the SPA catch-all and get a misleading `405 Method Not Allowed` ([#22]).
  Like Entra, the segment accepts the tenant GUID or a verified domain name; a
  tenant that matches neither is rejected with `400 invalid_request`
  (AADSTS90002). Set `MOCKDR_STRICT_TENANT=false` to accept any tenant.

[#22]: https://github.com/mockdr/mockdr/issues/22

