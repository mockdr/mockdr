# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed

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
- Graph reports a missing user, group or device as `Request_ResourceNotFound`,
  the code real Graph uses for directory objects.

- Graph, MDE and Sentinel token endpoints now accept the tenant-scoped URL real
  Entra ID uses (`/{tenant}/oauth2/v2.0/token`) in addition to the bare path, so
  clients that mirror the Microsoft authority shape no longer fall through to
  the SPA catch-all and get a misleading `405 Method Not Allowed` ([#22]).
  Like Entra, the segment accepts the tenant GUID or a verified domain name; a
  tenant that matches neither is rejected with `400 invalid_request`
  (AADSTS90002). Set `MOCKDR_STRICT_TENANT=false` to accept any tenant.

[#22]: https://github.com/mockdr/mockdr/issues/22

