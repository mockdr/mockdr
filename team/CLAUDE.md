# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working in this repository.
The previous version of this file described a different project (a CTEA
dashboard with `client-ts/` and an Express server); nothing of that exists
here. Code is the source of truth — if this file and the code disagree, the
code is right and this file is the bug.

## Project Overview

**mockdr** — a multi-protocol mock server for security-platform integration
testing. One FastAPI process on port 5001 (Docker) / 8001 (dev) serves eight
vendor APIs under their own prefixes — SentinelOne `/web/api/v2.1`,
CrowdStrike `/cs`, Defender for Endpoint `/mde`, Microsoft Graph `/graph`,
Microsoft Sentinel `/sentinel`, Cortex XDR `/xdr`, Splunk `/splunk`,
Elastic/Kibana `/elastic`, `/kibana` — plus a Vue 3 console on port 3000 in
dev (served from `frontend/dist` by the backend in Docker). Response shapes
are *measured* against public references of the real products; the rule is
"no evidence, no route" and the frontend only calls routes the real product
has. The mock's own controls live under `/web/api/v2.1/_dev/`.

## Commands

All backend commands run from `backend/` with the virtualenv's binaries
(`.venv/bin/…` — plain `ruff`/`mypy`/`pytest` are not on PATH).

```bash
# Backend (port 8001, auto-reload)
cd backend && .venv/bin/uvicorn main:app --port 8001 --reload

# Frontend dev server (port 3000; proxies every API root to 8001)
cd frontend && npm run dev

# Backend CI mirror
cd backend && .venv/bin/ruff check . \
  && .venv/bin/mypy --strict --allow-any-generics . --ignore-missing-imports --exclude tests/ \
  && .venv/bin/python -m pytest --cov --cov-fail-under=85 \
  && .venv/bin/python -m pytest -m critical --no-cov \
  && .venv/bin/bandit -r . -x ./tests,./.venv -ll

# Frontend CI mirror
cd frontend && npx eslint . --max-warnings=0 && npx vue-tsc --noEmit && npx vitest run --coverage

# E2E (Playwright, chromium): build, serve the build, point the suite at it
cd frontend && npm run build && npx vite preview --port 3101 --strictPort &
cd frontend && E2E_BASE_URL=http://localhost:3101 npx playwright test

# Everything CI runs, locally
./ci.sh
```

Single tests: `.venv/bin/python -m pytest tests/unit/test_version.py -q --no-cov`,
`npx vitest run src/stores/__tests__/auth.spec.ts`.

## Architecture

- `backend/main.py` — app, middleware stack (body limit outermost → … →
  recording proxy innermost), router registration per vendor.
- `backend/api/routers/` — ~70 routers; `graph/`, `splunk/`, `sentinel/`
  are sub-packages. One `<vendor>_auth.py` per auth scheme in `backend/api/`.
- `backend/application/` — CQRS: `commands/` mutate, `queries/` read.
- `backend/repository/store.py` — the single in-memory store (one RLock;
  traffic-written collections are capped in `CAPS`). Optional JSON snapshot
  via `MOCKDR_PERSIST`.
- `backend/infrastructure/seeders/` — deterministic seed (`random.seed(42)`),
  documentation-range IPs/domains only. `fixtures/` hold per-route default
  shapes generated from the vendor references.
- `backend/application/splunk/edr_shapes.py` + `commands/edr_bridge.py` —
  EDR → Splunk/Sentinel bridge, one event per API object under the add-on's
  sourcetype, dated by the record.
- `backend/utils/` — the hand-written parsers (SPL, KQL, OData, FQL, ES DSL)
  and the completion helpers (`complete_s1`, `complete_mde`, `xdr_shape`, …).
- `frontend/src/api/` — one axios client per vendor; every failure is
  reported to the notifications store (`Toasts.vue`, `aria-live`).
- `data/vendor-specs/` — reduced public references (sources and licences in
  `NOTICE.md`); `scripts/` regenerates them (`scripts/README.md`).
- `conformance/` — the harness that runs real Splunk/Elasticsearch/Kibana
  in containers and diffs them against the mock.

## Rules that are enforced, not aspirational

- A removed or renamed field in a response is drift; CI's `field-drift`
  job and `scripts/schema_drift.py` measure it. Never "fix" a test by
  loosening the comparison.
- `tests/critical/` (`-m critical`) proves internal fields never leak; it
  must stay green.
- `tests/unit/test_version.py` requires `config.py`, `pyproject.toml`,
  `package.json` and a CHANGELOG section to agree.
- Tag a release only after CI is green on the release commit
  (`scripts/README.md` → release checklist).
- Bridge events must equal the list route's serialization key for key
  (`tests/integration/api/test_splunk_edr_bridge.py`).

## Gotchas

- `cd` does not persist between tool calls; start each command with the
  directory.
- `tail -1` of `ruff check` hides "Found N errors"; check the exit code.
- Port 3100 on this machine is Loki, not a Vite leftover.
- The SPA catch-all answers 200/HTML for unknown paths when `frontend/dist`
  exists; without it (CI) they are 404.
- `team/` is untracked review material; do not `git add -A` it.
