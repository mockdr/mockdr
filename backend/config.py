import os

#: Single source of truth for the mockdr release version.
#:
#: Mirrored by ``backend/pyproject.toml`` and ``frontend/package.json``; the UI
#: footer reads the latter at build time rather than hardcoding a string. Kept
#: in step by ``tests/unit/test_version.py``.
#:
#: Note this is *mockdr's* version, not the version of any API it mocks — the
#: SentinelOne surface stays pinned at v2.1 via ``API_PREFIX``.
APP_VERSION = "2.8.0"

API_PREFIX = "/web/api/v2.1"
#: `limit` defaults to 10 on every SentinelOne list route the mock serves —
#: `default: 10` on all of them in data/swagger_2_1.json (122 GET operations
#: in all). This was 25, so a client that relies on the default got pages
#: two and a half times the size the product sends, and a paging test that
#: passed here walked a different number of pages in production.
DEFAULT_PAGE_SIZE = 10
MAX_PAGE_SIZE = 1000
#: `skip` is documented "(0-1000). To iterate over more than 1000 items, use
#: `cursor`" with `maximum: 1000` on every list route this mock serves that
#: takes it (data/swagger_2_1.json); past that a client is meant to page by
#: cursor. Enforced the way `limit`'s documented maximum is, as a 400.
MAX_SKIP = 1000
DV_FINISH_DELAY_SECONDS = 2

SEED_COUNT_AGENTS = int(os.getenv("SEED_COUNT_AGENTS", "60"))
SEED_COUNT_THREATS = int(os.getenv("SEED_COUNT_THREATS", "30"))
SEED_COUNT_ALERTS = int(os.getenv("SEED_COUNT_ALERTS", "20"))

CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:8001,http://localhost:5001").split(",")

PERSIST_PATH = os.getenv("MOCKDR_PERSIST", "")


def _duration_seconds(text: str) -> float:
    """``90``, ``90s``, ``15m``, ``12h`` or ``1d`` in seconds; 0 for empty or unreadable."""
    value = text.strip().lower()
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    scale = units.get(value[-1:], 1) if value else 1
    number = value[:-1] if value[-1:] in units else value
    try:
        return max(float(number) * scale, 0.0)
    except ValueError:
        return 0.0


# Re-seed the data set this often (e.g. `12h`), as `/_dev/reset` does: off
# by default. Seed records are dated relative to the moment they were
# seeded, so an instance that runs for days ages like a tenant nobody
# writes to: one day in, `earliest=-24h` finds nothing; after a week every
# 7-day window is empty; after 30 days Graph hunting's default `Timespan`
# returns no rows; after 180 days the seeded SentinelOne API tokens expire.
# A real tenant keeps receiving new data and the mock does not, so a public
# demo or a long-lived shared instance should set this. Issued tokens and
# sessions survive it, as they survive `/_dev/reset`; what clients wrote
# does not.
RESEED_INTERVAL_SECONDS = _duration_seconds(os.getenv("MOCKDR_RESEED_INTERVAL", ""))

# How long a Splunk search job takes to reach DONE, in seconds.
#
# The search itself runs synchronously, so results are ready immediately and
# the default of 0 keeps every response deterministic. Setting this makes the
# dispatch states real Splunk passes through — QUEUED, PARSING, RUNNING,
# FINALIZING — observable, which is what a client polling `isDone` in a loop
# needs in order to be exercised at all.
SPLUNK_DISPATCH_SECONDS = float(os.getenv("MOCKDR_SPLUNK_DISPATCH_SECONDS", "0"))

# Whether HEC accepts its token as ?token=, mirroring inputs.conf's
# allowQueryStringAuth. Off by default, because that is splunkd's default:
# verified against Splunk 10.4.2, which answers a valid token sent this way
# with 400 {"text": "Query string authorization is not enabled", "code": 16}
# unless the setting is turned on.
SPLUNK_HEC_QUERY_STRING_AUTH = os.getenv(
    "MOCKDR_SPLUNK_HEC_QUERY_STRING_AUTH", "false",
).lower() in ("1", "true", "yes")

# When true, a tenant segment in an Entra token URL must match the tenant the
# credential belongs to. Set MOCKDR_STRICT_TENANT=false to accept any tenant,
# e.g. when pointing a connector configured with a real tenant ID at the mock.
STRICT_TENANT = os.getenv("MOCKDR_STRICT_TENANT", "true").strip().lower() not in {
    "0", "false", "no", "off",
}

# The largest request body accepted, in bytes; a larger one answers 413 as a
# reverse proxy in front of the real products would. HEC batches and
# Elasticsearch _bulk bodies fit comfortably; an unbounded body only grows
# the process.
MAX_BODY_BYTES = int(os.getenv("MOCKDR_MAX_BODY_BYTES", str(16 * 1024 * 1024)))

# Public-instance posture. Off by default, so a mock started in CI or on a
# developer's machine keeps every control route the docs describe. Set
# MOCKDR_PUBLIC=true on an instance anyone can reach (the Render demo sets
# it): the admin token is a documented constant, so whatever it unlocks
# beyond the mocked APIs is unlocked for every visitor. Public mode refuses
# the routes whose effect leaves the mock or outlives one visitor's session —
# the recording proxy, outbound webhooks, snapshot import, fault injection
# and the rate-limit switch — and every outbound request the mock would make.
PUBLIC_MODE = os.getenv("MOCKDR_PUBLIC", "false").strip().lower() in {
    "1", "true", "yes", "on",
}
