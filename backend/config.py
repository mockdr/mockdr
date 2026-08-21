import os

#: Single source of truth for the mockdr release version.
#:
#: Mirrored by ``backend/pyproject.toml`` and ``frontend/package.json``; the UI
#: footer reads the latter at build time rather than hardcoding a string. Kept
#: in step by ``tests/unit/test_version.py``.
#:
#: Note this is *mockdr's* version, not the version of any API it mocks — the
#: SentinelOne surface stays pinned at v2.1 via ``API_PREFIX``.
APP_VERSION = "2.0.2"

API_PREFIX = "/web/api/v2.1"
DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 1000
DV_FINISH_DELAY_SECONDS = 2

SEED_COUNT_AGENTS = int(os.getenv("SEED_COUNT_AGENTS", "60"))
SEED_COUNT_THREATS = int(os.getenv("SEED_COUNT_THREATS", "30"))
SEED_COUNT_ALERTS = int(os.getenv("SEED_COUNT_ALERTS", "20"))

CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:8001").split(",")

PERSIST_PATH = os.getenv("MOCKDR_PERSIST", "")

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
