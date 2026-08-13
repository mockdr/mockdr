import os

API_PREFIX = "/web/api/v2.1"
DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 1000
DV_FINISH_DELAY_SECONDS = 2

SEED_COUNT_AGENTS = int(os.getenv("SEED_COUNT_AGENTS", "60"))
SEED_COUNT_THREATS = int(os.getenv("SEED_COUNT_THREATS", "30"))
SEED_COUNT_ALERTS = int(os.getenv("SEED_COUNT_ALERTS", "20"))

CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:8001").split(",")

PERSIST_PATH = os.getenv("MOCKDR_PERSIST", "")

# When true, a tenant segment in an Entra token URL must match the tenant the
# credential belongs to. Set MOCKDR_STRICT_TENANT=false to accept any tenant,
# e.g. when pointing a connector configured with a real tenant ID at the mock.
STRICT_TENANT = os.getenv("MOCKDR_STRICT_TENANT", "true").strip().lower() not in {
    "0", "false", "no", "off",
}
