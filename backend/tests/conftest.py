"""Global test fixtures for mockdr backend tests."""
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from api.middleware.rate_limit import reset_counters, set_config
from infrastructure.seed import generate_all
from main import app


@pytest.fixture(autouse=True)
def fresh_seed() -> None:
    """Re-seed all repositories before each test to ensure isolation."""
    generate_all()


@pytest.fixture(autouse=True)
def quiet_rate_limiter() -> Iterator[None]:
    """Leave the limiter off, whatever a test did to it.

    The limiter's config and counters are process-global and live outside
    the store `generate_all` clears, so a test that switches throttling on
    hands it to every later test in the same xdist worker.  The file that
    owns the `_dev/rate-limit` route did switch it on at 120 rpm and relied
    on a *later test in the same file* to switch it off — which holds until
    xdist puts the two in different workers.  It then throttled whatever
    else that worker ran, and a test asserting on a response body got the
    429 envelope instead: a red build with nothing wrong in the code under
    test.  Seen once in five full runs here, so rare enough to be re-run
    away and never explained.
    """
    yield
    set_config(enabled=False, rpm=60)
    reset_counters()


@pytest.fixture()
def client(fresh_seed: None) -> TestClient:
    """FastAPI test client with seeded data and admin auth header."""
    return TestClient(app)


@pytest.fixture()
def auth_headers() -> dict[str, str]:
    """Admin API token headers for authenticated requests."""
    return {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}


@pytest.fixture()
def viewer_headers() -> dict[str, str]:
    """Viewer API token headers."""
    return {"Authorization": "ApiToken viewer-token-0000-0000-000000000002"}
