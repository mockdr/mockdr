"""Global test fixtures for mockdr backend tests."""
import pytest
from fastapi.testclient import TestClient

from infrastructure.seed import generate_all
from main import app


@pytest.fixture(autouse=True)
def fresh_seed() -> None:
    """Re-seed all repositories before each test to ensure isolation."""
    generate_all()


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
