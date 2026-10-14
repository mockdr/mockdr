"""`mockdr_server`, the fixture ADR-013 offers external suites, over real TCP.

The unit tests drive MockdrClient through a mock transport. The fixture
itself -- a uvicorn thread on a free port, a health poll, a client pointed
at it -- was said to be "exercised implicitly by every integration test that
depends on it", and no test depended on it. These do, the way the module's
own docstring tells a consumer to use it.
"""
import httpx
import pytest

from mockdr.testing import MockdrClient, mockdr_server  # noqa: F401 - the fixture


@pytest.fixture(scope="module")
def server(mockdr_server: MockdrClient) -> MockdrClient:  # noqa: F811
    return mockdr_server


def test_the_documented_agent_list(server: MockdrClient) -> None:
    agents = server.get("/agents")
    assert agents["pagination"]["totalItems"] == 60
    # SentinelOne's documented default page, not the whole fleet.
    assert len(agents["data"]) == 10


def test_the_documented_scenario_round_trip(server: MockdrClient) -> None:
    server.reset()
    before = server.get("/agents", params={"infected": True})["pagination"]["totalItems"]
    assert server.scenario("mass_infection")["data"]["affected"] == 20
    after = server.get("/agents", params={"infected": True})["pagination"]["totalItems"]
    assert after > before
    server.reset()
    again = server.get("/agents", params={"infected": True})["pagination"]["totalItems"]
    assert again == before


def test_a_misspelt_scenario_raises(server: MockdrClient) -> None:
    with pytest.raises(httpx.HTTPStatusError) as caught:
        server.scenario("ransomware_outbreak")
    assert caught.value.response.status_code == 400


def test_a_snapshot_goes_back_in(server: MockdrClient) -> None:
    snapshot = server.export_state()
    assert server.import_state(snapshot)["data"]["skipped"] == 0
