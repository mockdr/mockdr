"""A Falcon ``ids`` query parameter is an array, sent once per id.

Every ``ids`` the Falcon API takes in a query string is declared as an array
with ``collectionFormat: multi``, and gofalcon serialises it that way:
``swag.JoinByFormat(idsIC, "multi")`` in
``falcon/client/hosts/get_device_details_v2_parameters.go`` (and the same
line in the IOC, host-group and process clients) puts ``?ids=a&ids=b&ids=c``
on the wire. The mock declared ``ids`` as one string, so FastAPI kept the
last repetition only: three hosts asked for, one returned, with a 200 that
looked complete. The comma-separated spelling the mock always accepted keeps
working beside it.
"""
from __future__ import annotations

from fastapi.testclient import TestClient


def _cs_auth(client: TestClient) -> dict[str, str]:
    resp = client.post("/cs/oauth2/token", data={
        "client_id": "cs-mock-admin-client",
        "client_secret": "cs-mock-admin-secret",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _repeated(ids: list[str]) -> list[tuple[str, str]]:
    """The query string gofalcon builds: one ``ids`` pair per id."""
    return [("ids", i) for i in ids]


class TestRepeatedIdsAreAllRead:
    """Each repetition of ``ids`` names an entity, not just the last one."""

    def test_device_details_v2_answers_every_repeated_id(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        ids = client.get("/cs/devices/queries/devices/v1", headers=headers,
                         params={"limit": 3}).json()["resources"]
        assert len(ids) == 3
        resp = client.get("/cs/devices/entities/devices/v2", headers=headers,
                          params=_repeated(ids))
        assert resp.status_code == 200
        assert sorted(r["device_id"] for r in resp.json()["resources"]) == sorted(ids)

    def test_comma_separated_ids_still_work(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        ids = client.get("/cs/devices/queries/devices/v1", headers=headers,
                         params={"limit": 3}).json()["resources"]
        resp = client.get("/cs/devices/entities/devices/v2", headers=headers,
                          params={"ids": ",".join(ids)})
        assert len(resp.json()["resources"]) == 3

    def test_host_groups_answer_every_repeated_id(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        ids = client.get("/cs/devices/queries/host-groups/v1", headers=headers,
                         params={"limit": 2}).json()["resources"]
        assert len(ids) == 2
        resp = client.get("/cs/devices/entities/host-groups/v1", headers=headers,
                          params=_repeated(ids))
        assert sorted(r["id"] for r in resp.json()["resources"]) == sorted(ids)

    def test_iocs_answer_every_repeated_id(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        ids = [r["id"] for r in client.get(
            "/cs/iocs/combined/indicator/v1", headers=headers,
            params={"limit": 3}).json()["resources"]]
        assert len(ids) == 3
        resp = client.get("/cs/iocs/entities/indicators/v1", headers=headers,
                          params=_repeated(ids))
        assert sorted(r["id"] for r in resp.json()["resources"]) == sorted(ids)

    def test_ioc_delete_removes_every_repeated_id(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        ids = [r["id"] for r in client.get(
            "/cs/iocs/combined/indicator/v1", headers=headers,
            params={"limit": 2}).json()["resources"]]
        client.delete("/cs/iocs/entities/indicators/v1", headers=headers,
                      params=_repeated(ids))
        # Read back in the comma spelling, which never lost an id.
        left = client.get("/cs/iocs/entities/indicators/v1", headers=headers,
                          params={"ids": ",".join(ids)}).json()["resources"]
        assert left == []
