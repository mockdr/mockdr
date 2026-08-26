"""Cross-cutting behaviours that span several endpoints.

Each of these was invisible from any single endpoint: a role change that took
effect in the user list and nowhere else, a cursor that never advanced, a
store read that raced with a concurrent write, and an event bus with
subscribers but no publishers.
"""
import threading

import pytest
from fastapi.testclient import TestClient

PREFIX = "/web/api/v2.1"


class TestRoleChangeInvalidatesPrivileges:
    """Authorisation reads the role off the token record, not the user."""

    @staticmethod
    def _soc_user(client: TestClient, auth_headers: dict) -> dict:
        users = client.get(f"{PREFIX}/users", headers=auth_headers).json()["data"]
        return next(u for u in users if u["email"] == "soc@acmecorp.com")

    SOC_TOKEN = {"Authorization": "ApiToken soc-analyst-token-000-000000000003"}

    def _write_attempt(self, client: TestClient) -> int:
        return client.post(
            f"{PREFIX}/agents/actions/disconnect",
            json={"filter": {"ids": ["no-such-agent"]}},
            headers=self.SOC_TOKEN,
        ).status_code

    def _set_role(self, client: TestClient, auth_headers: dict, role: str) -> None:
        user = self._soc_user(client, auth_headers)
        client.put(
            f"{PREFIX}/users/{user['id']}",
            json={"data": {"role": role}},
            headers=auth_headers,
        )

    def test_demotion_revokes_write_access(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        assert self._write_attempt(client) == 200

        self._set_role(client, auth_headers, "Viewer")

        # The token record's role was written once at creation and never
        # revisited, so a demoted user kept every privilege of the old role.
        assert self._write_attempt(client) == 403

    def test_promotion_grants_write_access(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        self._set_role(client, auth_headers, "Viewer")
        assert self._write_attempt(client) == 403

        self._set_role(client, auth_headers, "Admin")
        assert self._write_attempt(client) == 200


class TestCursorAdvancesWithTiedSortColumns:
    """A keyset cursor on a non-unique column must still advance."""

    def test_pagination_terminates_when_the_cursor_column_ties(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        from repository.firewall_repo import firewall_repo

        rules = firewall_repo.list_all()
        # Firewall rules key on createdAt, which is not unique. With every
        # value identical, resuming by value alone re-found the first row
        # forever and the client looped.
        for rule in rules:
            rule.createdAt = "2026-01-01T00:00:00.000Z"
            rule.order = 1
            firewall_repo.save(rule)

        seen: set[str] = set()
        cursor = None
        for _ in range(len(rules) + 5):
            params = {"limit": 2}
            if cursor:
                params["cursor"] = cursor
            body = client.get(
                f"{PREFIX}/firewall-control", headers=auth_headers, params=params,
            ).json()
            ids = [r["id"] for r in body["data"]]
            if not ids:
                break
            assert not (set(ids) & seen), "pagination returned a page it already gave"
            seen |= set(ids)
            cursor = body["pagination"]["nextCursor"]
            if not cursor:
                break

        assert len(seen) == len(rules)


class TestStoreReadsAreThreadSafe:
    """Reads must not iterate the live collection dicts."""

    def test_concurrent_writes_do_not_break_reads(
        self, client: TestClient,
    ) -> None:
        from repository.store import store

        token = client.post("/mde/oauth2/v2.0/token", data={
            "client_id": "mde-mock-admin-client",
            "client_secret": "mde-mock-admin-secret",
            "grant_type": "client_credentials",
        "scope": "https://api.securitycenter.microsoft.com/.default",
        }).json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        failures: list[object] = []
        stop = threading.Event()

        def write() -> None:
            index = 0
            while not stop.is_set():
                store.save("edr_id_map", f"stress-{index}", {"mde_machine_id": "x"})
                index += 1

        def read() -> None:
            for _ in range(40):
                try:
                    resp = client.get("/mde/api/machines", headers=headers)
                    if resp.status_code != 200:
                        failures.append(resp.status_code)
                except RuntimeError as exc:  # dict changed size during iteration
                    failures.append(type(exc).__name__)

        writer = threading.Thread(target=write, daemon=True)
        writer.start()
        readers = [threading.Thread(target=read) for _ in range(3)]
        for thread in readers:
            thread.start()
        for thread in readers:
            thread.join()
        stop.set()

        assert failures == [], f"concurrent reads failed: {failures[:3]}"


class TestEdrToSiemBridge:
    """The bridge had subscribers for ten event types and three publishers."""

    @staticmethod
    def _splunk_event_count() -> int:
        from repository.splunk.splunk_event_repo import splunk_event_repo

        return len(splunk_event_repo.list_all())

    def test_agent_action_reaches_splunk(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        agent_id = client.get(
            f"{PREFIX}/agents?limit=1", headers=auth_headers,
        ).json()["data"][0]["id"]

        before = self._splunk_event_count()
        client.post(
            f"{PREFIX}/agents/actions/disconnect",
            json={"filter": {"ids": [agent_id]}},
            headers=auth_headers,
        )

        assert self._splunk_event_count() > before

    def test_mde_isolation_reaches_splunk(self, client: TestClient) -> None:
        token = client.post("/mde/oauth2/v2.0/token", data={
            "client_id": "mde-mock-admin-client",
            "client_secret": "mde-mock-admin-secret",
            "grant_type": "client_credentials",
        "scope": "https://api.securitycenter.microsoft.com/.default",
        }).json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        machine_id = client.get(
            "/mde/api/machines", headers=headers,
        ).json()["value"][0]["id"]

        before = self._splunk_event_count()
        client.post(
            f"/mde/api/machines/{machine_id}/isolate",
            json={"Comment": "bridge test", "IsolationType": "Full"},
            headers=headers,
        )

        assert self._splunk_event_count() > before

    def test_xdr_alert_insert_reaches_splunk(self, client: TestClient) -> None:
        import hashlib
        import secrets
        import time

        nonce = secrets.token_hex(32)
        timestamp = str(int(time.time() * 1000))
        headers = {
            "x-xdr-auth-id": "1",
            "x-xdr-nonce": nonce,
            "x-xdr-timestamp": timestamp,
            "Authorization": hashlib.sha256(
                ("xdr-admin-secret" + nonce + timestamp).encode(),
            ).hexdigest(),
        }

        before = self._splunk_event_count()
        client.post(
            "/xdr/public_api/v1/alerts/insert_parsed_alerts/",
            json={"request_data": {"alerts": [
                {"alert_id": "bridge-probe", "severity": "high", "product": "Test"},
            ]}},
            headers=headers,
        )

        assert self._splunk_event_count() > before


@pytest.mark.parametrize(
    "event_type",
    ["threat_created", "agent_updated", "activity_created",
     "mde_alert_created", "mde_machine_updated", "xdr_alert_created"],
)
def test_bridge_subscription_has_a_publisher(event_type: str) -> None:
    """Every wired subscription should have something that fires it."""
    from domain.event_bus import event_bus

    assert event_bus._subscribers.get(event_type), (
        f"nothing subscribes to {event_type}"
    )
