"""Cortex XDR answers in the shapes the XSOAR integration reads.

The Cortex XDR - IR integration (demisto/content, Packs/CortexXDR,
CortexXDRIR.py on CoreIRApiModule.py) was driven against the mock end to
end. The requests below are the ones it sends -- its ``get_headers``
(advanced auth, a 64-character nonce, a timestamp in whole seconds times
1000) and its bodies -- and each class names the command that broke.
"""
from __future__ import annotations

import hashlib
import secrets
import string
from datetime import UTC, datetime

from fastapi.testclient import TestClient

XDR = "/xdr/public_api/v1"


def _xsoar_headers() -> dict[str, str]:
    """``CortexXDRIR.get_headers``, as written."""
    nonce = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
    timestamp = str(int(datetime.now(UTC).timestamp()) * 1000)
    digest = hashlib.sha256(f"xdr-admin-secret{nonce}{timestamp}".encode()).hexdigest()
    return {"x-xdr-timestamp": timestamp, "x-xdr-nonce": nonce,
            "x-xdr-auth-id": "1", "Authorization": digest}


def _incidents_with_alerts(client: TestClient) -> list[dict]:
    response = client.post(f"{XDR}/incidents/get_multiple_incidents_extra_data/",
                           headers=_xsoar_headers(),
                           json={"request_data": {"search_from": 0, "search_to": 100}})
    assert response.status_code == 200, response.text
    return [i for i in response.json()["reply"]["incidents"] if i["alerts"]["data"]]


class TestExtraDataHostIpIsAString:
    """``fetch-incidents`` and ``xdr-get-incident-extra-data`` split ``host_ip``.

    Every recorded extra-data reply spells an alert's ``host_ip`` as one
    comma-separated string -- ``"1.1.1.1, 2.2.2.2"`` for two (XSOAR test_data
    ``get_incident_extra_data_host_id_array.json``) -- and the integration's
    ``sort_incident_data`` builds ``host_ip_list`` with
    ``alert.get("host_ip").split(",")``. The mock answered the list it
    stores, and every fetch cycle raised ``AttributeError: 'list' object has
    no attribute 'split'`` on the first incident that had an alert.
    """

    def test_multiple_incidents_extra_data(self, client: TestClient) -> None:
        incidents = _incidents_with_alerts(client)
        assert incidents
        for incident in incidents:
            for alert in incident["alerts"]["data"]:
                assert alert["host_ip"] is None or isinstance(alert["host_ip"], str)
                # What sort_incident_data does with it.
                assert [ip.strip() for ip in (alert["host_ip"] or "").split(",")]

    def test_single_incident_extra_data(self, client: TestClient) -> None:
        incident_id = _incidents_with_alerts(client)[0]["incident"]["incident_id"]
        response = client.post(f"{XDR}/incidents/get_incident_extra_data/",
                               headers=_xsoar_headers(),
                               json={"request_data": {"incident_id": incident_id,
                                                      "alerts_limit": 1000}})
        assert response.status_code == 200, response.text
        alerts = response.json()["reply"]["alerts"]["data"]
        assert alerts
        assert all(isinstance(a["host_ip"], str) for a in alerts if a["host_ip"] is not None)

    def test_two_addresses_are_comma_separated(self, client: TestClient) -> None:
        """The stored list and the string agree, address for address."""
        from repository.xdr_alert_repo import xdr_alert_repo

        incident = _incidents_with_alerts(client)[0]
        alert = incident["alerts"]["data"][0]
        stored = xdr_alert_repo.get(alert["alert_id"])
        assert stored is not None
        assert alert["host_ip"] == (", ".join(stored.host_ip) or None)


def _filter_data(client: TestClient, filter_data: dict):  # type: ignore[no-untyped-def]
    return client.post(f"{XDR}/alerts/get_alerts_by_filter_data/", headers=_xsoar_headers(),
                       json={"request_data": {"filter_data": filter_data}})


class TestAlertsByFilterData:
    """``xdr-get-alerts`` asks with ``filter_data`` and reads ``alert_fields``.

    The integration's ``get_alerts_by_filter_command`` builds
    ``{"filter": {"AND": [...]}, "sort": [{"FIELD", "ORDER"}], "paging":
    {"from", "to"}}`` and reads each alert from ``alert["alert_fields"]``
    (the recorded reply, XSOAR test_data ``get_alerts_by_filter_results.json``).
    The route read only the public ``filters`` form: the command's filter,
    sort and paging were ignored and every item's ``alert_fields`` was the
    recorded template, blank -- the command listed forty alerts with no
    name, no severity and no id.
    """

    #: What the command sends for ``severity=high limit=5``.
    HIGH = {
        "sort": [{"FIELD": "source_insert_ts", "ORDER": "DESC"}],
        "paging": {"from": 0, "to": 5},
        "filter": {"AND": [{"OR": [{"SEARCH_FIELD": "severity", "SEARCH_TYPE": "EQ",
                                    "SEARCH_VALUE": "SEV_040_HIGH"}]}]},
    }

    def test_the_filter_sort_and_paging_apply(self, client: TestClient) -> None:
        response = _filter_data(client, self.HIGH)
        assert response.status_code == 200, response.text
        reply = response.json()["reply"]
        fields = [a["alert_fields"] for a in reply["alerts"]]
        assert reply["result_count"] == len(fields)
        assert 0 < len(fields) <= 5
        assert {f["severity"] for f in fields} == {"SEV_040_HIGH"}
        stamps = [f["source_insert_ts"] for f in fields]
        assert stamps == sorted(stamps, reverse=True)

    def test_alert_fields_carry_the_alert(self, client: TestClient) -> None:
        from repository.xdr_alert_repo import xdr_alert_repo

        fields = _filter_data(client, self.HIGH).json()["reply"]["alerts"][0]["alert_fields"]
        stored = xdr_alert_repo.get(fields["external_id"])
        assert stored is not None
        assert fields["alert_name"] == stored.name
        assert fields["agent_id"] == stored.endpoint_id
        assert fields["agent_ip_addresses"] == stored.host_ip
        assert fields["source_insert_ts"] == stored.detection_timestamp
        assert fields["internal_id"] == stored.internal_id

    def test_paging_walks_the_whole_set_once(self, client: TestClient) -> None:
        from repository.xdr_alert_repo import xdr_alert_repo

        total = len(xdr_alert_repo.list_all())
        seen: list[str] = []
        start = 0
        while start <= total:
            page = _filter_data(client, {
                "sort": [{"FIELD": "internal_id", "ORDER": "ASC"}],
                "paging": {"from": start, "to": start + 7}, "filter": {"AND": []},
            }).json()["reply"]["alerts"]
            if not page:
                break
            seen += [a["alert_fields"]["internal_id"] for a in page]
            start += 7
        assert sorted(seen) == seen
        assert len(seen) == len(set(seen)) == total

    def test_contains_and_relative_time(self, client: TestClient) -> None:
        name = _filter_data(client, self.HIGH).json()["reply"]["alerts"][0]["alert_fields"]["alert_name"]
        found = _filter_data(client, {"paging": {"from": 0, "to": 100}, "filter": {"AND": [
            {"SEARCH_FIELD": "alert_name", "SEARCH_TYPE": "CONTAINS", "SEARCH_VALUE": name[2:8]},
            {"SEARCH_FIELD": "source_insert_ts", "SEARCH_TYPE": "RELATIVE_TIMESTAMP",
             "SEARCH_VALUE": str(400 * 86_400_000)},
        ]}}).json()["reply"]["alerts"]
        assert found
        assert all(name[2:8].lower() in a["alert_fields"]["alert_name"].lower() for a in found)
        none = _filter_data(client, {"filter": {"AND": [
            {"SEARCH_FIELD": "source_insert_ts", "SEARCH_TYPE": "RELATIVE_TIMESTAMP",
             "SEARCH_VALUE": "1"}]}}).json()["reply"]["alerts"]
        assert none == []

    def test_an_unknown_search_type_is_refused(self, client: TestClient) -> None:
        response = _filter_data(client, {"filter": {"AND": [
            {"SEARCH_FIELD": "severity", "SEARCH_TYPE": "LIKE", "SEARCH_VALUE": "x"}]}})
        assert response.status_code == 400

    def test_the_filters_form_still_answers_the_stored_fields(self, client: TestClient) -> None:
        response = client.post(f"{XDR}/alerts/get_alerts_by_filter_data/",
                               headers=_xsoar_headers(),
                               json={"request_data": {"filters": [
                                   {"field": "severity", "operator": "in", "value": ["high"]}]}})
        assert response.status_code == 200, response.text
        alerts = response.json()["reply"]["alerts"]
        assert alerts and all(a["severity"] == "high" for a in alerts)
        assert all(a["alert_fields"]["severity"] == "SEV_040_HIGH" for a in alerts)


class TestDistributionVersionsPerPlatform:
    """``xdr-get-distribution-versions`` tables one list per platform.

    Cortex answers ``{"windows": [...], "linux": [...], "macos": [...]}``
    and nothing else (XSOAR test_data ``get_distribution_versions.json``);
    the CoreIRApiModule's ``get_distribution_versions_command`` iterates the
    reply's keys and tables each value as a list of versions. The mock sent
    the three platforms empty beside an invented ``data`` list -- every
    version labelled ``windows`` -- and ``total_count``/``result_count``
    integers, and the command raised ``object of type 'int' has no len()``.
    """

    def test_the_reply_is_three_lists_of_versions(self, client: TestClient) -> None:
        response = client.post(f"{XDR}/distributions/get_versions/",
                               headers=_xsoar_headers(), json={})
        assert response.status_code == 200, response.text
        reply = response.json()["reply"]
        assert set(reply) == {"windows", "linux", "macos"}
        for versions in reply.values():
            assert isinstance(versions, list)
            assert all(isinstance(v, str) and v.count(".") == 3 for v in versions)
        assert all(reply.values()), "every seeded platform offers a version"

    def test_each_platform_offers_its_own_distributions_versions(
        self, client: TestClient,
    ) -> None:
        from repository.xdr_distribution_repo import xdr_distribution_repo

        reply = client.post(f"{XDR}/distributions/get_versions/",
                            headers=_xsoar_headers(), json={}).json()["reply"]
        for dist in xdr_distribution_repo.list_all():
            assert dist.agent_version in reply[dist.platform]
