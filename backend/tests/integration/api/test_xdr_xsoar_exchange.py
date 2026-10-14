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
