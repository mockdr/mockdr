"""Referential-integrity regressions for seeded data.

Seeded records used to reference ids that existed nowhere, and counts used to
be drawn at random independently of the collection they were counting. Both
read as success to a client — a 200 with a plausible number — while the pivot
a real integration performs came back empty.
"""
from fastapi.testclient import TestClient

PREFIX = "/web/api/v2.1"


def _mde_auth(client: TestClient) -> dict[str, str]:
    resp = client.post("/mde/oauth2/v2.0/token", data={
        "client_id": "mde-mock-admin-client",
        "client_secret": "mde-mock-admin-secret",
        "grant_type": "client_credentials",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


class TestAlertsReferenceRealStarRules:
    """``alert.ruleInfo.id`` must name a rule the rules endpoint returns."""

    def test_rules_endpoint_is_not_empty(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        rules = client.get(
            f"{PREFIX}/cloud-detection/rules", headers=auth_headers,
        ).json()["data"]
        assert rules, "alerts cite STAR rules, so the rules must exist"

    def test_no_alert_cites_a_missing_rule(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        rule_ids = {
            r["id"] for r in client.get(
                f"{PREFIX}/cloud-detection/rules", headers=auth_headers,
            ).json()["data"]
        }
        alerts = client.get(
            f"{PREFIX}/cloud-detection/alerts", headers=auth_headers,
        ).json()["data"]

        dangling = [
            a["alertInfo"]["alertId"] for a in alerts
            if a["ruleInfo"]["id"] not in rule_ids
        ]
        assert not dangling, f"alerts cite rules that do not exist: {dangling}"


class TestAccountCountsMatchReality:
    """Account totals must describe the collections they claim to count."""

    def test_number_of_users_matches_the_user_list(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        account = client.get(f"{PREFIX}/accounts", headers=auth_headers).json()["data"][0]
        users = client.get(f"{PREFIX}/users", headers=auth_headers).json()

        assert account["numberOfUsers"] == users["pagination"]["totalItems"]


class TestQuarantinedFilesReferenceRealDetections:
    """A quarantined file is produced by a detection, so the id must resolve."""

    def test_detect_ids_are_real_detection_ids(self, client: TestClient) -> None:
        token = client.post("/cs/oauth2/token", data={
            "client_id": "cs-mock-admin-client",
            "client_secret": "cs-mock-admin-secret",
        }).json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        files = client.get(
            "/cs/quarantine/queries/quarantined-files/v1", headers=headers,
        ).json()["resources"]
        detail = client.get(
            f"/cs/quarantine/entities/quarantined-files/v1?ids={','.join(files)}",
            headers=headers,
        ).json()["resources"]

        detect_ids = [d for record in detail for d in record.get("detect_ids", [])]
        assert detect_ids, "nothing exercised — seeder stopped emitting detect_ids"

        known = set(client.get(
            "/cs/alerts/queries/alerts/v2?limit=500", headers=headers,
        ).json()["resources"])
        dangling = [d for d in detect_ids if d not in known]
        assert not dangling, f"quarantined files cite unknown detections: {dangling[:3]}"


class TestExposureCountsMatchMembership:
    """``exposedMachines`` must equal the machineReferences it summarises."""

    def test_software_counts_agree(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        for software in client.get("/mde/api/software", headers=headers).json()["value"]:
            refs = client.get(
                f"/mde/api/software/{software['softwareId']}/machineReferences",
                headers=headers,
            ).json()["value"]
            assert software["exposedMachines"] == len(refs), software["name"]

    def test_vulnerability_counts_agree(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        vulns = client.get("/mde/api/vulnerabilities", headers=headers).json()["value"]
        for vuln in vulns:
            refs = client.get(
                f"/mde/api/vulnerabilities/{vuln['vulnerabilityId']}/machineReferences",
                headers=headers,
            ).json()["value"]
            assert vuln["exposedMachines"] == len(refs), vuln["name"]
