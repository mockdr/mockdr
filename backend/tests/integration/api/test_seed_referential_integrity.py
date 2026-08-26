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
        "scope": "https://api.securitycenter.microsoft.com/.default",
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
        detail = client.post(
            "/cs/quarantine/entities/quarantined-files/GET/v1",  # the current API takes ids in the body
            headers=headers,
            json={"ids": files},
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


class TestSeedIsReproducible:
    """``generate_all`` documents determinism; ids did not honour it."""

    def test_ids_are_stable_across_reseeds(self, client: TestClient) -> None:
        from infrastructure.seed import generate_all
        from repository.agent_repo import agent_repo

        generate_all()
        first = [(a.id, a.uuid) for a in agent_repo.list_all()[:5]]
        generate_all()
        second = [(a.id, a.uuid) for a in agent_repo.list_all()[:5]]

        # secrets.randbelow and uuid4() cannot be seeded, so every id and uuid
        # changed on every restart — breaking anything that pinned one.
        assert first == second


class TestTimestampOrdering:
    """A record's later timestamp must not precede its earlier one."""

    PAIRS = [
        ("createdAt", "updatedAt"),
        ("created_at", "updated_at"),
        ("createdDateTime", "lastModifiedDateTime"),
        ("firstEventTime", "lastEventTime"),
        ("alertCreationTime", "lastUpdateTime"),
        ("start", "end"),
        ("created_timestamp", "modified_timestamp"),
    ]

    def test_no_record_updates_before_it_was_created(self, client: TestClient) -> None:
        from dataclasses import asdict, is_dataclass

        from repository.store import store

        violations = []
        for name in store._collections:
            for record in store.get_all(name):
                data = (
                    asdict(record) if is_dataclass(record)
                    else record if isinstance(record, dict) else None
                )
                if not data:
                    continue
                for earlier, later in self.PAIRS:
                    a, b = data.get(earlier), data.get(later)
                    if isinstance(a, str) and isinstance(b, str) and a and b and a > b:
                        violations.append(f"{name}.{earlier} > {later}")

        assert not violations, f"{len(violations)} ordering violations: {violations[:5]}"


class TestLicenceCountsMatchAssignments:
    """``consumedUnits`` must describe the users who hold the licence."""

    @staticmethod
    def _graph_headers(client: TestClient) -> dict[str, str]:
        resp = client.post("/graph/oauth2/v2.0/token", data={
            "client_id": "graph-mock-admin-client",
            "client_secret": "graph-mock-admin-secret",
            "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default",
        })
        return {"Authorization": f"Bearer {resp.json()['access_token']}"}

    def test_consumed_units_match_the_user_list(self, client: TestClient) -> None:
        headers = self._graph_headers(client)
        skus = client.get("/graph/v1.0/subscribedSkus", headers=headers).json()["value"]
        users = client.get(
            "/graph/v1.0/users", headers=headers, params={"$top": 999},
        ).json()["value"]

        held: dict[str, int] = {}
        for user in users:
            for licence in user.get("assignedLicenses") or []:
                sku_id = licence.get("skuId", "")
                held[sku_id] = held.get(sku_id, 0) + 1

        for sku in skus:
            assert sku["consumedUnits"] == held.get(sku["skuId"], 0), sku["skuPartNumber"]

    def test_no_subscription_is_oversubscribed(self, client: TestClient) -> None:
        skus = client.get(
            "/graph/v1.0/subscribedSkus", headers=self._graph_headers(client),
        ).json()["value"]

        for sku in skus:
            # Two SKUs described tenants consuming more seats than they bought.
            assert sku["consumedUnits"] <= sku["prepaidUnits"]["enabled"], (
                sku["skuPartNumber"]
            )


class TestManagedDeviceUsersExist:
    """A device's primary user must be a real directory user."""

    def test_every_device_upn_resolves(self, client: TestClient) -> None:
        resp = client.post("/graph/oauth2/v2.0/token", data={
            "client_id": "graph-mock-admin-client",
            "client_secret": "graph-mock-admin-secret",
            "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default",
        })
        headers = {"Authorization": f"Bearer {resp.json()['access_token']}"}

        upns = {
            u["userPrincipalName"] for u in client.get(
                "/graph/v1.0/users", headers=headers, params={"$top": 999},
            ).json()["value"]
        }
        devices = client.get(
            "/graph/v1.0/deviceManagement/managedDevices",
            headers=headers, params={"$top": 999},
        ).json()["value"]

        dangling = [
            d["deviceName"] for d in devices
            if d.get("userPrincipalName") not in upns
        ]
        assert not dangling, f"devices whose user does not exist: {dangling[:5]}"


class TestCasesReferenceRealAlerts:
    """``total_alerts`` counts alerts the case actually references."""

    def test_case_alert_ids_resolve(self, client: TestClient) -> None:
        from repository.es_alert_repo import es_alert_repo
        from repository.es_case_repo import es_case_repo

        known = {a.id for a in es_alert_repo.list_all()}
        cases = es_case_repo.list_all()

        assert cases
        for case in cases:
            assert len(case.alert_ids) == case.total_alerts
            assert all(alert_id in known for alert_id in case.alert_ids)
