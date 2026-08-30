"""A STAR rule's own counters must agree with the alerts this mock holds.

Nothing set `generatedAlerts`, `lastAlertTime`, `creatorId` or `updaterId`,
so the completion filled all four from the swagger's examples: every one of
the twenty rules answered `generatedAlerts: 0` and
`lastAlertTime: "2018-02-27T04:49:26.257525Z"` while each of them had an
alert seeded within the last few weeks, and both id fields carried the
swagger's example user id, which resolves to nobody. A console reading this
shows twenty rules that have never fired, in an estate where each has.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"


def _rules(client: TestClient, headers: dict) -> list[dict]:
    response = client.get(f"{BASE}/cloud-detection/rules", headers=headers, params={"limit": 100})
    assert response.status_code == 200, response.text
    return response.json()["data"]


def _alerts(client: TestClient, headers: dict) -> list[dict]:
    response = client.get(
        f"{BASE}/cloud-detection/alerts", headers=headers, params={"limit": 1000},
    )
    assert response.status_code == 200, response.text
    return response.json()["data"]


class TestARuleCountsTheAlertsItGenerated:
    def test_generated_alerts_is_the_number_this_mock_holds(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        alerts = _alerts(client, auth_headers)
        per_rule: dict[str, int] = {}
        for alert in alerts:
            rule_id = alert.get("ruleInfo", {}).get("id")
            if rule_id:
                per_rule[rule_id] = per_rule.get(rule_id, 0) + 1
        assert per_rule, "no alert names a rule, so this proves nothing"

        wrong = [
            f"{rule['id']}: says {rule.get('generatedAlerts')}, holds {per_rule[rule['id']]}"
            for rule in _rules(client, auth_headers)
            if rule["id"] in per_rule and rule.get("generatedAlerts") != per_rule[rule["id"]]
        ]
        assert not wrong, wrong

    def test_the_last_alert_time_is_not_the_swaggers_example(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        """One 2018 timestamp for every rule was the tell."""
        stamps = {rule.get("lastAlertTime") for rule in _rules(client, auth_headers)}
        assert "2018-02-27T04:49:26.257525Z" not in stamps
        assert len(stamps) > 1, f"every rule reports the same last alert: {stamps}"

    def test_the_author_resolves_to_a_user_this_mock_serves(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        users = {
            u["id"]
            for u in client.get(f"{BASE}/users", headers=auth_headers,
                                params={"limit": 100}).json()["data"]
        }
        for rule in _rules(client, auth_headers):
            assert rule.get("creatorId") in users, rule.get("creatorId")
            assert rule.get("updaterId") in users, rule.get("updaterId")
