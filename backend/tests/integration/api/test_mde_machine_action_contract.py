"""A Defender machine action is created, needs its Comment, and runs one at a time.

Every action page on learn.microsoft.com/en-us/defender-endpoint/api/ --
isolate-machine, unisolate-machine, run-av-scan, restrict-code-execution,
unrestrict-code-execution, collect-investigation-package, run-live-response --
says the call "returns 201 - Created". The mock answered 200, so a client
checking for 201 (the generated SDKs do) treated every success as a failure.

`Comment` is "Required" on all of them but live response, and the body is
case-sensitive ("The submitted body parameters are currently case-sensitive",
https://learn.microsoft.com/en-us/defender-endpoint/api/common-errors); a
missing one is `400 MissingRequiredParameter`. `IsolationType` allows "Full,
Selective, or UnManagedDevice" and `ScanType` (Required) "Quick" or "Full".
The mock took anything, and stored an empty comment.

And a second action of a kind while the first is pending: "it returns ...
HTTP 400 with the message 'Action is already in progress'" (unisolate,
run-av-scan, restrict, unrestrict pages), and for live response "HTTP 400 -
ActiveRequestAlreadyExists". The mock queued as many as it was sent.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

ACTIONS = [
    ("isolate", {"IsolationType": "Full"}),
    ("unisolate", {}),
    ("runAntiVirusScan", {"ScanType": "Quick"}),
    ("restrictCodeExecution", {}),
    ("unrestrictCodeExecution", {}),
    ("collectInvestigationPackage", {}),
]


@pytest.fixture()
def mde_headers(client: TestClient) -> dict[str, str]:
    token = client.post("/mde/oauth2/v2.0/token", data={
        "client_id": "mde-mock-admin-client",
        "client_secret": "mde-mock-admin-secret",
        "grant_type": "client_credentials",
        "scope": "https://api.securitycenter.microsoft.com/.default",
    }).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _machines(client: TestClient, headers: dict[str, str]) -> list[str]:
    return [m["id"] for m in client.get("/mde/api/machines", headers=headers,
                                        params={"$top": 50}).json()["value"]]


class TestActionsAreCreated:
    """Each documented action answers 201 with the machine action."""

    @pytest.mark.parametrize(("action", "extra"), ACTIONS)
    def test_action_answers_201(
        self, client: TestClient, mde_headers: dict[str, str], action: str, extra: dict,
    ) -> None:
        machine_id = _machines(client, mde_headers)[0]
        response = client.post(f"/mde/api/machines/{machine_id}/{action}", headers=mde_headers,
                               json={"Comment": "zzz contract", **extra})
        assert response.status_code == 201, response.text
        assert response.json()["status"] == "Pending"

    def test_live_response_answers_201(
        self, client: TestClient, mde_headers: dict[str, str],
    ) -> None:
        machine_id = _machines(client, mde_headers)[1]
        response = client.post(
            f"/mde/api/machines/{machine_id}/runliveresponse", headers=mde_headers,
            json={"Commands": [{"type": "GetFile", "params": [{"key": "Path", "value": "C:\\\\x"}]}],
                  "Comment": "zzz"},
        )
        assert response.status_code == 201, response.text


class TestCommentIsRequired:
    """No `Comment` -- or `comment` in the wrong case -- is MissingRequiredParameter."""

    @pytest.mark.parametrize(("action", "extra"), ACTIONS)
    def test_missing_comment_is_refused(
        self, client: TestClient, mde_headers: dict[str, str], action: str, extra: dict,
    ) -> None:
        machine_id = _machines(client, mde_headers)[2]
        response = client.post(f"/mde/api/machines/{machine_id}/{action}",
                               headers=mde_headers, json=extra)
        assert response.status_code == 400
        error = response.json()["error"]
        assert error["code"] == "MissingRequiredParameter"
        assert "Comment" in error["message"]

    def test_lowercase_comment_is_not_comment(
        self, client: TestClient, mde_headers: dict[str, str],
    ) -> None:
        machine_id = _machines(client, mde_headers)[2]
        response = client.post(f"/mde/api/machines/{machine_id}/isolate", headers=mde_headers,
                               json={"comment": "case matters", "IsolationType": "Full"})
        assert response.status_code == 400

    def test_a_refused_isolation_changes_nothing(
        self, client: TestClient, mde_headers: dict[str, str],
    ) -> None:
        machine_id = _machines(client, mde_headers)[3]
        before = client.get(f"/mde/api/machines/{machine_id}", headers=mde_headers).json()
        client.post(f"/mde/api/machines/{machine_id}/isolate", headers=mde_headers,
                    json={"IsolationType": "Full"})
        after = client.get(f"/mde/api/machines/{machine_id}", headers=mde_headers).json()
        assert after["healthStatus"] == before["healthStatus"]


class TestEnumeratedMembers:
    """`IsolationType` and `ScanType` take only their documented values."""

    def test_unknown_isolation_type_is_refused(
        self, client: TestClient, mde_headers: dict[str, str],
    ) -> None:
        machine_id = _machines(client, mde_headers)[4]
        response = client.post(f"/mde/api/machines/{machine_id}/isolate", headers=mde_headers,
                               json={"Comment": "x", "IsolationType": "Partial"})
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "InvalidRequestBody"

    def test_scan_type_is_required(
        self, client: TestClient, mde_headers: dict[str, str],
    ) -> None:
        machine_id = _machines(client, mde_headers)[5]
        response = client.post(f"/mde/api/machines/{machine_id}/runAntiVirusScan",
                               headers=mde_headers, json={"Comment": "x"})
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "MissingRequiredParameter"

    def test_unknown_scan_type_is_refused(
        self, client: TestClient, mde_headers: dict[str, str],
    ) -> None:
        machine_id = _machines(client, mde_headers)[5]
        response = client.post(f"/mde/api/machines/{machine_id}/runAntiVirusScan",
                               headers=mde_headers, json={"Comment": "x", "ScanType": "Deep"})
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "InvalidRequestBody"


class TestOneActionOfAKindAtATime:
    """A second action of the same type while the first is pending is refused."""

    @pytest.mark.parametrize("action,extra", [
        ("runAntiVirusScan", {"ScanType": "Full"}),
        ("collectInvestigationPackage", {}),
        ("restrictCodeExecution", {}),
    ])
    def test_the_second_is_active_request_already_exists(
        self, client: TestClient, mde_headers: dict[str, str], action: str, extra: dict,
    ) -> None:
        machine_id = _machines(client, mde_headers)[6]
        body = {"Comment": "zzz first", **extra}
        first = client.post(f"/mde/api/machines/{machine_id}/{action}",
                            headers=mde_headers, json=body)
        assert first.status_code == 201
        second = client.post(f"/mde/api/machines/{machine_id}/{action}",
                             headers=mde_headers, json=body)
        assert second.status_code == 400
        assert second.json()["error"]["code"] == "ActiveRequestAlreadyExists"
        assert second.json()["error"]["message"] == "Action is already in progress"

    def test_another_machine_is_not_blocked(
        self, client: TestClient, mde_headers: dict[str, str],
    ) -> None:
        first_id, other_id = _machines(client, mde_headers)[7:9]
        body = {"Comment": "zzz", "ScanType": "Quick"}
        assert client.post(f"/mde/api/machines/{first_id}/runAntiVirusScan",
                           headers=mde_headers, json=body).status_code == 201
        assert client.post(f"/mde/api/machines/{other_id}/runAntiVirusScan",
                           headers=mde_headers, json=body).status_code == 201
