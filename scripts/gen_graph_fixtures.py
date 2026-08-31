# ruff: noqa: ANN001, ANN201, ANN202, D103, E402, PLR2004, S101, T201
# A release tool, not library code: every function is local to this file and
# sys.path is set before the project imports on purpose.
"""Capture the Graph console's own requests as test fixtures.

Every unit test of this frontend mounts a view over a hand-written mock of
its API, and a hand-written mock is a guess at what the backend answers. One
of them guessed wrong: `AlertsView`'s fixture gave `agentRealtimeInfo` an
object where the product answers `null`, so the view read a property off
null, rendered nothing at all, and 2 103 unit tests went on passing over a
page that was blank against the real thing.

The Graph console had no unit tests at all — 24 views, its store and its API
client — and all three defects the end-to-end sweep found on the day it was
strengthened were in it. Testing it with more hand-written fixtures would
repeat the mistake that hid the first one, so these are captured from the
mock instead: this asks the running backend exactly what the console asks
it, and writes the answers down.

The companion check is `scripts/frontend_fixture_drift.py`, which reads the
file back and compares it with the mock again. A fixture that stops matching
is then a failure rather than a quiet lie.

    backend/.venv/bin/python scripts/gen_graph_fixtures.py
"""

import json
import logging
import sys
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "frontend" / "src" / "views" / "__tests__" / "graph" / "__fixtures__"

#: Every static path the console asks Graph for, read off `src/api/graph.ts`.
STATIC = [
    "/v1.0/users",
    "/v1.0/groups",
    "/v1.0/deviceManagement/managedDevices",
    "/v1.0/deviceManagement/deviceCompliancePolicies",
    "/v1.0/deviceManagement/deviceConfigurations",
    "/v1.0/deviceManagement/windowsAutopilotDeviceIdentities",
    "/v1.0/deviceAppManagement/mobileApps",
    "/v1.0/identity/conditionalAccess/policies",
    "/v1.0/identityProtection/riskyUsers",
    "/v1.0/security/alerts_v2",
    "/v1.0/security/incidents",
    "/v1.0/security/secureScores",
    "/v1.0/security/attackSimulation/simulations",
    "/v1.0/auditLogs/directoryAudits",
    "/v1.0/auditLogs/signIns",
    "/v1.0/admin/serviceAnnouncement/healthOverviews",
    "/v1.0/subscribedSkus",
    "/v1.0/teams",
    "/v1.0/sites",
    "/beta/deviceManagement/windowsAutopilotDeploymentProfiles",
    "/beta/deviceManagement/windowsUpdateForBusinessConfigurations",
]

#: Paths that need an id, and the collection to take one from.
DERIVED = [
    ("/v1.0/users/{id}", "/v1.0/users"),
    ("/v1.0/groups/{id}", "/v1.0/groups"),
    ("/v1.0/groups/{id}/members", "/v1.0/groups"),
    ("/v1.0/deviceManagement/managedDevices/{id}", "/v1.0/deviceManagement/managedDevices"),
    ("/v1.0/users/{id}/messages", "/v1.0/users"),
    ("/v1.0/users/{id}/mailFolders", "/v1.0/users"),
    ("/v1.0/users/{id}/drive", "/v1.0/users"),
    ("/v1.0/users/{id}/drive/root/children", "/v1.0/users"),
    ("/v1.0/teams/{id}/channels", "/v1.0/teams"),
]


def first_id(body: object) -> str:
    """The first record's id in an OData collection, or an empty string."""
    values = body.get("value") if isinstance(body, dict) else None
    if isinstance(values, list) and values and isinstance(values[0], dict):
        return str(values[0].get("id", ""))
    return ""


def main() -> int:
    """Ask the mock what the console asks it, and write the answers down."""
    logging.disable(logging.CRITICAL)
    warnings.filterwarnings("ignore")
    sys.path.insert(0, str(ROOT / "backend"))
    from fastapi.testclient import TestClient  # noqa: PLC0415
    from main import app  # noqa: PLC0415

    captured: dict[str, object] = {}
    with TestClient(app) as client:
        token = client.post("/graph/oauth2/v2.0/token", data={
            "client_id": "graph-mock-admin-client",
            "client_secret": "graph-mock-admin-secret",
            "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default",
        })
        if token.status_code != 200:
            print(f"the token call answered {token.status_code}: {token.text[:120]}")
            return 2
        headers = {"Authorization": f"Bearer {token.json()['access_token']}"}

        for path in STATIC:
            answer = client.get(f"/graph{path}", headers=headers)
            if answer.status_code != 200:
                print(f"  !  {path} answered {answer.status_code}")
                continue
            captured[path] = answer.json()

        for template, collection in DERIVED:
            source = captured.get(collection)
            record_id = first_id(source) if source else ""
            if not record_id:
                print(f"  !  {template}: {collection} gave no id to use")
                continue
            path = template.replace("{id}", record_id)
            answer = client.get(f"/graph{path}", headers=headers)
            if answer.status_code != 200:
                print(f"  !  {path} answered {answer.status_code}")
                continue
            captured[template] = answer.json()

    OUT.mkdir(parents=True, exist_ok=True)
    target = OUT / "graph-responses.json"
    target.write_text(json.dumps(captured, indent=2, sort_keys=True) + "\n")
    total = sum(
        len(v["value"]) for v in captured.values()
        if isinstance(v, dict) and isinstance(v.get("value"), list)
    )
    print(f"=== GRAPH FIXTURES === {len(captured)} path(s), {total} record(s)")
    print(f"  written to {target.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
