# ruff: noqa: ANN001, ANN003, ANN201, ANN202, D103, E402, S101, T201
# A release tool, not library code: every function is local to this file and
# sys.path is set before the project imports on purpose.
"""Time has to run forwards, in every record this mock serves.

Every other check here asks whether a field is *shaped* right. This asks
whether the story it tells is possible. A threat updated five days before it
was detected is well-formed JSON, passes every schema, and makes a console
draw a timeline that runs backwards — or a "time to triage" that comes out
negative.

Nine pairs were wrong when this was written, in six seeders, all from the
same habit: drawing the two moments independently.

    threats        createdAt / identifiedAt   >  updatedAt        3 of 30
    cloud alerts   alertInfo.createdAt        >  updatedAt        4 of 40
    CrowdStrike    created_on                 >  modified_on      2
    Defender       creationTimeDateTimeUtc    >  lastUpdateTime   2
    Defender       investigation startTime    >  endTime          2
    SentinelOne    IOC creationTime           >  updatedAt        1
    agents         registeredAt               >  lastScan…        1
    Graph users    createdDateTime            >  lastSignIn…      1
    Graph incident createdDateTime            >  lastUpdate…      1

`infrastructure/seeders/_shared.rand_after` exists for exactly this and was
written for an earlier round of it; six seeders had not been told.

Only pairs where both names describe the *same subject* are judged. A file
modified before the alert that mentions it is ordinary — the file is older
than the alert — and so is a machine that rebooted since its last scan, so
neither is here. What is here is a record disagreeing with itself.

    backend/.venv/bin/python scripts/causality_audit.py

Exit status 1 when anything is flagged.
"""
from __future__ import annotations

import re
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

import logging

logging.disable(logging.CRITICAL)

from fastapi.testclient import TestClient  # noqa: E402
from main import app  # noqa: E402

#: (collection, the earlier field, the later field). Both names describe one
#: subject, so the order between them is the record's own claim.
ORDERED: tuple[tuple[str, str, str], ...] = (
    ("/web/api/v2.1/threats", "threatInfo.createdAt", "threatInfo.updatedAt"),
    ("/web/api/v2.1/threats", "threatInfo.identifiedAt", "threatInfo.updatedAt"),
    ("/web/api/v2.1/agents", "registeredAt", "lastActiveDate"),
    ("/web/api/v2.1/agents", "registeredAt", "lastSuccessfulScanDate"),
    ("/web/api/v2.1/agents", "registeredAt", "fullDiskScanLastUpdatedAt"),
    ("/web/api/v2.1/agents", "createdAt", "updatedAt"),
    ("/web/api/v2.1/agents", "scanStartedAt", "scanFinishedAt"),
    ("/web/api/v2.1/cloud-detection/alerts",
     "alertInfo.createdAt", "alertInfo.updatedAt"),
    ("/web/api/v2.1/threat-intelligence/iocs", "creationTime", "updatedAt"),
    ("/cs/iocs/combined/indicator/v1", "created_on", "modified_on"),
    ("/mde/api/indicators", "creationTimeDateTimeUtc", "lastUpdateTime"),
    ("/mde/api/alerts", "alertCreationTime", "lastUpdateTime"),
    ("/mde/api/investigations", "startTime", "endTime"),
    ("/graph/v1.0/users", "createdDateTime", "signInActivity.lastSignInDateTime"),
    ("/graph/v1.0/users", "createdDateTime",
     "signInActivity.lastNonInteractiveSignInDateTime"),
    ("/graph/v1.0/security/incidents", "createdDateTime", "lastUpdateDateTime"),
    ("/graph/v1.0/security/alerts_v2", "createdDateTime", "lastUpdateDateTime"),
    ("/graph/v1.0/security/alerts_v2",
     "firstActivityDateTime", "lastActivityDateTime"),
)

_STAMP = re.compile(r"^\d{4}-\d\d-\d\dT")


def moment(value):
    """`value` as a datetime, or None when it is not a timestamp."""
    if not isinstance(value, str) or not _STAMP.match(value):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def reach(record, path):
    """The value at a dotted path, or None."""
    node = record
    for part in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def collection(body):
    """The records in a vendor's list envelope, whatever it calls the list."""
    if isinstance(body, list):
        return body
    if not isinstance(body, dict):
        return []
    for key in ("data", "value", "resources", "results"):
        found = body.get(key)
        if isinstance(found, list):
            return found
    return []


def tokens(client):
    """A bearer for each mount that wants one."""
    def grant(path, **kwargs):
        return client.post(path, **kwargs).json().get("access_token")

    return {
        "/web": {"Authorization": "ApiToken admin-token-0000-0000-000000000001"},
        "/cs": {"Authorization": "Bearer " + str(grant(
            "/cs/oauth2/token", data={
                "client_id": "cs-mock-admin-client",
                "client_secret": "cs-mock-admin-secret"}))},
        "/mde": {"Authorization": "Bearer " + str(grant(
            "/mde/oauth2/v2.0/token", data={
                "grant_type": "client_credentials",
                "client_id": "mde-mock-admin-client",
                "client_secret": "mde-mock-admin-secret",
                "scope": "https://api.securitycenter.microsoft.com/.default"}))},
        "/graph": {"Authorization": "Bearer " + str(grant(
            "/graph/oauth2/v2.0/token", data={
                "grant_type": "client_credentials",
                "client_id": "graph-mock-admin-client",
                "client_secret": "graph-mock-admin-secret",
                "scope": "https://graph.microsoft.com/.default"}))},
    }


def main() -> int:
    with TestClient(app) as client:
        auth = tokens(client)
        checked = 0
        findings: list[str] = []
        empty: list[str] = []
        for path, earlier, later in ORDERED:
            mount = next((m for m in auth if path.startswith(m)), None)
            if mount is None:
                continue
            response = client.get(path, headers=auth[mount], params={"limit": 200})
            if response.status_code != 200:
                empty.append(f"{path} answered {response.status_code}")
                continue
            records = collection(response.json())
            pairs = backwards = 0
            worst = None
            for record in records:
                if not isinstance(record, dict):
                    continue
                first, second = moment(reach(record, earlier)), moment(reach(record, later))
                if first is None or second is None:
                    continue
                pairs += 1
                checked += 1
                if first > second:
                    backwards += 1
                    gap = first - second
                    if worst is None or gap > worst[0]:
                        worst = (gap, record.get("id"))
            if not pairs:
                empty.append(f"{path}: no record carries both {earlier} and {later}")
            elif backwards:
                findings.append(
                    f"  {path.replace('/web/api/v2.1', '/web')} "
                    f"{earlier} > {later}: {backwards} of {pairs}"
                    + (f", worst {worst[0].days}d on {worst[1]}" if worst else ""))

    print(f"=== CAUSALITY === {checked} ordered pair(s) read "
          f"across {len(ORDERED)} claim(s)")
    for line in findings:
        print(line)
    if empty:
        print(f"\n  {len(empty)} claim(s) nothing could be read for:")
        for line in empty:
            print(f"      {line}")
    print(f"\n  {len(findings)} pair(s) where a record disagrees with itself")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
