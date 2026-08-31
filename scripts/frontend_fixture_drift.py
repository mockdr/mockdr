# ruff: noqa: ANN001, ANN201, ANN202, D103, E402, PLR2004, S101, T201
# A release tool, not library code: every function is local to this file and
# sys.path is set before the project imports on purpose.
"""Do the frontend's captured fixtures still match what the mock answers?

A unit test that mounts a view over a hand-written mock of its API is only
as true as the guess in that mock, and one of them guessed wrong:
`AlertsView`'s fixture gave `agentRealtimeInfo` an object where the product
answers `null`. The view read a property off null, rendered nothing at all,
and 2 103 unit tests passed over a page that was blank against the real
backend.

`scripts/gen_graph_fixtures.py` captures the Graph console's answers from the
mock instead of guessing them. Captured is not the same as current, though —
a fixture written once rots exactly like a hand-written one. This reads the
file back and asks the mock the same questions again, comparing the *shape*:
which keys a record carries, and which of them are null.

Values are not compared. They are seeded from a random draw and change on
every restart, so comparing them would report noise. A key that appears, a
key that disappears and a key that turns null are the changes that break a
view, and those are what this reports.

    backend/.venv/bin/python scripts/frontend_fixture_drift.py
"""

import json
import logging
import sys
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = (
    ROOT / "frontend" / "src" / "views" / "__tests__" / "graph"
    / "__fixtures__" / "graph-responses.json"
)


def shape(body: object) -> tuple[frozenset, frozenset]:
    """The keys a collection's first record carries, and which are null."""
    if not isinstance(body, dict):
        return frozenset(), frozenset()
    record: object = body
    values = body.get("value")
    if isinstance(values, list):
        if not values:
            return frozenset(), frozenset()
        record = values[0]
    if not isinstance(record, dict):
        return frozenset(), frozenset()
    keys = frozenset(record)
    empty = frozenset(k for k, v in record.items() if v is None)
    return keys, empty


def main() -> int:
    """Compare every captured answer with the one the mock gives now."""
    if not FIXTURES.exists():
        print(f"{FIXTURES.relative_to(ROOT)} is missing — run scripts/gen_graph_fixtures.py")
        return 2

    logging.disable(logging.CRITICAL)
    warnings.filterwarnings("ignore")
    sys.path.insert(0, str(ROOT / "backend"))
    from fastapi.testclient import TestClient  # noqa: PLC0415
    from main import app  # noqa: PLC0415

    captured = json.loads(FIXTURES.read_text())
    findings: list[str] = []
    checked = 0

    with TestClient(app) as client:
        token = client.post("/graph/oauth2/v2.0/token", data={
            "client_id": "graph-mock-admin-client",
            "client_secret": "graph-mock-admin-secret",
            "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default",
        })
        if token.status_code != 200:
            print(f"the token call answered {token.status_code}")
            return 2
        headers = {"Authorization": f"Bearer {token.json()['access_token']}"}

        # Resolved from the mock as it stands, not from the file: ids come
        # from `secrets.randbelow` and cannot be seeded, so every one of them
        # changes on every restart. Reading them out of the capture made
        # every `{id}` path report "the mock answers 404 now" after any
        # reseed — a check that always fires is one nobody believes.
        ids: dict[str, str] = {}
        for path in captured:
            if "{id}" in path:
                continue
            answer = client.get(f"/graph{path}", headers=headers)
            if answer.status_code != 200:
                continue
            values = answer.json().get("value")
            if isinstance(values, list) and values and isinstance(values[0], dict):
                ids[path] = str(values[0].get("id", ""))

        for path, body in sorted(captured.items()):
            asked = path
            if "{id}" in path:
                # The collection this template's id came from is its own prefix.
                source = next(
                    (p for p in ids if path.startswith(p + "/") or path == p + "/{id}"), "",
                )
                record_id = ids.get(source, "")
                if not record_id:
                    findings.append(f"{path}: no id to resolve it with any more")
                    continue
                asked = path.replace("{id}", record_id)

            answer = client.get(f"/graph{asked}", headers=headers)
            checked += 1
            if answer.status_code != 200:
                findings.append(f"{path}: the mock answers {answer.status_code} now")
                continue

            was_keys, was_null = shape(body)
            now_keys, now_null = shape(answer.json())
            if not was_keys and not now_keys:
                continue
            gone = sorted(was_keys - now_keys)
            new = sorted(now_keys - was_keys)
            shared = was_keys & now_keys
            nulled = sorted((now_null - was_null) & shared)
            # Both directions. The defect that started all of this was a
            # fixture claiming an object where the product answers null, so
            # checking only "the mock started answering null" would miss the
            # very case it exists for.
            filled = sorted((was_null - now_null) & shared)
            if gone:
                findings.append(f"{path}: no longer carries {gone}")
            if new:
                findings.append(f"{path}: now also carries {new}")
            if nulled:
                findings.append(f"{path}: the mock answers null for {nulled}, the fixture does not")
            if filled:
                findings.append(f"{path}: the fixture says null for {filled}, the mock does not")

    print(f"=== FIXTURE DRIFT === {checked} captured answer(s) re-asked\n")
    print(f"  {len(findings)} that no longer match what the mock gives")
    for finding in findings:
        print(f"      {finding}")
    if findings:
        print("\n  run scripts/gen_graph_fixtures.py, then look at what changed")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
