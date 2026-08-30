# ruff: noqa: ANN001, ANN201, ANN202, D103, E402, PLR2004, S101, T201
# A release tool, not library code: every function is local to this file and
# sys.path is set before the project imports on purpose.
"""Ask every write route whether the members it accepts do anything.

`body_audit.py` asks whether a route *reads* its body — whether it refuses
`{}` and a member it does not declare. That is a different question from
whether the members it does accept are *applied*, and the gap between them
was wide: `PUT /tenant/policy` refused both of those bodies and then ignored
43 of the 51 members the swagger documents, so a client turning on
anti-tampering was answered 200 and read back the value it had before. Three
creates and three updates dropped fourteen more between them, and
`PUT /sites/{id}/reactivate` cleared the expiration it was handed.

None of it was visible to a client that re-reads, either: the answer came
from the fixture completion, which never changes.

Each route is sent every member of its documented body, typed from the
swagger's own schema, and the answer is compared member by member. Two kinds
of difference are not findings, and both are listed in the script rather
than guessed at:

* **server-owned** — `id`, `createdAt`, `updatedAt` and who last acted. A
  route that let a client set these would let it rewrite its own audit
  trail;
* **write-only** — a password or a one-time code, which must never come back.

A member the response schema does not declare is reported separately: it is
not wrong for a create to accept something it does not echo, but the number
belongs in the open.

Only SentinelOne is covered, and by measurement rather than choice: it is
the one vendor whose reference gives body schemas with types. The
CrowdStrike and Cortex references name their members and not their types, so
a generated body would be a guess, and a guess that answers 400 measures the
guess.

    backend/.venv/bin/python scripts/write_effect.py
    backend/.venv/bin/python scripts/write_effect.py --verbose
"""

import json
import logging
import re
import sys
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SWAGGER = ROOT / "data" / "swagger_2_1.json"
BASE = "/web/api/v2.1"

#: Members the server owns. A client may send them; the record must not take
#: them from the body.
SERVER_OWNED = frozenset({
    "id", "createdAt", "updatedAt", "userId", "userFullName", "creator",
    "creatorId", "updater", "updaterId", "siteId", "accountId", "scopeId",
    "isDefault", "inheritedFrom", "source", "state",
})

#: Members that must never appear in an answer.
WRITE_ONLY = frozenset({"password", "currentPassword", "twoFaCode", "apiToken"})

#: Members that cannot be sent alongside the rest, with the reason. Sending
#: every member of a body at once is the point of this audit, and these are
#: the places where two of them contradict each other by design.
EXCLUSIVE: dict[tuple[str, str], frozenset[str]] = {
    # `unlimited` reads "if false an expiration should be supplied", so
    # sending both and then reporting that the expiration was ignored would
    # be reporting the route obeying its own documentation.
    ("PUT", "/sites/{site_id}/reactivate"): frozenset({"unlimited"}),
}


def load_spec() -> dict:
    """The vendored 2.1 swagger, or an empty spec when it has not been fetched."""
    if not SWAGGER.exists():
        return {}
    return json.loads(SWAGGER.read_text())


def resolve(spec: dict, node: object, depth: int = 0) -> dict:
    """Follow `$ref` until it lands on a schema, or give up."""
    while isinstance(node, dict) and "$ref" in node and depth < 5:
        node = spec.get("definitions", {}).get(node["$ref"].split("/")[-1], {})
        depth += 1
    return node if isinstance(node, dict) else {}


def value_for(name: str, decl: dict) -> object | None:
    """A value of the declared type, distinguishable from any default."""
    kind = decl.get("type")
    if kind == "string":
        enum = decl.get("enum")
        if enum:
            return enum[-1]
        example = decl.get("example")
        if isinstance(example, str) and "T" in example and ":" in example:
            return "2026-02-03T04:05:06.000000Z"
        return f"zzz-{name}"
    if kind == "integer":
        return 8765
    if kind == "number":
        return 87.65
    if kind == "boolean":
        return True
    return None


def body_members(spec: dict, operation: dict) -> dict:
    """The typed members of a route's documented `data` payload."""
    parameter = next(
        (p for p in operation.get("parameters", []) or [] if p.get("in") == "body"), None,
    )
    if parameter is None:
        return {}
    schema = resolve(spec, parameter.get("schema", {}))
    payload = resolve(spec, schema.get("properties", {}).get("data", {}))
    return payload.get("properties", {})


def answered_members(spec: dict, operation: dict) -> set:
    """What the route's own 200 schema says it answers."""
    schema = ((operation.get("responses", {}).get("200") or {}).get("schema") or {})
    definition = resolve(spec, schema)
    payload = definition.get("properties", {}).get("data", {})
    payload = resolve(spec, payload.get("items", payload))
    return set(payload.get("properties", {}))


def records(body: object) -> list:
    """The records in an answer, whatever envelope it wears."""
    payload = body.get("data") if isinstance(body, dict) else None
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        # The payload is the record itself when it carries an id. Descending
        # into the first nested list found here compared a user's answer with
        # one of its own `scopeRoles`, and reported every member as missing.
        if "id" in payload:
            return [payload]
        for value in payload.values():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                return value
        return [payload]
    return []


def main() -> int:
    """Send every documented member to every write route and read the answer."""
    verbose = "--verbose" in sys.argv
    spec = load_spec()
    if not spec:
        print(f"{SWAGGER.relative_to(ROOT)} is missing — run scripts/fetch_swagger.sh")
        return 2

    logging.disable(logging.CRITICAL)
    warnings.filterwarnings("ignore")
    sys.path.insert(0, str(ROOT / "backend"))
    from fastapi.testclient import TestClient  # noqa: PLC0415
    from main import app  # noqa: PLC0415

    headers = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}
    dropped: list[tuple[str, str, str]] = []
    unechoed: list[tuple[str, str]] = []
    routes = 0

    with TestClient(app) as client:
        mock = app.openapi()["paths"]

        def an_id(collection: str) -> str:
            answer = client.get(collection, headers=headers, params={"limit": 5})
            if answer.status_code != 200:
                return ""
            for record in records(answer.json()):
                if record.get("id"):
                    return str(record["id"])
            return ""

        for path, operations in spec.get("paths", {}).items():
            if not path.startswith(BASE):
                continue
            placeholders = re.findall(r"\{([^}]+)\}", path)
            if len(placeholders) > 1:
                continue
            for method in ("post", "put", "patch"):
                operation = operations.get(method)
                if not operation or method not in mock.get(path, {}):
                    continue
                members = body_members(spec, operation)
                if not members:
                    continue
                url = path
                if placeholders:
                    collection = path[: path.index("{") - 1]
                    found = an_id(collection)
                    if not found:
                        continue
                    url = path.replace("{" + placeholders[0] + "}", found)
                exclusive = EXCLUSIVE.get((method.upper(), path[len(BASE):]), frozenset())
                sent = {
                    name: value
                    for name, declaration in members.items()
                    if name not in exclusive
                    and (value := value_for(name, resolve(spec, declaration))) is not None
                }
                if not sent:
                    continue
                routes += 1
                answer = client.request(method.upper(), url, headers=headers,
                                        json={"data": sent})
                if answer.status_code not in (200, 201):
                    continue
                found_records = records(answer.json())
                if not found_records:
                    continue
                record = found_records[0]
                declared = answered_members(spec, operation)
                for name, value in sent.items():
                    if name in SERVER_OWNED or name in WRITE_ONLY:
                        continue
                    if name not in record:
                        if declared and name in declared:
                            dropped.append((f"{method.upper()} {path[len(BASE):]}",
                                            name, "absent from an answer that declares it"))
                        else:
                            unechoed.append((f"{method.upper()} {path[len(BASE):]}", name))
                    elif record[name] != value:
                        dropped.append((f"{method.upper()} {path[len(BASE):]}", name,
                                        f"sent {value!r}, answered {record[name]!r}"))

    print(f"=== WRITE EFFECT === {routes} write route(s) sent every member they document\n")
    print(f"  {len(dropped)} member(s) a route accepted and did not apply")
    for route, name, why in sorted(dropped):
        print(f"      {route:36} {name:24} {why}")
    print(f"  {len(unechoed)} member(s) the response schema does not declare, so not judged")
    if verbose:
        for route, name in sorted(unechoed):
            print(f"      {route:36} {name}")
    return 1 if dropped else 0


if __name__ == "__main__":
    raise SystemExit(main())
