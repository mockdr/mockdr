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
    if kind == "array":
        # An array member the generator could not value was left out, and a
        # route whose reference marks that member required refused the whole
        # body -- `data.hashes`, `data.events` and `data.value` among them,
        # so five routes were never judged at all.
        item = decl.get("items") or {}
        inner = value_for(name, item)
        return [inner] if inner is not None else None
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


def wants_filter(spec: dict, operation: dict) -> bool:
    """Whether the route's own reference marks `filter` required.

    Almost every SentinelOne action takes `data` and `filter` together, and a
    sweep that sends only `data` is refused before anything it wanted to
    measure is reached.
    """
    parameter = next(
        (p for p in operation.get("parameters", []) or [] if p.get("in") == "body"), None,
    )
    if parameter is None:
        return False
    schema = resolve(spec, parameter.get("schema", {}))
    return "filter" in (schema.get("required") or [])


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
    refused: list[str] = []
    unechoed: list[tuple[str, str]] = []
    routes = 0
    #: Why a documented write was not exercised. Without this the headline
    #: says 25 and nothing says of how many -- and 25 of 286 is a sample,
    #: not a sweep.
    skipped = {
        "two path parameters to fill": 0, "the mock does not serve it": 0,
        "the swagger types no body member": 0, "no id to address it with": 0,
        "no member could be given a value": 0,
        "the answer carried no record to compare": 0,
    }

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
                for method in ("post", "put", "patch"):
                    if operations.get(method) and method in mock.get(path, {}):
                        skipped["two path parameters to fill"] += 1
                continue
            for method in ("post", "put", "patch"):
                operation = operations.get(method)
                if not operation:
                    continue
                if method not in mock.get(path, {}):
                    skipped["the mock does not serve it"] += 1
                    continue
                members = body_members(spec, operation)
                if not members:
                    skipped["the swagger types no body member"] += 1
                    continue
                url = path
                if placeholders:
                    collection = path[: path.index("{") - 1]
                    found = an_id(collection)
                    if not found:
                        skipped["no id to address it with"] += 1
                        continue
                    url = path.replace("{" + placeholders[0] + "}", found)
                exclusive = EXCLUSIVE.get((method.upper(), path[len(BASE):]), frozenset())
                sent = {
                    name: value
                    for name, declaration in members.items()
                    if name not in exclusive
                    and (value := value_for(name, resolve(spec, declaration))) is not None
                }
                # An update names the record it updates. A made-up `id` is a
                # 404 that says nothing about whether the route applies what
                # it accepts: `PUT /exclusions` and `PUT /restrictions` were
                # both refused for that reason and neither was ever judged.
                if method == "put" and "id" in sent and not placeholders:
                    existing = an_id(path)
                    if not existing:
                        skipped["no id to address it with"] += 1
                        continue
                    sent["id"] = existing
                if not sent:
                    skipped["no member could be given a value"] += 1
                    continue
                body: dict = {"data": sent}
                if wants_filter(spec, operation):
                    # The widest filter the vendor takes, so the write reaches
                    # whatever the estate holds rather than nothing.
                    body["filter"] = {"tenant": True}
                answer = client.request(method.upper(), url, headers=headers, json=body)
                # `POST /users/generate-api-token` rotates the caller's token,
                # so this sweep used to revoke its own credential halfway
                # through and read 401 for every route the swagger lists after
                # it -- counted as "refused the generated body", which is not
                # what happened. A real client keeps the token it is handed.
                minted = ""
                if answer.status_code in (200, 201):
                    body = answer.json()
                    if isinstance(body, dict) and isinstance(body.get("data"), dict):
                        minted = str(body["data"].get("token") or "")
                if minted:
                    headers["Authorization"] = f"ApiToken {minted}"
                if answer.status_code not in (200, 201):
                    # Counted apart, not silently. `routes += 1` used to come
                    # before the request, so six routes that refuse this
                    # generated body — `PUT /exclusions` among them — were
                    # inside "N routes sent every member they document" while
                    # nothing about them was judged. A denominator that counts
                    # what was never looked at is the shape of an audit that
                    # has stopped looking.
                    refused.append(f"{method.upper()} {path[len(BASE):]} "
                                   f"-> {answer.status_code}")
                    continue
                routes += 1
                found_records = records(answer.json())
                if not found_records:
                    skipped["the answer carried no record to compare"] += 1
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
    total = routes + len(refused) + sum(skipped.values())
    print(f"  of {total} documented write(s) this mock serves:")
    for reason, count in skipped.items():
        if count:
            print(f"    {count:>4} not exercised — {reason}")
    print(f"  {len(refused)} route(s) that refused the generated body, so were not judged")
    for entry in sorted(refused):
        print(f"      {entry}")
    if verbose:
        for route, name in sorted(unechoed):
            print(f"      {route:36} {name}")
    return 1 if dropped else 0


if __name__ == "__main__":
    raise SystemExit(main())
