#!/usr/bin/env python3
"""Ask whether the console's response types describe the answers it gets.

The console declares a TypeScript interface for most of the responses it
reads, and `src/api/*.ts` names the path and the type on the same line:

    timeline: (id: string): Promise<PaginatedResponse<TimelineEvent>> =>
      client.get(`/threats/${id}/timeline`) as Promise<PaginatedResponse<...>>

Nothing checks that claim. `vue-tsc` type-checks the console against the
interface, not the interface against the API, so an interface copied from
the seeder rather than from the vendor schema type-checks perfectly and
renders nothing -- which is how eight blank timeline events reached a tab.

So: call each documented GET, and report every declared field that no
record in the answer carries. A field the answer never has is a field the
console draws blank.

Paths with an `${id}` are filled from the nearest parameterless sibling in
the same module -- `/threats/${id}/timeline` from `/threats` -- so nothing
here is invented; an id that cannot be found that way is reported as a
route this script could not reach, not as a pass.
"""
from __future__ import annotations

import json
import logging
import re
import sys
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
API_DIR = ROOT / "frontend" / "src" / "api"
SRC = ROOT / "frontend" / "src"

sys.path.insert(0, str(ROOT / "backend"))
logging.disable(logging.CRITICAL)
warnings.filterwarnings("ignore")
from fastapi.testclient import TestClient  # noqa: E402
from main import app  # noqa: E402

client = TestClient(app, raise_server_exceptions=False).__enter__()

#: Every axios client the console builds, and the prefix it hangs its paths on.
CLIENT_PREFIX = {
    "client": "/web/api/v2.1", "csClient": "/cs", "mdeClient": "/mde",
    "graphClient": "/graph", "sentinelClient": "/sentinel", "xdrClient": "/xdr/public_api/v1",
    "splunkClient": "/splunk", "esClient": "/elastic", "kbnClient": "/kibana",
}

#: Credentials per prefix. OAuth-guarded vendors get their token at run time.
STATIC_AUTH = {
    "/web/api/v2.1": {"Authorization": "ApiToken admin-token-0000-0000-000000000001"},
    "/xdr/public_api/v1": {"x-xdr-auth-id": "1", "Authorization": "xdr-admin-secret"},
    "/splunk": {"Authorization": "Basic YWRtaW46bW9ja2RyLWFkbWlu"},
    "/elastic": {"Authorization": "Basic ZWxhc3RpYzptb2NrLWVsYXN0aWMtcGFzc3dvcmQ="},
    "/kibana": {"Authorization": "Basic ZWxhc3RpYzptb2NrLWVsYXN0aWMtcGFzc3dvcmQ="},
}

#: Splunk speaks XML unless asked otherwise, and Kibana hides several
#: listings behind `_find`. Both are the vendor's own idiom, not a guess.
QUERY = {"/splunk": "output_mode=json"}
FIND_SUFFIX = ("", "/_find")

OAUTH = {
    "/cs": ("/cs/oauth2/token",
            "client_id=cs-mock-admin-client&client_secret=cs-mock-admin-secret"),
    "/mde": ("/mde/oauth2/v2.0/token",
             "grant_type=client_credentials&client_id=mde-mock-admin-client"
             "&client_secret=mde-mock-admin-secret"
             "&scope=https://api.securitycenter.microsoft.com/.default"),
    "/graph": ("/graph/oauth2/v2.0/token",
               "grant_type=client_credentials&client_id=graph-mock-admin-client"
               "&client_secret=graph-mock-admin-secret"
               "&scope=https://graph.microsoft.com/.default"),
    "/sentinel": ("/sentinel/oauth2/v2.0/token",
                  "grant_type=client_credentials&client_id=sentinel-mock-client-id"
                  "&client_secret=sentinel-mock-client-secret"
                  "&scope=https://management.azure.com/.default"),
}

#: Wrappers that carry a payload rather than being one.
_WRAPPER = re.compile(r"^(PaginatedResponse|SplunkEnvelope|Array|Promise)<(.+)>$")

_CALL = re.compile(
    r"(?P<client>\w*[Cc]lient)\.get\(\s*[`'\"](?P<path>[^`'\"]+)[`'\"]"
    r"(?:\s*,[^)]*)?\)\s*as\s+Promise<(?P<type>[^;\n]+?)>\s*,?\s*$",
    re.MULTILINE,
)


def leaf_type(expr: str) -> str | None:
    """Peel wrappers and array suffixes down to one named interface."""
    expr = expr.strip().rstrip(",")
    while True:
        expr = expr.strip()
        if expr.endswith("[]"):
            expr = expr[:-2]
            continue
        match = _WRAPPER.match(expr)
        if match:
            expr = match.group(2)
            continue
        break
    return expr if re.fullmatch(r"[A-Z]\w+", expr) else None


def declared_fields(name: str) -> dict[str, bool] | None:
    """Top-level members of an interface, mapped to whether they are optional."""
    pattern = re.compile(r"\binterface\s+" + re.escape(name) + r"\b[^{]*\{")
    for path in SRC.rglob("*.ts"):
        text = path.read_text()
        match = pattern.search(text)
        if not match:
            continue
        depth, end = 1, match.end()
        while depth and end < len(text):
            depth += {"{": 1, "}": -1}.get(text[end], 0)
            end += 1
        body, fields = text[match.end():end - 1], {}
        for line in re.finditer(r"^\s{2}(\w+)(\??):", body, re.MULTILINE):
            fields[line.group(1)] = line.group(2) == "?"
        return fields
    return None


def token(prefix: str) -> dict[str, str]:
    """The header this vendor wants, minted fresh where it is an OAuth one."""
    if prefix in STATIC_AUTH:
        return dict(STATIC_AUTH[prefix])
    path, body = OAUTH[prefix]
    form = dict(pair.split("=", 1) for pair in body.split("&"))
    payload = client.post(path, data=form).json()
    return {"Authorization": f"Bearer {payload['access_token']}"}


def get(url: str, headers: dict[str, str], query: str = "") -> object | None:
    """The decoded answer, or None if the route did not give us one."""
    if query:
        url += ("&" if "?" in url else "?") + query
    response = client.get(url, headers=headers)
    if response.status_code >= 400:
        return None
    try:
        payload: object = response.json()
    except json.JSONDecodeError:
        return None
    return payload


def first_id(rows: list[dict[str, object]]) -> str | None:
    """An identifier from the first row, however deeply the vendor nests it."""
    keys = ("id", "device_id", "endpoint_id", "rule_id", "sid", "name")
    for row in rows[:1]:
        for key in keys:
            if isinstance(row.get(key), str | int):
                return str(row[key])
        for value in row.values():
            if isinstance(value, dict):
                found = first_id([value])
                if found:
                    return found
    return None


def records(payload: object) -> list[dict[str, object]]:
    """The rows inside whatever envelope the vendor uses."""
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("data", "value", "resources", "results", "saved_objects",
                "reply", "cases", "entry", "hits"):
        inner = payload.get(key)
        if isinstance(inner, dict) and key in ("reply", "hits"):
            return records(inner)
        if isinstance(inner, list):
            return [row for row in inner if isinstance(row, dict)]
    return [payload]


def main() -> int:
    """Compare every declared response type against a real answer."""
    calls: list[tuple[str, str, str, str]] = []
    for source in sorted(API_DIR.glob("*.ts")):
        for match in _CALL.finditer(source.read_text()):
            prefix = CLIENT_PREFIX.get(match.group("client"))
            name = leaf_type(match.group("type"))
            if prefix and name:
                calls.append((source.stem, prefix, match.group("path"), name))

    heads: dict[str, dict[str, str]] = {}
    findings: list[str] = []
    unreachable: list[str] = []
    checked = 0

    for module, prefix, path, name in calls:
        fields = declared_fields(name)
        if not fields:
            continue
        if prefix not in heads:
            heads[prefix] = token(prefix)
        url = prefix + path
        query = QUERY.get(prefix, "")
        if "${" in path:
            stem = path.split("${")[0].rstrip("/")
            ident = None
            for suffix in FIND_SUFFIX:
                if not stem:
                    break
                listing = get(prefix + stem + suffix, heads[prefix], query)
                ident = first_id(records(listing)) if listing is not None else None
                if ident:
                    break
            if ident is None:
                unreachable.append(f"{module}: {prefix}{path} ({name}) - no id from {stem}")
                continue
            url = prefix + re.sub(r"\$\{[^}]+\}", ident, path, count=1)
        if "${" in url:
            unreachable.append(f"{module}: {prefix}{path} ({name}) - unfilled parameter")
            continue

        payload = get(url, heads[prefix], query)
        if payload is None:
            unreachable.append(f"{module}: {prefix}{path} ({name}) - no answer")
            continue
        rows = records(payload)
        if not rows:
            unreachable.append(f"{module}: {prefix}{path} ({name}) - no records")
            continue

        checked += 1
        # A declared field counts as present at whichever level the vendor
        # puts it: on the envelope, on a record, or inside Splunk's `content`.
        seen: set[str] = set(payload) if isinstance(payload, dict) else set()
        for row in rows:
            seen |= set(row)
            content = row.get("content")
            if isinstance(content, dict):
                seen |= set(content)
        missing = sorted(f for f, optional in fields.items() if f not in seen and not optional)
        if missing:
            findings.append(f"{name} on {prefix}{path}: {', '.join(missing)}")

    print(f"=== FRONTEND TYPE DRIFT === {checked} answer(s) compared "
          f"against {len({c[3] for c in calls})} declared type(s)")
    print()
    for line in findings:
        print(f"  {line}")
    print(f"  {len(findings)} type(s) naming a field the answer never carries")
    if unreachable:
        print(f"  {len(unreachable)} route(s) this script could not reach:")
        for line in unreachable:
            print(f"    {line}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
