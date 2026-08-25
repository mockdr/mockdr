# ruff: noqa: ANN001, ANN201, ANN202, D103, E402, PLR0911, PLR0912, PLR0915, PLR2004, S101, T201
# A release tool, not library code: every function is local to this file and
# sys.path is set before the project imports on purpose.
"""Walk every collection a page at a time and check what comes back.

A mock that pages wrongly looks right in each single answer: the shape is
fine, the count is plausible, and only a client that reads to the end
notices it saw a record twice — or never saw one at all. That makes paging
the same class of defect as an ignored filter, and it needs the same kind of
audit rather than an eye.

For each collection route the walk asks:

* does the whole collection come back exactly once — no duplicate, no gap?
* does the reported total match what the pages actually held?
* does paging *terminate*, rather than handing back the same cursor for ever?
* does the last page say it is the last, rather than pointing past the end?

Cursors, ``@odata.nextLink``, ``skip``/``offset`` and Splunk's
``count``/``offset`` are each walked the way that vendor's clients walk
them. Exit status 1 when anything is flagged.

    backend/.venv/bin/python scripts/paging_audit.py [mount ...]
"""

import base64
import hashlib
import json
import logging
import re
import sys
import uuid
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
logging.disable(logging.CRITICAL)
warnings.filterwarnings("ignore")
from fastapi.testclient import TestClient
from main import app

client = TestClient(app, raise_server_exceptions=False).__enter__()


def oauth(path, cid, sec, extra=None):
    response = client.post(path, data={
        "grant_type": "client_credentials", "client_id": cid,
        "client_secret": sec, **(extra or {}),
    })
    token = (
        response.json().get("access_token")
        if response.headers.get("content-type", "").startswith("application/json")
        else None
    )
    return {"Authorization": f"Bearer {token}"} if token else None


AUTH = {
    "web": {"Authorization": "ApiToken admin-token-0000-0000-000000000001"},
    "cs": oauth("/cs/oauth2/token", "cs-mock-admin-client", "cs-mock-admin-secret"),
    "mde": oauth("/mde/oauth2/v2.0/token", "mde-mock-admin-client", "mde-mock-admin-secret",
                 {"scope": "https://api.securitycenter.microsoft.com/.default"}),
    "graph": oauth("/graph/oauth2/v2.0/token", "graph-mock-admin-client",
                   "graph-mock-admin-secret", {"scope": "https://graph.microsoft.com/.default"}),
    "sentinel": oauth("/sentinel/oauth2/v2.0/token", "sentinel-mock-client-id",
                      "sentinel-mock-client-secret",
                      {"scope": "https://management.azure.com/.default"}),
    "xdr": {"x-xdr-auth-id": "1", "Authorization": "xdr-admin-secret"},
    "splunk": {"Authorization": "Basic " + base64.b64encode(b"admin:mockdr-admin").decode()},
    "elastic": {"Authorization": "Basic " + base64.b64encode(
        b"elastic:mock-elastic-password").decode()},
    "kibana": {
        "Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode(),
        "kbn-xsrf": "true",
    },
}

_COLLECTION_KEYS = (
    "data", "value", "resources", "items", "entry", "results", "notes",
    "saved_objects", "cases", "rules", "agents", "objects", "list", "records",
)
#: How many pages to walk before calling it a loop. A collection is walked
#: two at a time, so this is generous for the sizes mockdr seeds.
_MAX_PAGES = 120


def collection(body):
    """The list of items in a response, wherever this vendor keeps it."""
    if isinstance(body, list):
        return body if all(isinstance(item, dict) for item in body) else None
    if not isinstance(body, dict):
        return None
    hits = body.get("hits")
    if isinstance(hits, dict) and isinstance(hits.get("hits"), list):
        return hits["hits"]
    for key in _COLLECTION_KEYS:
        found = body.get(key)
        if isinstance(found, list) and (not found or isinstance(found[0], dict)):
            return found
    reply = body.get("reply")
    if isinstance(reply, dict):
        return collection(reply)
    return None


def reported_total(body):
    """What the answer says the collection holds, if it says."""
    if not isinstance(body, dict):
        return None
    for key in ("total", "totalCount", "@odata.count"):
        if isinstance(body.get(key), int):
            return body[key]
    for holder in ("pagination", "paging", "meta"):
        block = body.get(holder)
        if isinstance(block, dict):
            for key in ("totalItems", "total", "total_count"):
                if isinstance(block.get(key), int):
                    return block[key]
            nested = block.get("pagination")
            if isinstance(nested, dict) and isinstance(nested.get("total"), int):
                return nested["total"]
    reply = body.get("reply")
    if isinstance(reply, dict):
        return reported_total(reply)
    return None


def identity(item, index):
    """Something stable to recognise an item by across pages.

    An id is used when the record carries a non-empty one, nested ids
    included; otherwise the whole record is hashed, because two records that
    merely *begin* alike are still two records.
    """
    for key in ("id", "_id", "_key", "sid", "uuid", "incident_id", "alert_id"):
        value = item.get(key)
        if isinstance(value, (str, int)) and str(value):
            return f"{key}={value}"
    for holder in ("metadata", "properties", "alertInfo", "agentDetectionInfo"):
        block = item.get(holder)
        if isinstance(block, dict):
            nested = block.get("id") or block.get("_id")
            if isinstance(nested, (str, int)) and str(nested):
                return f"{holder}.id={nested}"
    digest = hashlib.sha256(
        json.dumps(item, sort_keys=True, default=str).encode(),
    ).hexdigest()[:16]
    return f"sha={digest}" if digest else f"#{index}"


def next_cursor(body):
    """The cursor a vendor hands back for the following page, if any."""
    if not isinstance(body, dict):
        return None
    for holder in ("pagination", "paging", "meta"):
        block = body.get(holder)
        if isinstance(block, dict):
            if block.get("nextCursor"):
                return str(block["nextCursor"])
            nested = block.get("pagination")
            if isinstance(nested, dict) and nested.get("next_page"):
                return str(nested["next_page"])
    if body.get("next_page_token"):
        return str(body["next_page_token"])
    return None


def next_link(body):
    """An absolute next-page link, as OData and Kibana hand back."""
    if not isinstance(body, dict):
        return None
    link = body.get("@odata.nextLink") or body.get("nextLink")
    return str(link) if link else None


def fill(path):
    def sub(match):
        name = match.group(1).lower()
        if "uuid" in name or name.endswith("_id") or name == "id" or "sid" in name:
            return str(uuid.uuid4())
        if "index" in name or "name" in name or "collection" in name:
            return "zzz-conformance"
        return "x"
    return re.sub(r"\{([^}:]+)(?::[^}]*)?\}", sub, path)


#: The page-size parameter each vendor takes, in the order to try them.
_LIMITERS = ("limit", "$top", "count", "per_page", "perPage", "pageSize", "page_size")
_OFFSETS = {"limit": "skip", "$top": "$skip", "count": "offset",
            "per_page": "page", "perPage": "page", "pageSize": "page",
            "page_size": "page"}


def walk(url, headers, limiter, offsetter, declared, expected=None):
    """Page through one collection; return the ids seen and any complaint."""
    seen, order = set(), []
    duplicates, pages = [], 0
    cursor = None
    offset = 0
    # Big enough to walk a seeded collection in a handful of pages, small
    # enough that it takes more than one.
    page_size = max(2, (expected or 4) // 10)
    first_page = None
    total = None

    while pages < _MAX_PAGES:
        params = {limiter: page_size}
        if cursor is not None:
            params["cursor"] = cursor
        elif offsetter and pages:
            # A page number continues from the one the first answer echoed:
            # some collections count from 0 and some from 1, and the answer
            # is the only place that says which.
            params[offsetter] = (
                offset if offsetter != "page"
                else (0 if first_page is None else first_page) + pages
            )
        response = client.get(url, headers=headers, params=params)
        if response.status_code != 200:
            return order, None, f"page {pages} answered {response.status_code}"
        try:
            body = response.json()
        except ValueError:
            return order, None, "page was not json"
        items = collection(body)
        if items is None:
            return order, None, None
        if pages == 0 and next_cursor(body) is None and not offsetter:
            # Nothing in the answer says how to ask for the next page, and
            # the route declares no offset either. Some vendors really do
            # publish a collection that way — SentinelOne's per-agent
            # applications and processes both carry `data` and nothing else,
            # by their own swagger — so this is not a finding, only a fact.
            return order, reported_total(body), "unpageable"
        if total is None:
            total = reported_total(body)
        if first_page is None and isinstance(body, dict) and isinstance(body.get("page"), int):
            first_page = body["page"]
        pages += 1
        if len(items) > page_size:
            return order, total, (
                f"page held {len(items)} items where {page_size} were asked for"
            )
        for index, item in enumerate(items):
            key = identity(item, index)
            if key in seen:
                duplicates.append(key)
            seen.add(key)
            order.append(key)
        cursor = next_cursor(body)
        offset += len(items)
        if not items:
            break
        if cursor is None and not offsetter:
            break
        if cursor is None and len(items) < page_size:
            break
        if expected and len(seen) >= expected:
            # Everything the collection holds has been seen; a walk that
            # keeps going from here is paging past the end.
            break
    if duplicates:
        return order, total, f"{len(duplicates)} item(s) came back twice: {duplicates[:2]}"
    if pages >= _MAX_PAGES:
        return order, total, "paging did not terminate"
    return order, total, None


def main():
    wanted = sys.argv[1:]
    flags = []
    unpageable = []
    walked = 0
    for path, operations in app.openapi()["paths"].items():
        operation = operations.get("get")
        if not operation or "/_dev/" in path:
            # The dev routes record this audit's own traffic; walking them
            # walks a collection that grows while it is read.
            continue
        mount = path.split("/")[1]
        if wanted and mount not in wanted:
            continue
        headers = AUTH.get(mount)
        if headers is None:
            continue
        declared = {
            p["name"] for p in operation.get("parameters", []) if p.get("in") == "query"
        }
        limiter = next((name for name in _LIMITERS if name in declared), None)
        if limiter is None:
            continue
        url = fill(path)
        base = client.get(url, headers=headers, params={limiter: 1000})
        if base.status_code != 200:
            continue
        try:
            base_body = base.json()
        except ValueError:
            continue
        whole = collection(base_body)
        if not whole or len(whole) < 3:
            continue

        offsetter = _OFFSETS.get(limiter) if _OFFSETS.get(limiter) in declared else None
        walked += 1
        order, total, complaint = walk(
            url, headers, limiter, offsetter, declared, expected=len(whole),
        )
        if complaint == "unpageable":
            unpageable.append((mount, path))
            continue
        if complaint:
            flags.append((mount, path, complaint))
            continue
        expected = [identity(item, i) for i, item in enumerate(whole)]
        missing = [key for key in expected if key not in set(order)]
        if missing:
            flags.append((
                mount, path,
                f"paging returned {len(order)} of {len(expected)}; "
                f"{len(missing)} never appeared: {missing[:2]}",
            ))
        elif total is not None and total != len(expected):
            flags.append((
                mount, path, f"reported total {total}, collection holds {len(expected)}",
            ))

    print(f"=== PAGING AUDIT === {walked} collection(s) walked")
    if unpageable:
        print(f"  {len(unpageable)} collection(s) publish no way to page:")
        for mount, path in unpageable:
            print(f"    {mount:<9} {path}")
    for mount, path, complaint in flags:
        print(f"  {mount:<9} {path:<62} {complaint}")
    print(f"\n  {len(flags)} collection(s) flagged")
    return 1 if flags else 0


if __name__ == "__main__":
    sys.exit(main())
