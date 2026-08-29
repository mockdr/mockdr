"""Which query members Kibana's routes take, and whether mockdr agrees.

Kibana checks a route's query schema before the handler runs and refuses a
member the route does not declare — in three wordings, one per validator:
`[request query.zzz]: definition for this key is missing` (config-schema),
`[request query]: invalid keys "zzz"` (io-ts), and
`[request query]: Invalid value {...}, excess properties: [...]` (Timeline's).
mockdr answered 200 and ignored it, so a client that misspelled a filter read
an unfiltered result as a filtered one and got a 400 in production.

Fourteen routes were measured by hand for 2.3.1. This asks all of them, in
both directions:

* **every route**, whether an unknown member is refused at all, and with the
  same status Kibana gives — including on a path whose object does not
  exist, because the schema runs first and mockdr used to resolve the object
  and answer its 404;
* **every member mockdr declares**, whether Kibana knows it. That is the
  direction that matters most: a member the mock accepts and the product
  refuses works in testing and fails in production. `list_id` on
  `/api/exception_lists/_find` was one — it belongs to the *items* search.

The oracle is the message, not the status: a refusal names the member as
undeclared, where a bad *value* of a declared one is a 400 saying something
else entirely.

    python scripts/kbn_param_audit.py

Needs a real Kibana (`KIBANA`, default http://localhost:15601) and mockdr
(`MOCKDR`, default http://localhost:5001/kibana). Read-only: every request
is a GET, and path parameters are filled with a name nothing has.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

REAL = os.environ.get("KIBANA", "http://localhost:15601")
MOCK = os.environ.get("MOCKDR", "http://localhost:5001/kibana")
REAL_AUTH = "Basic " + base64.b64encode(
    f"elastic:{os.environ.get('KIBANA_PASSWORD', 'Probe-Passw0rd!')}".encode()).decode()
MOCK_AUTH = "Basic " + base64.b64encode(
    f"elastic:{os.environ.get('MOCKDR_PASSWORD', 'mock-elastic-password')}".encode(),
).decode()

#: A name no route declares, and none that does exist.
UNKNOWN = "zzzUnknownMember"
MISSING = "zzz-mockdr-param-probe"

#: The three ways a validator says "I do not know this member". Anything else
#: a 400 says is about a *value*, and says nothing about membership.
_UNDECLARED = (
    "definition for this key is missing",
    "invalid keys",
    "excess properties",
)


def _get(base: str, auth: str, path: str, query: dict[str, str]) -> tuple[int, str]:
    url = f"{base}{path}"
    if query:
        url = f"{url}?{urllib.parse.urlencode(query)}"
    request = urllib.request.Request(url, headers={  # noqa: S310 - fixed scheme
        "Authorization": auth, "kbn-xsrf": "true",
    })
    try:
        with urllib.request.urlopen(request, timeout=30) as answer:  # noqa: S310
            return answer.status, answer.read().decode()[:400]
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()[:400]
    except OSError as exc:
        return 0, str(exc)[:120]


def _message(body: str) -> str:
    """The message an answer carries, or the empty string."""
    try:
        parsed = json.loads(body)
    except ValueError:
        return ""
    if not isinstance(parsed, dict):
        return ""
    return str(parsed.get("message") or parsed.get("error") or "")


def _says_undeclared(body: str) -> bool:
    """Whether the answer names the member as one the route does not declare."""
    return any(phrase in _message(body) for phrase in _UNDECLARED)


def _routes() -> dict[str, list[str]]:
    """Every Kibana GET route mockdr serves, with the members it declares."""
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]
                          / "backend"))
    import logging
    import warnings
    logging.disable(logging.CRITICAL)
    warnings.filterwarnings("ignore")
    from main import app  # noqa: PLC0415 - after sys.path is set

    found: dict[str, list[str]] = {}
    for path, operations in app.openapi()["paths"].items():
        if not path.startswith("/kibana/") or "get" not in operations:
            continue
        members = [p["name"] for p in operations["get"].get("parameters", [])
                   if p.get("in") == "query"]
        found[path[len("/kibana"):]] = members
    return found


def main() -> int:
    """Compare every route's accepted members, in both directions."""
    routes = _routes()
    unrefused: list[str] = []
    invented: list[str] = []
    misworded: list[str] = []
    unknown_to_kibana: list[str] = []
    unchecked: list[str] = []
    asked = 0

    for path, members in sorted(routes.items()):
        filled = re.sub(r"\{([^}:]+)(?::[^}]*)?\}", MISSING, path)

        # Direction one: an unknown member, which every schema-checked route
        # refuses — the object in the path need not exist for it.
        real_status, real_body = _get(REAL, REAL_AUTH, filled, {UNKNOWN: "1"})
        mock_status, mock_body = _get(MOCK, MOCK_AUTH, filled, {UNKNOWN: "1"})
        asked += 2
        if real_status == 0 or mock_status == 0:
            unchecked.append(f"{path} (unreachable)")
            continue
        theirs = _says_undeclared(real_body)
        ours = _says_undeclared(mock_body)
        if theirs and ours:
            # Both refuse — but io-ts words the same refusal two ways, and a
            # substring check would take one for the other: the Cases API
            # leaves the `[request query]: ` prefix off and the exception-list
            # API keeps it.  Comparing the whole message is what catches that.
            said, we_said = _message(real_body), _message(mock_body)
            if said != we_said:
                misworded.append(f"GET {path}?{UNKNOWN}\n"
                                 f"      kibana {said!r}\n"
                                 f"      mockdr {we_said!r}")
        if theirs and not ours:
            unrefused.append(f"GET {path}?{UNKNOWN} — kibana {real_status}, "
                             f"mockdr {mock_status}")
        elif ours and not theirs:
            invented.append(f"GET {path}?{UNKNOWN} — kibana {real_status}, "
                            f"mockdr {mock_status}")

        # Direction two: every member mockdr declares, asked of Kibana.
        for member in members:
            real_status, real_body = _get(REAL, REAL_AUTH, filled, {member: "1"})
            asked += 1
            if real_status == 0:
                unchecked.append(f"{path}?{member} (unreachable)")
            elif _says_undeclared(real_body):
                unknown_to_kibana.append(f"GET {path}?{member} — kibana "
                                         f"{real_status} does not declare it")

    print(f"=== KIBANA QUERY MEMBERS === {asked} question(s) across "
          f"{len(routes)} route(s)")
    for line in unrefused:
        print(f"  ignored though Kibana refuses it: {line}")
    for line in invented:
        print(f"  refused though Kibana accepts it: {line}")
    for line in misworded:
        print(f"  refused in the wrong words: {line}")
    for line in unknown_to_kibana:
        print(f"  declared though Kibana does not know it: {line}")
    print(f"\n  {len(unrefused)} member(s) ignored that Kibana refuses, "
          f"{len(invented)} invented refusal(s), "
          f"{len(misworded)} refusal(s) worded differently, "
          f"{len(unknown_to_kibana)} declared member(s) Kibana does not know")
    if unchecked:
        print(f"  {len(unchecked)} question(s) not compared:")
        for line in unchecked:
            print(f"    {line}")
    return 1 if unrefused or invented or misworded or unknown_to_kibana else 0


if __name__ == "__main__":
    sys.exit(main())
