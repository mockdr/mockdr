# ruff: noqa: ANN001, ANN201, ANN202, D103, E402, PLR2004, S101, T201
# A release tool, not library code: every function is local to this file and
# sys.path is set before the project imports on purpose.
"""Check mockdr against the normative requirements of the protocols it speaks.

Every other audit here asks whether the mock matches a *vendor*. This one
asks whether it matches the *protocol*, which is a different and finite
question: the RFCs that bear on an HTTP origin server serving JSON over
Basic, Bearer and OAuth 2.0 client credentials state a countable number of
requirements that apply to it, and they can be listed and ticked off.

What is in play here, by measurement rather than by assumption:

* **RFC 9110** HTTP semantics — the status codes, the headers they oblige,
  conditional requests and the validators that make them work;
* **RFC 6749/6750** OAuth 2.0 and its bearer tokens — four mounts issue
  them;
* **RFC 7617** Basic authentication — Splunk and Elasticsearch challenge
  with it;
* **RFC 8259** JSON — every mount answers it.

Not in play, and so not checked: ranges (§14, no mount serves a partial
representation), cookies (RFC 6265, nothing sets one), JWT (RFC 7519, every
token this mock issues is opaque), and HTTP/2 or /3, which the ASGI server
answers, not the app.

**Where a product breaks the RFC, the simulation follows the product.** A
mock that is more conformant than the thing it stands in for tests clients
against a world that does not exist. Those cases are listed by name in
`DEVIATIONS` with the measurement behind each, counted apart from the
passes, and never silently.

    backend/.venv/bin/python scripts/rfc_conformance.py
"""

from __future__ import annotations

import json
import logging
import os
import sys
import urllib.error
import urllib.request
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
logging.disable(logging.CRITICAL)
warnings.filterwarnings("ignore")
from fastapi.testclient import TestClient
from main import app

client = TestClient(app, raise_server_exceptions=False).__enter__()

S1 = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}
SPLUNK = {"Authorization": "Basic YWRtaW46bW9ja2RyLWFkbWlu"}
ES = {"Authorization": "Basic ZWxhc3RpYzptb2NrLWVsYXN0aWMtcGFzc3dvcmQ="}

#: One representative route per mount, with the credential it wants.
MOUNTS = [
    ("sentinelone", "/web/api/v2.1/threats", S1),
    ("crowdstrike", "/cs/devices/queries/devices/v1", {}),
    ("defender", "/mde/api/machines", {}),
    ("graph", "/graph/v1.0/users", {}),
    ("sentinel", "/sentinel/oauth2/v2.0/token", {}),
    ("cortex", "/xdr/public_api/v1/incidents/get_incidents", {}),
    ("splunk", "/splunk/services/data/indexes", SPLUNK),
    ("elastic", "/elastic/_cluster/health", ES),
    ("kibana", "/kibana/api/features", ES),
]

TOKEN_ENDPOINTS = {
    "crowdstrike": ("/cs/oauth2/token", {
        "client_id": "cs-mock-admin-client", "client_secret": "cs-mock-admin-secret"}),
    "defender": ("/mde/oauth2/v2.0/token", {
        "grant_type": "client_credentials", "client_id": "mde-mock-admin-client",
        "client_secret": "mde-mock-admin-secret",
        "scope": "https://api.securitycenter.microsoft.com/.default"}),
    "graph": ("/graph/oauth2/v2.0/token", {
        "grant_type": "client_credentials", "client_id": "graph-mock-admin-client",
        "client_secret": "graph-mock-admin-secret",
        "scope": "https://graph.microsoft.com/.default"}),
    "sentinel": ("/sentinel/oauth2/v2.0/token", {
        "grant_type": "client_credentials", "client_id": "sentinel-mock-client-id",
        "client_secret": "sentinel-mock-client-secret",
        "scope": "https://management.azure.com/.default"}),
}

#: Requirements this mock does not meet, where no product is runnable here
#: to measure and meeting them would mean inventing the answer. Naming them
#: is the whole point: an assessment tool that cannot tell "conformant" from
#: "unmeasured" is guessing in both directions.
UNVERIFIABLE = {
    ("RFC 9110 §15.5.2", "sentinelone"):
        "SentinelOne declares its credential as `type: apiKey` in the "
        "Authorization header (swagger securityDefinitions.ApiTokenAuth), "
        "not as an HTTP authentication scheme. `ApiToken` is in no IANA "
        "registry, so there is no challenge to send that a real client has "
        "ever seen — and no SentinelOne runs here to measure what it does. "
        "Emitting an invented `ApiToken realm=...` would trade a known gap "
        "for an unknown fiction.",
}

#: One departure this mock *cannot* follow, recorded here rather than in the
#: table below, because the table is for deviations the simulation
#: reproduces: Elasticsearch 8.15 sends no `Date` on any answer — measured
#: on /_cluster/health and /_cat/indices, 200 and 401 alike. `Date` is added
#: by the ASGI server after the app has answered, and uvicorn's switch for
#: it is process-wide, so one mount cannot stay silent while the others
#: speak.

#: Where a product's own behaviour departs from the RFC and the simulation
#: follows it. Each entry names what was measured, on which version.
DEVIATIONS = {
    ("RFC 9110 §15.5.2", "kibana"):
        "Kibana 8.15 answers 401 with no WWW-Authenticate — measured on "
        "/api/features without credentials.",
    ("RFC 9110 §12.5.5", "elastic"):
        "Elasticsearch 8.15 gzips a 242-byte /_cluster/health and publishes "
        "no Vary at all — measured with a raw request that sets "
        "Accept-Encoding itself, because urllib overrides it and reports no "
        "compression where there is some. Kibana in the same distribution "
        "does send `Vary: accept-encoding`, and this mock sends it there.",
    ("RFC 7617 §2.1", "splunk"):
        "splunkd 10.4.2 challenges with `Basic realm=\"/splunk\"` and no "
        "charset — measured without credentials on /services/data/indexes.",
    ("RFC 6749 §5.2 (description)", "crowdstrike"):
        "Falcon's envelope carries the reason in errors[].message rather "
        "than in an `error_description` member.",
    ("RFC 6749 §5.2", "crowdstrike"):
        "Falcon answers a bad client_secret in its own {errors, meta, "
        "resources} envelope, which every one of its routes uses and "
        "error_envelope_audit.py enforces over 2144 refusals.",
}


def check(rfc, section, requirement, level="MUST"):
    """Register one normative requirement as a check."""
    def register(fn):
        CHECKS.append((f"{rfc} {section}", requirement, level, fn))
        return fn
    return register


CHECKS: list[tuple[str, str, str, object]] = []


# ── RFC 9110: HTTP semantics ───────────────────────────────────────────────

@check("RFC 9110", "§6.6.1", "an origin server sends Date on every response")
def date_on_every_answer():
    """Measured over HTTP, because the app is not what supplies it.

    `Date` and `Server` are added by the ASGI server after the application
    has answered — which is why uvicorn has a flag to suppress each. An
    in-process client speaks to the app directly and sees neither, so
    checking this here would report a violation that no client can ever
    observe. It cost a middleware and two commits to learn that: a probe
    that read `headers.get("Date")` out of a dict keyed in lower case found
    nothing, and nothing was what it was looking at.

    With no HTTP instance reachable, this reports unmeasured rather than
    met: MOCKDR_HTTP_BASE names one (`ci.sh` and the conformance harness
    both have one running).
    """
    base = os.environ.get("MOCKDR_HTTP_BASE")
    if not base:
        return ["unmeasured: set MOCKDR_HTTP_BASE to an http:// instance"]

    missing = []
    for name, path, headers in MOUNTS:
        request = urllib.request.Request(base.rstrip("/") + path, headers=headers)
        try:
            answered = urllib.request.urlopen(request, timeout=10).headers
        except urllib.error.HTTPError as refused:
            answered = refused.headers
        except urllib.error.URLError:
            return [f"unmeasured: {base} did not answer"]
        if answered.get("date") is None:
            missing.append(name)
        elif not str(answered.get("date")).endswith(" GMT"):
            # §5.6.7 admits one form, and it ends in GMT.
            missing.append(f"{name}: {answered.get('date')!r} is not IMF-fixdate")
    return missing


@check("RFC 9110", "§15.5.2", "a 401 carries a WWW-Authenticate challenge")
def challenge_on_401():
    missing = []
    for name, path, _ in MOUNTS:
        response = client.get(path)
        if response.status_code == 401 and not response.headers.get("www-authenticate"):
            missing.append(name)
    return missing


@check("RFC 9110", "§15.5.6", "a 405 carries Allow")
def allow_on_405():
    missing = []
    for name, path, headers in MOUNTS:
        response = client.request("DELETE", path, headers=headers)
        if response.status_code == 405 and not response.headers.get("allow"):
            missing.append(name)
    return missing


@check("RFC 9110", "§9.3.2", "HEAD answers as GET does, with no body")
def head_matches_get():
    wrong = []
    for name, path, headers in MOUNTS:
        got, head = client.get(path, headers=headers), client.head(path, headers=headers)
        if head.status_code == 405:
            continue          # a route may decline HEAD; §9.3.2 binds those that serve it
        if head.content:
            wrong.append(f"{name}: HEAD carried {len(head.content)} bytes")
        elif head.headers.get("content-type") != got.headers.get("content-type"):
            wrong.append(f"{name}: content-type differs from GET")
    return wrong


@check("RFC 9110", "§15.4.5", "a 304 carries no body and no content-length")
def not_modified_is_empty():
    first = client.get("/splunk/services/data/indexes", headers=SPLUNK,
                       params={"output_mode": "json"})
    etag = first.headers.get("etag")
    if not etag:
        return []
    again = client.get(
        "/splunk/services/data/indexes",
        headers={**SPLUNK, "If-None-Match": etag},
        params={"output_mode": "json"},
    )
    if again.status_code != 304:
        return [f"a matching If-None-Match answered {again.status_code}, not 304"]
    problems = []
    if again.content:
        problems.append(f"304 carried {len(again.content)} bytes")
    if "content-length" in {k.lower() for k in again.headers}:
        problems.append("304 carried Content-Length")
    return problems


@check("RFC 9110", "§8.8.3", "an ETag is a quoted-string, weak ones prefixed W/")
def etag_syntax():
    response = client.get("/splunk/services/data/indexes", headers=SPLUNK,
                          params={"output_mode": "json"})
    etag = response.headers.get("etag")
    if etag is None:
        return []
    body = etag[2:] if etag.startswith("W/") else etag
    return [] if body.startswith('"') and body.endswith('"') else [f"malformed: {etag!r}"]


@check("RFC 9110", "§8.3", "a response with content names its media type")
def content_type_present():
    missing = []
    for name, path, headers in MOUNTS:
        response = client.get(path, headers=headers)
        if response.content and not response.headers.get("content-type"):
            missing.append(name)
    return missing


@check("RFC 9110", "§15.4", "a redirect names where it points")
def redirect_has_location():
    response = client.post("/kibana/api/endpoint/unisolate",
                           headers={**ES, "kbn-xsrf": "true"},
                           json={"endpoint_ids": ["zzz"]}, follow_redirects=False)
    if response.status_code not in range(300, 400):
        return []
    return [] if response.headers.get("location") else ["308 with no Location"]


# ── RFC 6749 / 6750: OAuth 2.0 ─────────────────────────────────────────────

@check("RFC 6749", "§5.1", "a token response carries access_token and token_type")
def token_response_members():
    missing = []
    for name, (path, form) in TOKEN_ENDPOINTS.items():
        body = client.post(path, data=form).json()
        absent = [m for m in ("access_token", "token_type") if m not in body]
        if absent:
            missing.append(f"{name}: {absent}")
    return missing


@check("RFC 6749", "§5.1", "a token response is not stored")
def token_response_no_store():
    missing = []
    for name, (path, form) in TOKEN_ENDPOINTS.items():
        headers = client.post(path, data=form).headers
        if "no-store" not in (headers.get("cache-control") or ""):
            missing.append(name)
    return missing


@check("RFC 6749", "§5.2", "a refused token request names the error")
def token_error_member():
    missing = []
    for name, (path, form) in TOKEN_ENDPOINTS.items():
        response = client.post(path, data={**form, "client_secret": "wrong"})
        body = response.json() if response.headers.get(
            "content-type", "").startswith("application/json") else {}
        if not body.get("error"):
            missing.append(name)
    return missing


@check("RFC 6750", "§3", "a Bearer challenge names its realm")
def bearer_realm():
    wrong = []
    for name, path, _ in MOUNTS:
        challenge = client.get(path).headers.get("www-authenticate", "")
        if challenge.startswith("Bearer") and "realm=" not in challenge:
            wrong.append(f"{name}: {challenge}")
    return wrong


# ── RFC 7617: Basic authentication ─────────────────────────────────────────

@check("RFC 7617", "§2", "a Basic challenge names its realm")
def basic_realm():
    wrong = []
    for name, path, _ in MOUNTS:
        challenge = client.get(path).headers.get("www-authenticate", "")
        if challenge.startswith("Basic") and "realm=" not in challenge:
            wrong.append(f"{name}: {challenge}")
    return wrong


@check("RFC 6749", "§5.1", "a token response says how long it lasts", "SHOULD")
def token_expires_in():
    return [name for name, (path, form) in TOKEN_ENDPOINTS.items()
            if "expires_in" not in client.post(path, data=form).json()]


@check("RFC 6749", "§5.2 (description)", "a refused token request explains itself",
       "SHOULD")
def token_error_description():
    missing = []
    for name, (path, form) in TOKEN_ENDPOINTS.items():
        body = client.post(path, data={**form, "client_secret": "wrong"}).json()
        if not body.get("error_description"):
            missing.append(name)
    return missing


@check("RFC 6750", "§3.1", "an invalid token is answered error=\"invalid_token\"",
       "SHOULD")
def invalid_token_named():
    wrong = []
    for name, path, _ in MOUNTS:
        response = client.get(path, headers={"Authorization": "Bearer not-a-real-token"})
        challenge = response.headers.get("www-authenticate", "")
        if challenge.startswith("Bearer") and 'error="invalid_token"' not in challenge:
            wrong.append(f"{name}: {challenge}")
    return wrong


@check("RFC 7617", "§2.1", "a Basic challenge names charset=\"UTF-8\"", "SHOULD")
def basic_charset():
    wrong = []
    for name, path, _ in MOUNTS:
        challenge = client.get(path).headers.get("www-authenticate", "")
        if challenge.startswith("Basic") and "charset=" not in challenge:
            wrong.append(name)
    return wrong


@check("RFC 9110", "§12.5.5", "a negotiated answer names what it varies on", "SHOULD")
def vary_on_negotiated():
    wrong = []
    for name, path, headers in MOUNTS:
        response = client.get(path, headers={**headers, "Accept-Encoding": "gzip"})
        if response.headers.get("content-encoding") and "accept-encoding" not in (
                response.headers.get("vary", "").lower()):
            wrong.append(name)
    return wrong


@check("RFC 9110", "§10.2.3", "a 429 says when to come back", "SHOULD")
def retry_after_on_429():
    """The limiter is off by default; turn it on, provoke one, put it back.

    One request a minute, not three: at three this check refused to trip
    about once in thirty runs, depending where in the window it started, and
    a gate that flakes is worse than no gate at all.
    """
    client.post("/web/api/v2.1/_dev/rate-limit", headers=S1,
                json={"enabled": True, "requestsPerMinute": 1})
    try:
        refused = None
        for _ in range(40):
            response = client.get("/web/api/v2.1/threats?limit=1", headers=S1)
            if response.status_code == 429:
                refused = response
                break
        if refused is None:
            return ["the limiter never refused, so nothing was measured"]
        # `Date` is the ASGI server's, not the app's, and is checked over
        # HTTP above rather than here where no server exists.
        return [] if refused.headers.get("retry-after") else ["429 with no Retry-After"]
    finally:
        client.post("/web/api/v2.1/_dev/rate-limit", headers=S1, json={"enabled": False})


# ── RFC 8259: JSON ─────────────────────────────────────────────────────────

@check("RFC 8259", "§8.1", "a JSON answer is valid JSON in UTF-8")
def json_is_json():
    broken = []
    for name, path, headers in MOUNTS:
        response = client.get(path, headers=headers)
        if not response.headers.get("content-type", "").startswith("application/json"):
            continue
        try:
            json.loads(response.content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            broken.append(f"{name}: {type(exc).__name__}")
    return broken


def main():
    passed = failed = 0
    deviations: list[str] = []
    failures: list[str] = []

    unmeasured: list[str] = []

    for citation, requirement, level, fn in CHECKS:
        found = fn()
        real = []
        for item in found:
            mount = str(item).split(":")[0]
            if (citation, mount) in DEVIATIONS:
                deviations.append(f"{citation} — {mount}: {DEVIATIONS[(citation, mount)]}")
            elif (citation, mount) in UNVERIFIABLE:
                unmeasured.append(f"{citation} — {mount}: {UNVERIFIABLE[(citation, mount)]}")
            else:
                real.append(item)
        if real:
            failed += 1
            failures.append(f"{citation} [{level}] {requirement}\n        {real}")
        else:
            passed += 1

    print(f"=== RFC CONFORMANCE === {len(CHECKS)} requirement(s) checked, "
          f"{passed} met, {failed} not")
    print()
    for line in failures:
        print(f"  FAIL  {line}")
    if deviations:
        print(f"  {len(deviations)} requirement(s) the simulated product breaks, "
              f"and the simulation with it:")
        for line in sorted(deviations):
            print(f"    {line}")
    if unmeasured:
        print(f"  {len(unmeasured)} requirement(s) unmet with no product here to "
              f"measure, where meeting them would mean inventing the answer:")
        for line in sorted(unmeasured):
            print(f"    {line}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
