#!/usr/bin/env python3
# ruff: noqa: ANN001, ANN003, ANN201, ANN202, ANN401, BLE001, C901, D101, D102, D103, D105, D107, D301, E402, N818, PLR0912, PLR0915, PLR2004, S101, S105, S106, S110, S311, T201
# A release tool, not library code: it imports the vendors' own client
# libraries, which live in a venv of their own and never in the backend's.
"""Drive the vendors' real client libraries against a running mock.

Every other check in this repo reads a vendor's SDK source, or replays what a
test author believed it sends. This one runs the SDK: falconpy, msgraph-sdk
with azure-identity, elasticsearch-py, splunk-sdk (splunklib),
azure-mgmt-securityinsight and azure-monitor-query, plain ``requests`` for
Defender and Kibana (Microsoft's and Elastic's own samples use it), and the
XSOAR integrations for SentinelOne and Cortex XDR -- which have no official
Python SDK -- driven through a minimal ``demistomock`` shim. Each vendor goes
through a realistic workflow: authenticate, list and page to the end with
the SDK's own pager, fetch by id, run an action and poll it to completion,
search or hunt, and walk the error paths (bad credentials, an unknown id, a
429 from the dev rate limiter), checking that the SDK raises what it would
raise against the product.

It mutates the mock (isolates hosts, writes indices, creates rules), so run
it against a dev instance, never a shared one. It is a release check, not a
CI one: it needs network installs, so it is not in ci.sh or the pytest run.

Set up once (see scripts/README.md):

    python3 -m venv /tmp/sdk-venv
    /tmp/sdk-venv/bin/pip install crowdstrike-falconpy msgraph-sdk azure-identity \\
        msal 'elasticsearch>=8,<9' splunk-sdk azure-mgmt-securityinsight \\
        azure-monitor-query requests dateparser python-dateutil pytz setuptools

The Azure SDKs refuse plain http (azure-identity: "The value must be a TLS
protected (https) URL"; azure-core's bearer policy likewise), so start the
mock with TLS and hand this script the certificate:

    openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=127.0.0.1 \\
        -addext subjectAltName=IP:127.0.0.1 -keyout /tmp/mock.key -out /tmp/mock.crt
    cd backend && .venv/bin/python -m uvicorn main:app --port 8101 --no-server-header \\
        --ssl-keyfile /tmp/mock.key --ssl-certfile /tmp/mock.crt

    /tmp/sdk-venv/bin/python scripts/sdk_smoke.py --base-url https://127.0.0.1:8101 \\
        --ca-file /tmp/mock.crt --xsoar-dir /tmp/xsoar --fetch-xsoar --reset

Against an http base URL the Graph, Defender and Sentinel workflows are
reported SKIP. Exit status 1 when any vendor fails (or, with --strict, is
skipped).
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import importlib.metadata
import importlib.util
import json
import os
import ssl
import sys
import time
import traceback
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

TENANT = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
S1_ADMIN = "admin-token-0000-0000-000000000001"
XSOAR_FILES = {
    "SentinelOne-V2.py": "Packs/SentinelOne/Integrations/SentinelOne-V2/SentinelOne-V2.py",
    "CortexXDRIR.py": "Packs/CortexXDR/Integrations/CortexXDRIR/CortexXDRIR.py",
    "CoreIRApiModule.py": "Packs/ApiModules/Scripts/CoreIRApiModule/CoreIRApiModule.py",
    "CommonServerPython.py": "Packs/Base/Scripts/CommonServerPython/CommonServerPython.py",
    "demistomock.py": "Tests/demistomock/demistomock.py",
}


# ── Bookkeeping ──────────────────────────────────────────────────────────────


class StepFailed(Exception):
    """A workflow step failed; carries the step's name."""

    def __init__(self, step: str, error: str) -> None:
        super().__init__(f"{step}: {error}")
        self.step = step
        self.error = error


class Skip(Exception):
    """The vendor cannot be exercised in this setup."""


@dataclass
class Outcome:
    vendor: str
    sdk: str = ""
    status: str = "PASS"
    steps: list[str] = field(default_factory=list)
    failed_step: str = ""
    error: str = ""
    seconds: float = 0.0


class Steps:
    """Run named steps in order; the first that raises ends the workflow."""

    def __init__(self, outcome: Outcome, verbose: bool) -> None:
        self.outcome = outcome
        self.verbose = verbose

    def __call__(self, name: str, fn: Callable[[], Any]) -> Any:
        try:
            value = fn()
        except (StepFailed, Skip):
            raise
        except Exception as exc:
            if self.verbose:
                traceback.print_exc()
            raise StepFailed(name, f"{type(exc).__name__}: {str(exc)[:300]}") from exc
        self.outcome.steps.append(name)
        if self.verbose:
            print(f"    ok  {self.outcome.vendor}: {name}")
        return value


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_raise(fn: Callable[[], Any], exc_type: type | tuple, why: str) -> BaseException:
    try:
        fn()
    except exc_type as exc:
        return exc
    except Exception as exc:
        msg = f"{why}: raised {type(exc).__name__}, wanted {exc_type}: {exc}"
        raise AssertionError(msg) from exc
    msg = f"{why}: nothing was raised"
    raise AssertionError(msg)


def version(*dists: str) -> str:
    found = []
    for dist in dists:
        try:
            found.append(f"{dist} {importlib.metadata.version(dist)}")
        except importlib.metadata.PackageNotFoundError:
            pass
    return ", ".join(found)


def require(*modules: str) -> None:
    for name in modules:
        if importlib.util.find_spec(name.split(".")[0]) is None:
            msg = f"{name} is not installed in this interpreter"
            raise Skip(msg)


@dataclass
class Config:
    base: str
    ca_file: str | None
    xsoar_dir: Path | None
    verbose: bool

    @property
    def https(self) -> bool:
        return self.base.startswith("https://")

    @property
    def verify(self) -> bool | str:
        return self.ca_file or True

    def need_tls(self, what: str) -> None:
        if not self.https:
            msg = f"plain http is refused by {what}; run the mock with TLS (see the header)"
            raise Skip(msg)


def dev(cfg: Config, method: str, path: str, body: dict | None = None) -> dict:
    """Call a /_dev route (they live under the S1 prefix, admin token)."""
    import requests

    response = requests.request(
        method, f"{cfg.base}/web/api/v2.1/_dev/{path}", json=body, timeout=30,
        headers={"Authorization": f"ApiToken {S1_ADMIN}"}, verify=cfg.verify,
    )
    response.raise_for_status()
    return response.json() if response.content else {}


class RateLimited:
    """The dev rate limiter switched on for the duration of a block."""

    def __init__(self, cfg: Config, rpm: int) -> None:
        self.cfg, self.rpm = cfg, rpm

    def __enter__(self) -> RateLimited:
        dev(self.cfg, "POST", "rate-limit", {"enabled": True, "requestsPerMinute": self.rpm})
        return self

    def __exit__(self, *exc: object) -> None:
        dev(self.cfg, "POST", "rate-limit", {"enabled": False, "requestsPerMinute": 60})


# ── CrowdStrike: falconpy ────────────────────────────────────────────────────


def crowdstrike(cfg: Config, step: Steps) -> None:
    require("falconpy")
    from falconpy import IOC, Alerts, Hosts, OAuth2

    base = f"{cfg.base}/cs"
    auth = OAuth2(client_id="cs-mock-admin-client", client_secret="cs-mock-admin-secret",
                  base_url=base, ssl_verify=cfg.verify)

    def token():
        r = auth.token()
        check(r["status_code"] == 201 and r["body"].get("access_token"), str(r))
    step("oauth2 token", token)
    hosts = Hosts(auth_object=auth)

    def scroll():
        seen, offset = set(), None
        for _ in range(100):
            r = hosts.query_devices_by_filter_scroll(limit=13, offset=offset)
            check(r["status_code"] == 200, str(r["body"]))
            page = r["body"]["resources"]
            seen.update(page)
            pagination = r["body"]["meta"]["pagination"]
            offset = pagination.get("offset")
            if not page or len(seen) >= pagination["total"]:
                check(len(seen) == pagination["total"], f"{len(seen)} != {pagination['total']}")
                return sorted(seen)
        raise AssertionError("scroll never ended")
    ids = step("hosts: scroll to the end", scroll)

    def offset_paging():
        seen, offset = [], 0
        while True:
            r = hosts.query_devices_by_filter(limit=17, offset=offset, sort="hostname.asc")
            page = r["body"]["resources"]
            seen += page
            offset += len(page)
            if not page or offset >= r["body"]["meta"]["pagination"]["total"]:
                break
        check(sorted(seen) == ids, "offset paging and scroll disagree")
    step("hosts: offset paging", offset_paging)

    def filtered():
        r = hosts.query_devices_by_filter(filter="platform_name:'Windows'", limit=100)
        check(r["status_code"] == 200, str(r["body"]))
        details = hosts.get_device_details(ids=r["body"]["resources"][:20])["body"]["resources"]
        check(details and all(d["platform_name"] == "Windows" for d in details), "filter leaked")
    step("hosts: FQL filter + details", filtered)

    def contain():
        target = ids[0]
        r = hosts.perform_action(action_name="contain", ids=[target])
        check(r["status_code"] == 202, str(r["body"]))
        status = hosts.get_device_details(ids=[target])["body"]["resources"][0]["status"]
        check(status in ("containment_pending", "contained"), status)
        for _ in range(20):
            status = hosts.get_device_details(ids=[target])["body"]["resources"][0]["status"]
            if status == "contained":
                break
            time.sleep(0.5)
        check(status == "contained", f"never contained: {status}")
        r = hosts.perform_action(action_name="lift_containment", ids=[target])
        check(r["status_code"] == 202, str(r["body"]))
    step("hosts: contain, poll, lift", contain)

    alerts = Alerts(auth_object=auth)

    def alert_flow():
        r = alerts.query_alerts_v2(limit=5, filter="status:'new'")
        check(r["status_code"] == 200, str(r["body"]))
        composite = r["body"]["resources"]
        check(composite, "no new alerts")
        got = alerts.get_alerts_v2(composite_ids=composite[:2])
        check(len(got["body"]["resources"]) == len(composite[:2]), str(got["body"]))
        upd = alerts.update_alerts_v3(composite_ids=composite[:1], update_status="in_progress")
        check(upd["status_code"] == 200, str(upd["body"]))
        again = alerts.get_alerts_v2(composite_ids=composite[:1])["body"]["resources"][0]
        check(again["status"] == "in_progress", again["status"])
    step("alerts v2: query, get, update", alert_flow)

    ioc = IOC(auth_object=auth)

    def ioc_flow():
        r = ioc.indicator_create(type="domain", value="sdk-smoke.example.com", action="detect",
                                 platforms=["windows"], severity="high", applied_globally=True,
                                 comment="sdk smoke")
        check(r["status_code"] == 201, str(r["body"]))
        iid = r["body"]["resources"][0]["id"]
        check(ioc.indicator_get(ids=[iid])["body"]["resources"][0]["id"] == iid, "get")
        check(ioc.indicator_delete(ids=[iid])["status_code"] == 200, "delete")
    step("IOC: create, get, delete", ioc_flow)

    def bad_credentials():
        r = OAuth2(client_id="nope", client_secret="nope", base_url=base,
                   ssl_verify=cfg.verify).token()
        check(r["status_code"] == 401, str(r))
        check(r["body"]["errors"][0]["code"] == 401, str(r["body"]))
    step("bad credentials -> 401", bad_credentials)

    def unknown_route():
        r = hosts.get_device_details(ids=["0" * 32])
        check(r["status_code"] in (200, 404) and not r["body"]["resources"], str(r["body"]))
    step("unknown id -> no resource", unknown_route)

    def throttled():
        with RateLimited(cfg, 2):
            codes = [hosts.query_devices_by_filter(limit=1) for _ in range(4)]
        last = codes[-1]
        check(last["status_code"] == 429, f"{[c['status_code'] for c in codes]}")
        headers = {k.lower(): v for k, v in last["headers"].items()}
        check(int(headers["x-ratelimit-retryafter"]) > time.time() - 5,
              "X-RateLimit-RetryAfter is not a future epoch")
    step("429 with X-RateLimit-RetryAfter", throttled)


# ── Microsoft Graph: msgraph-sdk + azure-identity ────────────────────────────


def graph(cfg: Config, step: Steps) -> None:
    require("msgraph", "azure.identity", "msal")
    cfg.need_tls("azure-identity")
    import msal
    from azure.core.exceptions import ClientAuthenticationError
    from azure.identity import ClientSecretCredential
    from azure.identity.aio import ClientSecretCredential as AsyncCredential
    from kiota_abstractions.api_error import APIError
    from kiota_abstractions.base_request_configuration import RequestConfiguration
    from msgraph import GraphServiceClient
    from msgraph.generated.models.security.alert import Alert
    from msgraph.generated.models.security.alert_status import AlertStatus
    RunHuntingQueryPostRequestBody = importlib.import_module(  # noqa: N806
        "msgraph.generated.security.microsoft_graph_security_run_hunting_query"
        ".run_hunting_query_post_request_body").RunHuntingQueryPostRequestBody
    from msgraph.generated.users.users_request_builder import UsersRequestBuilder
    from msgraph_core import PageIterator

    authority = f"{cfg.base}/graph"
    scope = "https://graph.microsoft.com/.default"

    def msal_token():
        app = msal.ConfidentialClientApplication(
            "graph-mock-admin-client", client_credential="graph-mock-admin-secret",
            authority=f"{authority}/{TENANT}", instance_discovery=False)
        r = app.acquire_token_for_client(scopes=[scope])
        check("access_token" in r, str(r))
        bad = msal.ConfidentialClientApplication(
            "graph-mock-admin-client", client_credential="nope",
            authority=f"{authority}/{TENANT}", instance_discovery=False)
        r = bad.acquire_token_for_client(scopes=[scope])
        check(r.get("error") == "invalid_client" and 7000215 in r.get("error_codes", []), str(r))
    step("MSAL: discovery + token, bad secret", msal_token)

    def azid_token():
        cred = ClientSecretCredential(TENANT, "graph-mock-admin-client", "graph-mock-admin-secret",
                                      authority=authority, disable_instance_discovery=True)
        check(bool(cred.get_token(scope).token), "no token")
        bad = ClientSecretCredential(TENANT, "graph-mock-admin-client", "nope",
                                     authority=authority, disable_instance_discovery=True)
        expect_raise(lambda: bad.get_token(scope), ClientAuthenticationError, "bad secret")
    step("azure-identity: token, bad secret raises", azid_token)

    async def workflow() -> None:
        def client_for(cid: str, secret: str) -> GraphServiceClient:
            cred = AsyncCredential(TENANT, cid, secret, authority=authority,
                                   disable_instance_discovery=True)
            c = GraphServiceClient(credentials=cred, scopes=[scope])
            c.request_adapter.base_url = f"{authority}/v1.0"
            return c

        client = client_for("graph-mock-admin-client", "graph-mock-admin-secret")

        async def users_pager():
            params = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
                top=5, select=["id", "displayName", "userPrincipalName"])
            first = await client.users.get(RequestConfiguration(query_parameters=params))
            check(first.odata_next_link is not None, "no nextLink on a 5-user page")
            ids: list[str] = []
            await PageIterator(first, client.request_adapter).iterate(
                lambda u: ids.append(u.id) or True)
            check(len(ids) == len(set(ids)) > 5, f"{len(ids)} ids, {len(set(ids))} distinct")
            return ids
        ids = await astep("users: PageIterator to the end", users_pager)

        async def user_get():
            user = await client.users.by_user_id(ids[0]).get()
            check(user.id == ids[0], "wrong user")
            try:
                await client.users.by_user_id("00000000-0000-0000-0000-000000000000").get()
            except APIError as exc:
                check(exc.response_status_code == 404, str(exc.response_status_code))
                check(exc.error is not None and exc.error.code == "Request_ResourceNotFound",
                      str(exc.error and exc.error.code))
                return
            raise AssertionError("an unknown user did not raise")
        await astep("users: get, unknown id raises ODataError 404", user_get)

        async def alerts():
            page = await client.security.alerts_v2.get()
            check(page.value, "no alerts")
            alert = page.value[0]
            updated = await client.security.alerts_v2.by_alert_id(alert.id).patch(
                Alert(status=AlertStatus.InProgress))
            check(updated is not None and updated.status == AlertStatus.InProgress, "status")
            incidents = await client.security.incidents.get()
            check(incidents.value, "no incidents")
        await astep("security: alerts_v2 patch, incidents", alerts)

        async def hunting():
            run = client.security.microsoft_graph_security_run_hunting_query
            wide = await run.post(RunHuntingQueryPostRequestBody(
                query="DeviceNetworkEvents | project Timestamp", timespan="P30D"))
            narrow = await run.post(RunHuntingQueryPostRequestBody(
                query="DeviceNetworkEvents | project Timestamp", timespan="P1D"))
            check(wide.results and len(narrow.results) < len(wide.results),
                  f"timespan ignored: {len(narrow.results)} vs {len(wide.results)}")
            summary = await run.post(RunHuntingQueryPostRequestBody(
                query="DeviceInfo | summarize c=count() by OSPlatform"))
            check([s.name for s in summary.schema] == ["OSPlatform", "c"], "schema")
        await astep("runHuntingQuery: DeviceNetworkEvents + timespan", hunting)

        async def intune():
            devices = await client.device_management.managed_devices.get()
            check(devices.value, "no managed devices")
            await client.device_management.managed_devices.by_managed_device_id(
                devices.value[0].id).sync_device.post()
        await astep("intune: managedDevices + syncDevice", intune)

        async def plan_gate():
            p1 = client_for("graph-mock-p1-client", "graph-mock-p1-secret")
            try:
                await p1.security.microsoft_graph_security_run_hunting_query.post(
                    RunHuntingQueryPostRequestBody(query="DeviceInfo | take 1"))
            except APIError as exc:
                check(exc.response_status_code == 403, str(exc.response_status_code))
                return
            raise AssertionError("a Plan 1 hunt was not refused")
        await astep("plan 1 hunt -> ODataError 403", plan_gate)

    async def astep(name: str, fn: Callable[[], Any]) -> Any:
        try:
            value = await fn()
        except (StepFailed, Skip):
            raise
        except Exception as exc:
            if cfg.verbose:
                traceback.print_exc()
            raise StepFailed(name, f"{type(exc).__name__}: {str(exc)[:300]}") from exc
        step.outcome.steps.append(name)
        return value

    asyncio.run(workflow())


# ── Defender for Endpoint: azure-identity + requests ─────────────────────────


def defender(cfg: Config, step: Steps) -> None:
    require("azure.identity", "requests")
    cfg.need_tls("azure-identity")
    import requests
    from azure.identity import ClientSecretCredential

    base = f"{cfg.base}/mde"
    cred = ClientSecretCredential(TENANT, "mde-mock-admin-client", "mde-mock-admin-secret",
                                  authority=base, disable_instance_discovery=True)
    token = step("azure-identity token (securitycenter scope)", lambda: cred.get_token(
        "https://api.securitycenter.microsoft.com/.default").token)
    s = requests.Session()
    s.verify = cfg.verify
    s.headers["Authorization"] = f"Bearer {token}"

    def machines():
        url, ids = f"{base}/api/machines?$top=7", []
        while url:
            body = s.get(url, timeout=30).json()
            ids += [m["id"] for m in body["value"]]
            url = body.get("@odata.nextLink")
        check(len(ids) == len(set(ids)) > 7, f"{len(ids)} machines")
        return ids
    ids = step("machines: follow @odata.nextLink", machines)

    def isolate():
        r = s.post(f"{base}/api/machines/{ids[0]}/isolate",
                   json={"Comment": "sdk smoke", "IsolationType": "Full"}, timeout=30)
        check(r.status_code == 201, r.text)
        action = r.json()["id"]
        for _ in range(30):
            status = s.get(f"{base}/api/machineactions/{action}", timeout=30).json()["status"]
            if status in ("Succeeded", "Failed", "Cancelled", "TimeOut"):
                break
            time.sleep(0.5)
        check(status == "Succeeded", status)
        r = s.post(f"{base}/api/machines/{ids[0]}/unisolate", json={"Comment": "x"}, timeout=30)
        check(r.status_code == 201, r.text)
    step("isolate, poll machineaction, unisolate", isolate)

    def hunt():
        r = s.post(f"{base}/api/advancedqueries/run",
                   json={"Query": "DeviceNetworkEvents | take 3"}, timeout=30)
        check(r.status_code == 200 and r.json()["Results"], r.text[:200])
    step("advanced hunting", hunt)

    def errors():
        r = s.get(f"{base}/api/machines/{'0' * 40}", timeout=30)
        check(r.status_code == 404 and r.json()["error"]["code"] == "ResourceNotFound", r.text)
        r = requests.get(f"{base}/api/machines", headers={"Authorization": "Bearer nope"},
                         verify=cfg.verify, timeout=30)
        check(r.status_code == 401, r.text)
    step("404 and 401 envelopes", errors)


# ── Microsoft Sentinel: azure-mgmt-securityinsight + azure-monitor-query ─────


def sentinel(cfg: Config, step: Steps) -> None:
    require("azure.mgmt.securityinsight", "azure.monitor.query", "azure.identity")
    cfg.need_tls("azure-identity and azure-core")
    from azure.core.exceptions import ClientAuthenticationError, ResourceNotFoundError
    from azure.identity import ClientSecretCredential
    from azure.mgmt.securityinsight import SecurityInsights
    from azure.mgmt.securityinsight.models import IncidentComment
    from azure.monitor.query import LogsQueryClient, LogsQueryStatus

    authority = f"{cfg.base}/sentinel"
    sub, rg, ws = "00000000-0000-0000-0000-000000000000", "mockdr-rg", "mockdr-workspace"
    arm = ["https://management.azure.com/.default"]
    cred = ClientSecretCredential(TENANT, "sentinel-mock-client-id", "sentinel-mock-client-secret",
                                  authority=authority, disable_instance_discovery=True)
    step("azure-identity token (ARM scope)", lambda: cred.get_token(arm[0]).token)
    si = SecurityInsights(cred, sub, base_url=authority, credential_scopes=arm)

    def incidents():
        pages = list(si.incidents.list(rg, ws, top=7).by_page())
        names = [i.name for page in pages for i in page]
        check(len(pages) > 1 and len(names) == len(set(names)), f"{len(pages)} pages")
        return names
    names = step("incidents: by_page to the end", incidents)

    def update():
        incident = si.incidents.get(rg, ws, names[0])
        incident.status = "Active"
        updated = si.incidents.create_or_update(rg, ws, incident.name, incident)
        check(updated.status == "Active", str(updated.status))
        comment = si.incident_comments.create_or_update(
            rg, ws, incident.name, "sdk-smoke-comment", IncidentComment(message="sdk smoke"))
        check(comment.message == "sdk smoke", "comment")
        check(si.incidents.list_alerts(rg, ws, incident.name).value is not None, "alerts")
    step("incident: get, update, comment, alerts", update)

    def collections():
        for listing in (si.alert_rules, si.watchlists, si.bookmarks, si.data_connectors):
            check(list(listing.list(rg, ws)), f"{listing} is empty")
    step("alert rules, watchlists, bookmarks, connectors", collections)

    def errors():
        expect_raise(lambda: si.incidents.get(rg, ws, "no-such-incident"), ResourceNotFoundError,
                     "unknown incident")
        bad = SecurityInsights(
            ClientSecretCredential(TENANT, "sentinel-mock-client-id", "nope",
                                   authority=authority, disable_instance_discovery=True),
            sub, base_url=authority, credential_scopes=arm)
        expect_raise(lambda: list(bad.incidents.list(rg, ws)), ClientAuthenticationError,
                     "bad secret")
    step("ResourceNotFoundError, ClientAuthenticationError", errors)

    def logs():
        lq = LogsQueryClient(cred, endpoint=authority, audience="https://api.loganalytics.io")
        wide = lq.query_workspace("mockdr-workspace", "SecurityIncident | project TimeGenerated",
                                  timespan=timedelta(days=365))
        narrow = lq.query_workspace("mockdr-workspace", "SecurityIncident | project TimeGenerated",
                                    timespan=timedelta(days=1))
        check(wide.status == LogsQueryStatus.SUCCESS, str(wide.status))
        check(len(narrow.tables[0].rows) < len(wide.tables[0].rows), "timespan ignored")
    step("Log Analytics: query_workspace + timespan", logs)


# ── Elasticsearch: elasticsearch-py ──────────────────────────────────────────


def elasticsearch(cfg: Config, step: Steps) -> None:
    require("elasticsearch")
    import elasticsearch as es_module
    from elasticsearch import (
        ApiError,
        AuthenticationException,
        BadRequestError,
        Elasticsearch,
        NotFoundError,
        helpers,
    )

    url = f"{cfg.base}/elastic"
    tls = {"ca_certs": cfg.ca_file} if cfg.ca_file else {}
    es = Elasticsearch(url, basic_auth=("elastic", "mock-elastic-password"), **tls)
    index = "sdk-smoke"
    step("info + ping", lambda: check(es.ping() and es.info()["version"]["number"], "ping"))
    step("reset the index", lambda: es.indices.delete(index=index, ignore_unavailable=True))

    def writes():
        es.index(index=index, id="1", document={"n": 1, "msg": "hello"})
        check(es.count(index=index)["count"] == 0, "visible before a refresh")
        es.indices.refresh(index=index)
        check(es.get(index=index, id="1")["_source"]["n"] == 1, "get")
        ok, errors = helpers.bulk(es, ({"_index": index, "_id": str(n), "n": n}
                                       for n in range(2, 60)), refresh=True)
        check(ok == 58 and not errors, f"{ok} {errors}")
        es.update(index=index, id="1", doc={"tag": "x"}, refresh=True)
    step("index, refresh, helpers.bulk, update", writes)

    def reads():
        check(len(list(helpers.scan(es, index=index, size=7))) == 59, "scan")
        pit = es.open_point_in_time(index=index, keep_alive="1m")["id"]
        seen, after = [], None
        while True:
            kw: dict = {"size": 9, "pit": {"id": pit, "keep_alive": "1m"}, "sort": [{"n": "asc"}]}
            if after:
                kw["search_after"] = after
            hits = es.search(**kw)["hits"]["hits"]
            if not hits:
                break
            seen += [h["_source"]["n"] for h in hits]
            after = hits[-1]["sort"]
        es.close_point_in_time(id=pit)
        check(seen == list(range(1, 60)), "PIT + search_after")
        r = es.search(index=index, query={"range": {"n": {"gte": 50}}}, size=0)
        check(r["hits"]["total"]["value"] == 10, str(r["hits"]["total"]))
    step("scan, PIT + search_after, range query", reads)

    def errors():
        expect_raise(lambda: es.get(index=index, id="nope"), NotFoundError, "missing doc")
        exc = expect_raise(lambda: es.search(index="no-such-index-xyz"), NotFoundError, "index")
        check(exc.error == "index_not_found_exception", str(exc.error))
        expect_raise(lambda: es.search(index=index, query={"bogus": {}}), BadRequestError, "DSL")
        bad = Elasticsearch(url, basic_auth=("elastic", "nope"), **tls)
        expect_raise(lambda: bad.search(index=index), AuthenticationException, "bad password")
    step("NotFoundError, BadRequestError, AuthenticationException", errors)

    def api_key():
        keyed = Elasticsearch(url, api_key=("es-admin-key-001", "mock-es-admin-api-key"), **tls)
        check(keyed.count(index=index)["count"] == 59, "api key")
    step("API key auth", api_key)

    def throttled():
        quick = Elasticsearch(url, basic_auth=("elastic", "mock-elastic-password"),
                              max_retries=0, **tls)
        with RateLimited(cfg, 2):
            error = None
            for _ in range(4):
                try:
                    quick.count(index=index)
                except ApiError as exc:
                    error = exc
        check(error is not None and error.meta.status == 429, f"{error!r}")
    step("429 -> ApiError(status=429)", throttled)
    step.outcome.sdk = f"elasticsearch {es_module.__versionstr__}"
    es.indices.delete(index=index, ignore_unavailable=True)


# ── Kibana: requests, as Elastic's API reference does ────────────────────────


def kibana(cfg: Config, step: Steps) -> None:
    require("requests")
    import requests

    base = f"{cfg.base}/kibana"
    s = requests.Session()
    s.verify = cfg.verify
    s.auth = ("elastic", "mock-elastic-password")
    xsrf = {"kbn-xsrf": "true"}

    def rules():
        ids, page = [], 1
        while True:
            body = s.get(f"{base}/api/detection_engine/rules/_find",
                         params={"page": page, "per_page": 7}, timeout=30).json()
            ids += [r["id"] for r in body["data"]]
            if page * 7 >= body["total"]:
                break
            page += 1
        check(len(ids) == len(set(ids)) == body["total"], "rule paging")
    step("rules: _find to the end", rules)

    def rule_crud():
        refused = s.post(f"{base}/api/detection_engine/rules", json={"name": "x"}, timeout=30)
        check(refused.status_code == 400, "a write without kbn-xsrf was accepted")
        created = s.post(f"{base}/api/detection_engine/rules", headers=xsrf, timeout=30, json={
            "name": "sdk smoke", "description": "d", "risk_score": 21, "severity": "low",
            "type": "query", "query": "host.name:*", "language": "kuery", "index": ["logs-*"]})
        check(created.status_code == 200, created.text[:200])
        rid = created.json()["id"]
        r = s.post(f"{base}/api/detection_engine/rules/_bulk_action", headers=xsrf, timeout=30,
                   json={"action": "disable", "ids": [rid]})
        check(r.status_code == 200, r.text[:200])
        check(s.delete(f"{base}/api/detection_engine/rules", headers=xsrf, params={"id": rid},
                       timeout=30).status_code == 200, "delete")
        check(s.get(f"{base}/api/detection_engine/rules", params={"id": rid},
                    timeout=30).status_code == 404, "deleted rule still found")
    step("rules: kbn-xsrf, create, bulk disable, delete, 404", rule_crud)

    def signals():
        r = s.post(f"{base}/api/detection_engine/signals/search", headers=xsrf, timeout=30,
                   json={"query": {"bool": {"filter": [
                       {"term": {"kibana.alert.workflow_status": "open"}}]}}, "size": 3})
        hits = r.json()["hits"]["hits"]
        check(hits, "no open alerts")
        r = s.post(f"{base}/api/detection_engine/signals/status", headers=xsrf, timeout=30,
                   json={"signal_ids": [hits[0]["_id"]], "status": "acknowledged"})
        check(r.json().get("updated") == 1, r.text[:200])
    step("alerts: search, set status", signals)

    def cases():
        r = s.post(f"{base}/api/cases", headers=xsrf, timeout=30, json={
            "title": "sdk smoke", "description": "d", "tags": [], "owner": "securitySolution",
            "connector": {"id": "none", "name": "none", "type": ".none", "fields": None},
            "settings": {"syncAlerts": False}})
        check(r.status_code == 200, r.text[:200])
        case = r.json()
        s.post(f"{base}/api/cases/{case['id']}/comments", headers=xsrf, timeout=30,
               json={"type": "user", "comment": "hi", "owner": "securitySolution"})
        version = s.get(f"{base}/api/cases/{case['id']}", timeout=30).json()["version"]
        r = s.patch(f"{base}/api/cases", headers=xsrf, timeout=30,
                    json={"cases": [{"id": case["id"], "version": version, "status": "closed"}]})
        check(r.status_code == 200 and r.json()[0]["status"] == "closed", r.text[:200])
    step("cases: create, comment, close", cases)

    def isolate():
        listed = s.get(f"{base}/api/endpoint/metadata", params={"pageSize": 1}, timeout=30).json()
        agent = listed["data"][0]["metadata"]["agent"]["id"]
        r = s.post(f"{base}/api/endpoint/action/isolate", headers=xsrf, timeout=30,
                   json={"endpoint_ids": [agent], "comment": "sdk smoke"})
        check(r.status_code == 200, r.text[:200])
        action = r.json()["data"]["id"]
        for _ in range(20):
            details = s.get(f"{base}/api/endpoint/action/{action}", timeout=30).json()["data"]
            if details["isCompleted"]:
                break
            time.sleep(0.5)
        check(details["isCompleted"] and details["wasSuccessful"], str(details)[:200])
        r = s.post(f"{base}/api/endpoint/action/unisolate", headers=xsrf, timeout=30,
                   json={"endpoint_ids": [agent]})
        check(r.status_code == 200, r.text[:200])
    step("endpoint: isolate, poll data.isCompleted, release", isolate)

    def bad_auth():
        r = requests.get(f"{base}/api/detection_engine/rules/_find", auth=("elastic", "nope"),
                         verify=cfg.verify, timeout=30)
        check(r.status_code == 401, str(r.status_code))
    step("bad credentials -> 401", bad_auth)


# ── Splunk: splunk-sdk (splunklib) ───────────────────────────────────────────


def splunk(cfg: Config, step: Steps) -> None:
    require("splunklib")
    import splunklib.binding as binding
    import splunklib.client as client
    import splunklib.results as results

    parts = urlsplit(cfg.base)
    context = ssl.create_default_context(cafile=cfg.ca_file) if cfg.ca_file else None

    def handler():
        # splunklib has no path prefix; its documented extension point is a
        # custom HTTP handler, which here puts the mock's /splunk in front.
        base = binding.handler(context=context) if context else binding.handler()

        def request(url, message, **kwargs):
            p = urlsplit(url)
            return base(urlunsplit(p._replace(path="/splunk" + p.path)), message, **kwargs)
        return request

    def connect(password: str = "mockdr-admin"):
        return client.connect(scheme=parts.scheme, host=parts.hostname, port=parts.port,
                              username="admin", password=password, handler=handler(),
                              autologin=True)
    svc = step("login (client.connect)", connect)

    def collections():
        check("main" in [i.name for i in svc.indexes.list()], "indexes")
        check(len(svc.saved_searches.list()) > 0, "saved searches")
        check({"admin"} <= {u.name for u in svc.users.list()}, "users")
        check(len(svc.roles.list()) > 0, "roles")
    step("collections: indexes, saved searches, users, roles", collections)

    def job():
        job = svc.jobs.create("search index=* | head 25", exec_mode="normal")
        for _ in range(100):
            if job.is_done():
                break
            time.sleep(0.2)
        check(job["dispatchState"] == "DONE", job["dispatchState"])
        rows = [r for r in results.JSONResultsReader(job.results(output_mode="json", count=0))
                if isinstance(r, dict)]
        check(len(rows) == 25, f"{len(rows)} results")
        paged, offset = [], 0
        while True:
            page = [r for r in results.JSONResultsReader(
                job.results(output_mode="json", count=10, offset=offset)) if isinstance(r, dict)]
            if not page:
                break
            paged += page
            offset += len(page)
            check(offset <= 25, "results paging never ended")
        check(len(paged) == 25, f"{len(paged)} paged")
        preview = [r for r in results.JSONResultsReader(job.preview(output_mode="json"))
                   if isinstance(r, dict)]
        check(preview, "preview")
        job.cancel()
    step("job: create, poll is_done, results paged, preview", job)

    def blocking_and_export():
        job = svc.jobs.create("search index=* | stats count by sourcetype", exec_mode="blocking")
        check(job["dispatchState"] == "DONE", job["dispatchState"])
        exported = [r for r in results.JSONResultsReader(
            svc.jobs.export("search index=* | head 5", output_mode="json")) if isinstance(r, dict)]
        check(len(exported) == 5, f"{len(exported)} exported")
        oneshot = [r for r in results.JSONResultsReader(
            svc.jobs.oneshot("search index=* | head 3", output_mode="json")) if isinstance(r, dict)]
        check(len(oneshot) == 3, f"{len(oneshot)} oneshot")
    step("blocking job, export, oneshot", blocking_and_export)

    def kvstore():
        name = "sdk_smoke_kv"
        if name in svc.kvstore:
            svc.kvstore.delete(name)
        svc.kvstore.create(name, fields={"name": "string"})
        data = svc.kvstore[name].data
        data.insert(json.dumps({"name": "a"}))
        data.batch_save({"name": "b"}, {"name": "c"})
        check(len(data.query(query=json.dumps({"name": "b"}))) == 1, "query")
        svc.kvstore.delete(name)
    step("KV store: create, insert, batch_save, query", kvstore)

    def saved_search():
        name = "sdk_smoke_saved"
        if name in svc.saved_searches:
            svc.saved_searches.delete(name)
        saved = svc.saved_searches.create(name, "search index=* | head 2")
        job = saved.dispatch()
        for _ in range(100):
            if job.is_done():
                break
            time.sleep(0.2)
        check(job["resultCount"] == "2", job["resultCount"])
        svc.saved_searches.delete(name)
    step("saved search: create, dispatch, poll", saved_search)

    def errors():
        expect_raise(lambda: svc.jobs.create("| nosuchcommand"), binding.HTTPError, "bad SPL")
        exc = expect_raise(lambda: client.Job(svc, "nosuchsid").refresh(), binding.HTTPError, "sid")
        check(exc.status == 404, str(exc.status))
        expect_raise(lambda: connect("nope"), binding.AuthenticationError, "bad password")
    step("HTTPError 400/404, AuthenticationError", errors)

    def throttled():
        with RateLimited(cfg, 2):
            error = None
            for _ in range(4):
                try:
                    svc.indexes.list()
                except binding.HTTPError as exc:
                    error = exc
        check(error is not None and error.status == 429, f"{error!r}")
    step("429 -> HTTPError(status=429)", throttled)


# ── SentinelOne and Cortex XDR: the XSOAR integrations ───────────────────────


class Xsoar:
    """Load XSOAR integrations against a minimal demistomock shim."""

    _loaded: dict[str, Any] = {}

    def __init__(self, cfg: Config) -> None:
        if cfg.xsoar_dir is None or not (cfg.xsoar_dir / "CommonServerPython.py").exists():
            msg = "XSOAR sources not found; pass --xsoar-dir DIR (and --fetch-xsoar once)"
            raise Skip(msg)
        require("dateparser", "dateutil", "requests")
        directory = str(cfg.xsoar_dir)
        for stub in ("CommonServerUserPython.py", "DemistoClassApiModule.py"):
            path = cfg.xsoar_dir / stub
            if not path.exists():
                path.write_text("")
        if directory not in sys.path:
            sys.path.insert(0, directory)
        if cfg.ca_file:
            os.environ.setdefault("REQUESTS_CA_BUNDLE", cfg.ca_file)
        demisto = importlib.import_module("demistomock")
        self.state: dict[str, Any] = {"params": {}, "command": "", "args": {}, "results": [],
                                      "last_run": {}, "incidents": None, "ctx": {}}
        st = self.state
        demisto.params = lambda: st["params"]
        demisto.command = lambda: st["command"]
        demisto.args = lambda: st["args"]
        demisto.results = lambda r: st["results"].append(r)
        demisto.getLastRun = lambda: st["last_run"]
        demisto.setLastRun = lambda o: st.__setitem__("last_run", o)
        demisto.incidents = lambda inc=None: st.__setitem__("incidents", inc)
        demisto.getIntegrationContext = lambda: st["ctx"]
        demisto.setIntegrationContext = lambda c: st.__setitem__("ctx", c)
        demisto.integrationInstance = lambda: "sdk-smoke"
        for name in ("error", "info", "debug"):
            setattr(demisto, name, lambda *a, **k: None)
        self.dir = cfg.xsoar_dir

    def load(self, filename: str) -> Any:
        if filename not in self._loaded:
            spec = importlib.util.spec_from_file_location(filename[:-3].replace("-", "_"),
                                                          self.dir / filename)
            assert spec and spec.loader
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self._loaded[filename] = module
        return self._loaded[filename]

    def run(self, module: Any, params: dict, command: str, args: dict | None = None) -> Any:
        """Run one command through the integration's own main(); return its output."""
        self.state.update(params=params, command=command, args=dict(args or {}), results=[])
        try:
            module.main()
        except SystemExit:
            pass
        out = self.state["results"]
        errors = [r for r in out if isinstance(r, dict) and r.get("Type") == 4]
        if errors:
            raise AssertionError(str(errors[0].get("Contents"))[:300])
        result = out[-1] if out else None
        if hasattr(result, "outputs"):
            return result.outputs if result.outputs is not None else result.raw_response
        if isinstance(result, dict) and "Contents" in result:
            return result["Contents"]
        return result

    def refused(self, module: Any, params: dict, command: str, args: dict | None = None) -> str:
        try:
            self.run(module, params, command, args)
        except AssertionError as exc:
            return str(exc)
        msg = f"{command} succeeded where it should have been refused"
        raise AssertionError(msg)


def sentinelone(cfg: Config, step: Steps) -> None:
    xsoar = Xsoar(cfg)
    s1 = step("load SentinelOne-V2", lambda: xsoar.load("SentinelOne-V2.py"))
    step.outcome.sdk = "XSOAR SentinelOne-V2 (demisto/content)"
    params = {"url": cfg.base, "credentials": {"password": S1_ADMIN}, "api_version": "2.1",
              "fetch_type": "Threats", "fetch_time": "30 days", "fetch_limit": 50,
              "isFetch": True, "insecure": False}
    run = lambda command, args=None: xsoar.run(s1, params, command, args)  # noqa: E731

    step("test-module", lambda: check(run("test-module") == "ok", "not ok"))
    agents = step("list agents, by OS", lambda: run("sentinelone-list-agents", {"limit": "10"}))
    agent = agents[0].get("ID") or agents[0].get("id")
    step("get agent", lambda: check(run("sentinelone-get-agent", {"agent_id": agent}), "empty"))
    threats = step("get threats", lambda: run("sentinelone-get-threats", {"limit": "5"}))
    threat = threats[0].get("ID") or threats[0].get("id")

    def actions():
        for command, args in (
            ("sentinelone-disconnect-agent", {"agent_id": agent}),
            ("sentinelone-connect-agent", {"agent_id": agent}),
            ("sentinelone-initiate-endpoint-scan", {"agent_ids": agent}),
            ("sentinelone-mitigate-threat", {"action": "kill", "threat_ids": threat}),
            ("sentinelone-update-threats-verdict",
             {"threat_ids": threat, "verdict": "true_positive"}),
            ("sentinelone-update-threats-status", {"threat_ids": threat, "status": "in_progress"}),
            ("sentinelone-write-threat-note", {"threat_ids": threat, "note": "sdk smoke"}),
        ):
            out = run(command, args)
            check(isinstance(out, dict) and out.get("affected") == 1, f"{command}: {out}")
    step("disconnect, connect, scan, mitigate, verdict, status, note", actions)

    def reads():
        for command, args in (("sentinelone-get-activities", {"limit": "5"}),
                              ("sentinelone-get-sites", {}), ("sentinelone-get-groups", {}),
                              ("sentinelone-get-blocklist", {"limit": "5"}),
                              ("sentinelone-get-iocs", {"limit": "5"}),
                              ("sentinelone-get-threat-notes", {"threat_id": threat})):
            check(run(command, args), f"{command} came back empty")
    step("activities, sites, groups, blocklist, IOCs, notes", reads)

    def deep_visibility():
        query = run("sentinelone-create-query", {"query": "AgentName IS NOT EMPTY",
                                                 "from_date": "2026-01-01T00:00:00Z",
                                                 "to_date": "2030-01-01T00:00:00Z"})
        check(bool(query), "no query id")
    step("Deep Visibility: create query", deep_visibility)

    def fetch():
        xsoar.state["last_run"] = {}
        run("fetch-incidents")
        first = len(xsoar.state["incidents"] or [])
        run("fetch-incidents")
        second = len(xsoar.state["incidents"] or [])
        check(first > 0 and second == 0, f"fetched {first} then {second}")
    step("fetch-incidents twice (no duplicates)", fetch)

    def bad_token():
        message = xsoar.refused(s1, {**params, "credentials": {"password": "bogus"}}, "test-module")
        check("401" in message, message)
    step("bad token -> 401", bad_token)


def cortex_xdr(cfg: Config, step: Steps) -> None:
    xsoar = Xsoar(cfg)
    xdr = step("load CortexXDRIR", lambda: xsoar.load("CortexXDRIR.py"))
    step.outcome.sdk = "XSOAR CortexXDRIR + CoreIRApiModule (demisto/content)"
    params = {"url": f"{cfg.base}/xdr", "apikey_creds": {"password": "xdr-admin-secret"},
              "apikey_id_creds": {"password": "1"}, "fetch_time": "30 days", "max_fetch": "20"}
    run = lambda command, args=None: xsoar.run(xdr, params, command, args)  # noqa: E731

    step("test-module (advanced auth)", lambda: check(run("test-module") == "ok", "not ok"))
    incidents = step("get incidents", lambda: run("xdr-get-incidents",
                                                   {"limit": "5", "status": "new"}))
    incident = str(incidents[0]["incident_id"])

    def incident_flow():
        extra = run("xdr-get-incident-extra-data", {"incident_id": incident})
        check(extra, "no extra data")
        updated = run("xdr-update-incident", {"incident_id": incident,
                                              "status": "UNDER_INVESTIGATION"})
        check("updated" in str(updated), str(updated))
    step("incident extra data, update", incident_flow)
    endpoints = step("get endpoints", lambda: run("xdr-get-endpoints", {"limit": "5"}))
    endpoint = endpoints[0].get("endpoint_id") or endpoints[0].get("agent_id")

    def actions():
        isolated = run("xdr-isolate-endpoint", {"endpoint_id": endpoint})
        check(isolated.get("action_id"), str(isolated))
        scanned = run("xdr-endpoint-scan", {"endpoint_id_list": endpoint})
        check(scanned.get("action_id"), str(scanned))
        check(run("xdr-blocklist-files", {"hash_list": "a" * 64, "comment": "sdk smoke"}) is True,
              "blocklist")
    step("isolate, scan, blocklist", actions)

    def alerts():
        out = run("xdr-get-alerts", {"limit": "5", "severity": "high"})
        rows = out if isinstance(out, list) else (out or {}).get("alerts", [])
        check(rows, "no alerts")
        fields = [a.get("alert_fields", a) for a in rows]
        check(all(f.get("alert_name") and f.get("severity") == "SEV_040_HIGH" for f in fields),
              f"alert_fields are blank or unfiltered: {str(fields[0])[:200]}")
    step("xdr-get-alerts (filter_data -> alert_fields)", alerts)

    def reads():
        check(run("xdr-get-audit-management-logs", {"limit": "5"}), "audit logs")
        versions = run("xdr-get-distribution-versions")
        check(all(isinstance(v, list) for v in versions.values()), str(versions))
        check(run("xdr-get-policy", {"endpoint_id": endpoint}), "policy")
        check(run("xdr-list-users"), "users")
    step("audit logs, distribution versions, policy, users", reads)

    def fetch():
        xsoar.state["last_run"] = {}
        run("fetch-incidents")
        check(len(xsoar.state["incidents"] or []) > 0, "nothing fetched")
    step("fetch-incidents", fetch)

    def bad_key():
        message = xsoar.refused(xdr, {**params, "apikey_creds": {"password": "bogus"}},
                                "test-module")
        check("401" in message, message)
    step("bad key -> 401", bad_key)


def fetch_xsoar(target: Path, ref: str, ca_file: str | None) -> None:
    target.mkdir(parents=True, exist_ok=True)
    del ca_file  # GitHub's certificate, not the mock's
    for name, path in XSOAR_FILES.items():
        url = f"https://raw.githubusercontent.com/demisto/content/{ref}/{path}"
        with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310
            (target / name).write_bytes(response.read())
        print(f"  fetched {name} ({ref})")


# ── Driver ───────────────────────────────────────────────────────────────────

VENDORS: dict[str, tuple[Callable[[Config, Steps], None], tuple[str, ...]]] = {
    "crowdstrike": (crowdstrike, ("crowdstrike-falconpy",)),
    "graph": (graph, ("msgraph-sdk", "azure-identity", "msal")),
    "defender": (defender, ("azure-identity", "requests")),
    "sentinel": (sentinel, ("azure-mgmt-securityinsight", "azure-monitor-query",
                            "azure-identity")),
    "elasticsearch": (elasticsearch, ("elasticsearch",)),
    "kibana": (kibana, ("requests",)),
    "splunk": (splunk, ("splunk-sdk",)),
    "sentinelone": (sentinelone, ()),
    "cortex_xdr": (cortex_xdr, ()),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--base-url", default="https://127.0.0.1:8101",
                        help="the running mock, scheme and port, no path")
    parser.add_argument("--ca-file", help="the mock's TLS certificate, to verify against")
    parser.add_argument("--xsoar-dir", type=Path,
                        help="where the XSOAR integration sources are (or go, with --fetch-xsoar)")
    parser.add_argument("--fetch-xsoar", action="store_true",
                        help="download the XSOAR sources into --xsoar-dir first")
    parser.add_argument("--xsoar-ref", default="master", help="demisto/content ref to fetch")
    parser.add_argument("--reset", action="store_true", help="POST /_dev/reset before starting")
    parser.add_argument("--vendor", action="append", choices=sorted(VENDORS),
                        help="run only these (repeatable)")
    parser.add_argument("--strict", action="store_true", help="a SKIP fails the run too")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    cfg = Config(base=args.base_url.rstrip("/"), ca_file=args.ca_file,
                 xsoar_dir=args.xsoar_dir, verbose=args.verbose)
    if cfg.ca_file:
        # httpx (msgraph), aiohttp (azure-identity aio) and requests each
        # read one of these; the SDKs that take an argument get it as well.
        os.environ["SSL_CERT_FILE"] = cfg.ca_file
        os.environ["REQUESTS_CA_BUNDLE"] = cfg.ca_file
    if args.fetch_xsoar:
        if not args.xsoar_dir:
            parser.error("--fetch-xsoar needs --xsoar-dir")
        fetch_xsoar(args.xsoar_dir, args.xsoar_ref, cfg.ca_file)
    if args.reset:
        dev(cfg, "POST", "reset")

    outcomes: list[Outcome] = []
    for name in args.vendor or list(VENDORS):
        fn, dists = VENDORS[name]
        outcome = Outcome(vendor=name, sdk=version(*dists))
        started = time.monotonic()
        try:
            fn(cfg, Steps(outcome, cfg.verbose))
        except Skip as exc:
            outcome.status, outcome.error = "SKIP", str(exc)
        except StepFailed as exc:
            outcome.status, outcome.failed_step, outcome.error = "FAIL", exc.step, exc.error
        except Exception as exc:
            outcome.status, outcome.error = "FAIL", f"{type(exc).__name__}: {exc}"
        finally:
            try:
                dev(cfg, "POST", "rate-limit", {"enabled": False, "requestsPerMinute": 60})
            except Exception:
                pass
        outcome.seconds = time.monotonic() - started
        outcomes.append(outcome)
        print(f"{outcome.status:4}  {name:13} {len(outcome.steps):2} steps  "
              f"{outcome.seconds:5.1f}s  {outcome.sdk}")
        if outcome.status != "PASS":
            where = f" at '{outcome.failed_step}'" if outcome.failed_step else ""
            print(f"      {outcome.status.lower()}{where}: {outcome.error}")

    failed = [o for o in outcomes if o.status == "FAIL"]
    skipped = [o for o in outcomes if o.status == "SKIP"]
    print(f"\n{len(outcomes) - len(failed) - len(skipped)} passed, {len(failed)} failed, "
          f"{len(skipped)} skipped, {sum(len(o.steps) for o in outcomes)} steps")
    return 1 if failed or (args.strict and skipped) else 0


if __name__ == "__main__":
    sys.exit(main())
