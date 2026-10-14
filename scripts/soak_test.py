# ruff: noqa: ANN001, ANN201, ANN202, ANN206, D102, D103, D107, E402, PLR2004, S101, S110, T201, PLR0915, S311, BLE001
# A release tool, not library code: every function is local to this file and
# sys.path is set before the project imports on purpose.
"""Run a long day of client traffic and say what grew.

Every test runs against a seed seconds old; a real integration — and the
public demo — talks to an instance hours or days after it was seeded, under
steady traffic. This script plays that traffic in-process: the polls, token
fetches, searches, actions and acknowledgements the eight vendors' clients
send, in a fixed mix, for as many requests as asked. It samples the size of
every store collection and every module-level cache the server keeps,
and the process RSS, as it goes.

A size that tracks the request count instead of levelling off is the
finding: something a long-running instance keeps for ever. Anything that
grows past ``--allow`` per 10,000 requests in the second half of the run (so
the warm-up does not count) is listed, and the exit code is 1.

    backend/.venv/bin/python scripts/soak_test.py [--requests 50000] [--allow 50]
          [--advance SECONDS]

``--advance`` moves the clock forward by that many seconds after each
request (default 3 — 50,000 requests are about 42 simulated hours, past the
day a spent token is kept), so expiries, TTLs and the housekeeping sweep act
as they would on an instance two days old. A collection that grows only up
to a documented cap or lifetime is reported with it and is not a finding.
The clock is moved by patching ``time.time`` and ``datetime.now`` in every
loaded module; nothing sleeps.
"""

import argparse
import base64
import datetime as _dt
import gc
import logging
import random
import resource
import sys
import time as _time
import uuid
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
logging.disable(logging.CRITICAL)
warnings.filterwarnings("ignore")

_real_time = _time.time
_real_monotonic = _time.monotonic
_real_dt = _dt.datetime
_OFFSET = [0.0]


class _ShiftedDatetime(_real_dt):
    @classmethod
    def now(cls, tz=None):
        return _real_dt.now(tz) + _dt.timedelta(seconds=_OFFSET[0])


def _install_clock() -> None:
    _time.time = lambda: _real_time() + _OFFSET[0]
    _time.monotonic = lambda: _real_monotonic() + _OFFSET[0]
    for module in list(sys.modules.values()):
        try:
            if getattr(module, "datetime", None) is _real_dt:
                module.datetime = _ShiftedDatetime
        except Exception:
            pass


from fastapi.testclient import TestClient
from main import app

S1 = "/web/api/v2.1"
S1_AUTH = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}
XDR_AUTH = {"x-xdr-auth-id": "1", "Authorization": "xdr-admin-secret"}
ES_AUTH = {"Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode()}
SPLUNK_BASIC = {"Authorization": "Basic " + base64.b64encode(b"admin:mockdr-admin").decode()}
HEC = {"Authorization": "Splunk 33333333-3333-3333-3333-333333333333"}
WS = (
    "/sentinel/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/mockdr-rg"
    "/providers/Microsoft.OperationalInsights/workspaces/mockdr-workspace"
    "/providers/Microsoft.SecurityInsights"
)


class Clients:
    """Credentials the simulated clients hold, refreshed the way SDKs do."""

    def __init__(self, c: TestClient) -> None:
        self.c = c
        self.cs = self.mde = self.graph = self.sentinel = self.splunk = ""
        self.es = ""

    def token(self, vendor: str, fresh: bool = False) -> dict:
        if vendor == "cs" and (fresh or not self.cs):
            r = self.c.post("/cs/oauth2/token", data={
                "client_id": "cs-mock-admin-client", "client_secret": "cs-mock-admin-secret"})
            self.cs = r.json()["access_token"]
        if vendor == "mde" and (fresh or not self.mde):
            r = self.c.post("/mde/oauth2/v2.0/token", data={
                "client_id": "mde-mock-admin-client", "client_secret": "mde-mock-admin-secret",
                "grant_type": "client_credentials",
                "scope": "https://api.securitycenter.microsoft.com/.default"})
            self.mde = r.json()["access_token"]
        if vendor == "graph" and (fresh or not self.graph):
            r = self.c.post("/graph/oauth2/v2.0/token", data={
                "client_id": "graph-mock-admin-client", "client_secret": "graph-mock-admin-secret",
                "grant_type": "client_credentials", "scope": "https://graph.microsoft.com/.default"})
            self.graph = r.json()["access_token"]
        if vendor == "sentinel" and (fresh or not self.sentinel):
            r = self.c.post("/sentinel/oauth2/v2.0/token", data={
                "client_id": "sentinel-mock-client-id",
                "client_secret": "sentinel-mock-client-secret",
                "grant_type": "client_credentials",
                "scope": "https://management.azure.com/.default"})
            self.sentinel = r.json()["access_token"]
        if vendor == "splunk" and (fresh or not self.splunk):
            r = self.c.post("/splunk/services/auth/login?output_mode=json",
                            data={"username": "admin", "password": "mockdr-admin"})
            self.splunk = r.json()["sessionKey"]
        if vendor == "es" and (fresh or not self.es):
            r = self.c.post("/elastic/_security/oauth2/token", headers=ES_AUTH,
                            json={"grant_type": "client_credentials"})
            self.es = r.json().get("access_token", "")
        value = {"splunk": f"Splunk {self.splunk}"}.get(vendor) or f"Bearer {getattr(self, vendor)}"
        return {"Authorization": value}


def _ids(c: TestClient):
    agents = [a["id"] for a in c.get(f"{S1}/agents?limit=100", headers=S1_AUTH).json()["data"]]
    return agents


def scenarios(cl: Clients, agent_ids: list[str]):
    c = cl.c

    def s1_poll(i):
        return c.get(f"{S1}/threats?limit=50", headers=S1_AUTH)

    def s1_connect(i):
        action = "connect" if i % 2 else "disconnect"
        return c.post(f"{S1}/agents/actions/{action}", headers=S1_AUTH,
                      json={"filter": {"ids": [random.choice(agent_ids)]}})

    def s1_dv(i):
        r = c.post(f"{S1}/dv/init-query", headers=S1_AUTH, json={
            "query": "EventType = 'Process Creation'",
            "fromDate": "2026-01-01T00:00:00.000Z", "toDate": "2030-01-01T00:00:00.000Z"})
        qid = r.json().get("data", {}).get("queryId", "")
        return c.get(f"{S1}/dv/query-status?queryId={qid}", headers=S1_AUTH)

    def cs_poll(i):
        return c.get("/cs/devices/queries/devices/v1?limit=50",
                     headers=cl.token("cs", fresh=i % 7 == 0))

    def cs_contain(i):
        h = cl.token("cs")
        ids = c.get("/cs/devices/queries/devices/v1?limit=50", headers=h).json()["resources"]
        return c.post("/cs/devices/entities/devices-actions/v2", headers=h,
                      params={"action_name": "contain" if i % 2 else "lift_containment"},
                      json={"ids": [random.choice(ids)]})

    def mde_poll(i):
        return c.get("/mde/api/alerts?$top=50", headers=cl.token("mde", fresh=i % 5 == 0))

    def mde_action(i):
        h = cl.token("mde")
        machines = c.get("/mde/api/machines?$top=60", headers=h).json()["value"]
        m = random.choice(machines)["id"]
        return c.post(f"/mde/api/machines/{m}/runAntiVirusScan", headers=h,
                      json={"Comment": "soak", "ScanType": "Quick"})

    def graph_hunt(i):
        return c.post("/graph/v1.0/security/runHuntingQuery",
                      headers=cl.token("graph", fresh=i % 5 == 0),
                      json={"Query": "DeviceNetworkEvents | take 5"})

    def sentinel_poll(i):
        return c.get(f"{WS}/incidents?api-version=2024-03-01",
                     headers=cl.token("sentinel", fresh=i % 5 == 0))

    def xdr_poll(i):
        return c.post("/xdr/public_api/v1/incidents/get_incidents/", headers=XDR_AUTH,
                      json={"request_data": {}})

    def xdr_xql(i):
        r = c.post("/xdr/public_api/v1/xql/start_xql_query/", headers=XDR_AUTH,
                   json={"request_data": {"query": "dataset = xdr_data | limit 5"}})
        qid = r.json().get("reply")
        return c.post("/xdr/public_api/v1/xql/get_query_results/", headers=XDR_AUTH,
                      json={"request_data": {"query_id": qid, "pending_flag": False}})

    def xdr_isolate(i):
        eps = c.post("/xdr/public_api/v1/endpoints/get_endpoint/", headers=XDR_AUTH,
                     json={"request_data": {}}).json()["reply"]["endpoints"]
        ep = random.choice(eps)["endpoint_id"]
        path = "isolate" if i % 2 else "unisolate"
        return c.post(f"/xdr/public_api/v1/endpoints/{path}", headers=XDR_AUTH,
                      json={"request_data": {"endpoint_id": ep}})

    def splunk_job(i):
        h = cl.token("splunk", fresh=i % 11 == 0)
        r = c.post("/splunk/services/search/jobs?output_mode=json", headers=h,
                   data={"search": "search index=main | head 5"})
        sid = r.json().get("sid", "")
        return c.get(f"/splunk/services/search/jobs/{sid}/results?output_mode=json", headers=h)

    def splunk_basic(i):
        return c.post("/splunk/services/search/jobs?output_mode=json", headers=SPLUNK_BASIC,
                      data={"search": "search index=* earliest=-24h | stats count",
                            "exec_mode": "oneshot"})

    def hec(i):
        channel = str(uuid.UUID(int=random.getrandbits(128)))
        return c.post("/splunk/services/collector/event?useACK=true",
                      headers={**HEC, "X-Splunk-Request-Channel": channel},
                      json={"event": {"soak": i}, "index": "main"})

    def es_scroll(i):
        # A client that scrolls and never clears: the leak ES's keep_alive bounds.
        return c.post("/elastic/.alerts-security.alerts-default/_search?scroll=1m",
                      headers=ES_AUTH, json={"size": 5})

    def es_token(i):
        r = c.get("/elastic/_cluster/health", headers=cl.token("es", fresh=i % 4 == 0))
        if r.status_code == 401:  # expired: an SDK fetches a new one and retries
            r = c.get("/elastic/_cluster/health", headers=cl.token("es", fresh=True))
        return r

    def es_index(i):
        return c.post("/elastic/soak-logs/_doc", headers=ES_AUTH, json={"n": i})

    return [s1_poll, s1_connect, s1_dv, cs_poll, cs_contain, mde_poll, mde_action,
            graph_hunt, sentinel_poll, xdr_poll, xdr_xql, xdr_isolate, splunk_job,
            splunk_basic, hec, es_scroll, es_token, es_index]


def sizes() -> dict[str, int]:
    from api.middleware import metrics, rate_limit
    from api.routers.splunk import splunk_hec
    from application.proxy import _state as proxy_state
    from repository.store import store

    out = {name: len(records) for name, records in store._collections.items()}
    out["<request_log_order>"] = len(store._request_log_order)
    out["<activity_order>"] = len(store._activity_order)
    out["<metrics.counters>"] = len(metrics._counters)
    out["<metrics.histograms>"] = len(metrics._histograms)
    out["<rate_limit.counters>"] = len(rate_limit._counters)
    out["<hec.ack_counters>"] = len(splunk_hec._ACK_COUNTERS)
    out["<hec.issued_acks>"] = sum(len(v) for v in splunk_hec._ISSUED_ACKS.values())
    out["<proxy.recordings>"] = len(proxy_state._recordings)
    return out


def _bounded() -> dict[str, tuple[int, str]]:
    """What may grow with traffic, the most it may hold, and why it is right to grow.

    A capped collection grows linearly until its cap; that is the design, not
    a leak. So does a lifetime longer than the run: a bearer token is kept a
    day past expiry, so a run shorter than ~25 simulated hours sees tokens
    pile up and level off only after.
    """
    from repository.store import CAPS

    out = {name: (cap, f"capped at {cap}") for name, cap in CAPS.items()}
    out["activities"] = out["<activity_order>"] = (10_000, "capped at 10000")
    day = "kept a day past expiry, then swept"
    for name in ("cs_oauth_tokens", "mde_oauth_tokens", "graph_oauth_tokens",
                 "sentinel_oauth_tokens", "es_tokens", "es_refresh_tokens"):
        out[name] = (CAPS.get(name, 5_000), day)
    return out


BOUNDED: dict[str, tuple[int, str]] = {}


def rss_mb() -> float:
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024
    except OSError:
        pass
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--requests", type=int, default=50_000)
    parser.add_argument("--allow", type=int, default=50,
                        help="growth per 10k requests tolerated in the second half")
    parser.add_argument("--advance", type=float, default=3.0,
                        help="simulated seconds per request")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()

    random.seed(args.seed)
    BOUNDED.update(_bounded())
    _install_clock()
    with TestClient(app) as c:
        cl = Clients(c)
        agent_ids = _ids(c)
        mix = scenarios(cl, agent_ids)
        statuses: dict[tuple[str, int], int] = {}
        samples: list[tuple[int, float, dict[str, int]]] = [(0, rss_mb(), sizes())]
        step = max(1, args.requests // 10)
        started = _real_time()
        for i in range(1, args.requests + 1):
            fn = mix[i % len(mix)]
            try:
                r = fn(i)
                code = r.status_code
            except Exception as exc:
                code = -1
                print(f"{fn.__name__}: {type(exc).__name__}: {exc}")
            statuses[(fn.__name__, code)] = statuses.get((fn.__name__, code), 0) + 1
            _OFFSET[0] += args.advance
            if i % step == 0:
                gc.collect()
                samples.append((i, rss_mb(), sizes()))
                print(f"{i:>7} req  {_real_time() - started:6.0f}s  rss {samples[-1][1]:7.1f} MB"
                      f"  simulated +{_OFFSET[0] / 3600:5.1f} h")

    print("\nstatus per scenario:")
    for (name, code), n in sorted(statuses.items()):
        print(f"  {name:14} {code:>4} x{n}")

    first, mid, last = samples[0], samples[len(samples) // 2], samples[-1]
    span = (last[0] - mid[0]) / 10_000 or 1
    print(f"\nRSS {first[1]:.1f} -> {mid[1]:.1f} -> {last[1]:.1f} MB")
    print(f"{'collection':40} {'start':>8} {'mid':>8} {'end':>8} {'/10k (2nd half)':>16}  bound")
    growing = []
    for name in last[2]:
        a, b, z = first[2].get(name, 0), mid[2].get(name, 0), last[2][name]
        rate = (z - b) / span
        bound = BOUNDED.get(name)
        if z != a:
            note = f"  {bound[1]}" if bound else ""
            print(f"{name:40} {a:>8} {b:>8} {z:>8} {rate:>16.0f}{note}")
        if rate > args.allow and not (bound and z <= bound[0]):
            growing.append(name)
    if growing:
        print(f"\nstill growing linearly: {', '.join(growing)}")
        return 1
    print("\nnothing grows with traffic past the allowance")
    return 0


if __name__ == "__main__":
    sys.exit(main())
