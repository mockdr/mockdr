#!/usr/bin/env python3
"""Load testing script for the mockdr SentinelOne mock API server.

Uses concurrent.futures + httpx to stress-test read, write, and mixed workloads.
Collects latency percentiles, throughput, and error rates.

Exit code 0 if p99 < 500ms and error rate < 1%, exit code 1 otherwise.

Usage:
    python scripts/load_test.py
    python scripts/load_test.py --base-url http://localhost:8001/web/api/v2.1
    python scripts/load_test.py --token admin-token-0000-0000-000000000001
"""

from __future__ import annotations

import argparse
import random
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx

# ── Defaults ─────────────────────────────────────────────────────────────────

DEFAULT_BASE_URL = "http://localhost:8001/web/api/v2.1"
DEFAULT_TOKEN = "admin-token-0000-0000-000000000001"

# ── Result types ─────────────────────────────────────────────────────────────


@dataclass
class RequestResult:
    status_code: int
    latency_ms: float
    error: str | None = None


@dataclass
class ScenarioReport:
    name: str
    total_requests: int
    workers: int
    results: list[RequestResult] = field(default_factory=list)

    @property
    def latencies(self) -> list[float]:
        return [r.latency_ms for r in self.results if r.error is None]

    @property
    def error_count(self) -> int:
        return sum(1 for r in self.results if r.error is not None or r.status_code >= 400)

    @property
    def error_rate(self) -> float:
        if not self.results:
            return 0.0
        return self.error_count / len(self.results) * 100

    @property
    def status_distribution(self) -> dict[int, int]:
        dist: dict[int, int] = {}
        for r in self.results:
            dist[r.status_code] = dist.get(r.status_code, 0) + 1
        return dict(sorted(dist.items()))

    def percentile(self, p: float) -> float:
        if not self.latencies:
            return 0.0
        sorted_lat = sorted(self.latencies)
        k = (len(sorted_lat) - 1) * (p / 100)
        f = int(k)
        c = f + 1
        if c >= len(sorted_lat):
            return sorted_lat[f]
        return sorted_lat[f] + (k - f) * (sorted_lat[c] - sorted_lat[f])

    @property
    def p50(self) -> float:
        return self.percentile(50)

    @property
    def p95(self) -> float:
        return self.percentile(95)

    @property
    def p99(self) -> float:
        return self.percentile(99)

    @property
    def rps(self) -> float:
        if not self.latencies:
            return 0.0
        total_time = sum(self.latencies) / 1000  # seconds
        # Effective RPS = total successful requests / wall-clock approximation
        # Use actual wall time tracked externally; fallback to avg * count / workers
        avg_s = (sum(self.latencies) / len(self.latencies)) / 1000
        if avg_s == 0:
            return 0.0
        return self.workers / avg_s


# ── Request helpers ──────────────────────────────────────────────────────────


def make_get(client: httpx.Client, url: str) -> RequestResult:
    """Execute a GET request and return timing info."""
    try:
        start = time.perf_counter()
        resp = client.get(url)
        elapsed = (time.perf_counter() - start) * 1000
        return RequestResult(status_code=resp.status_code, latency_ms=elapsed)
    except Exception as exc:
        return RequestResult(status_code=0, latency_ms=0.0, error=str(exc))


def make_post(client: httpx.Client, url: str, json_body: dict[str, Any]) -> RequestResult:
    """Execute a POST request and return timing info."""
    try:
        start = time.perf_counter()
        resp = client.post(url, json=json_body)
        elapsed = (time.perf_counter() - start) * 1000
        return RequestResult(status_code=resp.status_code, latency_ms=elapsed)
    except Exception as exc:
        return RequestResult(status_code=0, latency_ms=0.0, error=str(exc))


# ── Scenario runners ─────────────────────────────────────────────────────────


def run_scenario(
    name: str,
    task_fn: Callable[[int], RequestResult],
    workers: int,
    total_requests: int,
) -> ScenarioReport:
    """Run a scenario with the given concurrency and request count."""
    report = ScenarioReport(name=name, total_requests=total_requests, workers=workers)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(task_fn, i) for i in range(total_requests)]
        for future in as_completed(futures):
            report.results.append(future.result())

    return report


def scenario_read_throughput(base_url: str, token: str) -> ScenarioReport:
    """GET /agents, /threats, /cloud-detection/alerts — 50 workers, 500 requests."""
    endpoints = [
        f"{base_url}/agents",
        f"{base_url}/threats",
        f"{base_url}/cloud-detection/alerts",
    ]

    def task(i: int) -> RequestResult:
        with httpx.Client(
            headers={"Authorization": f"ApiToken {token}"},
            timeout=30.0,
        ) as client:
            url = endpoints[i % len(endpoints)]
            return make_get(client, url)

    return run_scenario("Read Throughput", task, workers=50, total_requests=500)


def scenario_write_contention(base_url: str, token: str) -> ScenarioReport:
    """POST analyst-verdict + initiate-scan — 20 workers, 200 requests."""
    # Pre-fetch threat and agent IDs for realistic write targets
    with httpx.Client(
        headers={"Authorization": f"ApiToken {token}"},
        timeout=30.0,
    ) as client:
        threats_resp = client.get(f"{base_url}/threats")
        agents_resp = client.get(f"{base_url}/agents")

    threat_ids: list[str] = []
    agent_ids: list[str] = []
    if threats_resp.status_code == 200:
        threat_ids = [t["id"] for t in threats_resp.json().get("data", [])]
    if agents_resp.status_code == 200:
        agent_ids = [a["id"] for a in agents_resp.json().get("data", [])]

    if not threat_ids:
        threat_ids = ["fake-threat-id"]
    if not agent_ids:
        agent_ids = ["fake-agent-id"]

    write_endpoints: list[tuple[str, dict[str, Any]]] = [
        (
            f"{base_url}/threats/analyst-verdict",
            {
                "data": {"analystVerdict": "true_positive"},
                "filter": {"ids": [random.choice(threat_ids)]},
            },
        ),
        (
            f"{base_url}/agents/actions/initiate-scan",
            {
                "data": {},
                "filter": {"ids": [random.choice(agent_ids)]},
            },
        ),
    ]

    def task(i: int) -> RequestResult:
        with httpx.Client(
            headers={"Authorization": f"ApiToken {token}"},
            timeout=30.0,
        ) as client:
            url, body = write_endpoints[i % len(write_endpoints)]
            return make_post(client, url, body)

    return run_scenario("Write Contention", task, workers=20, total_requests=200)


def scenario_mixed_workload(base_url: str, token: str) -> ScenarioReport:
    """80% reads + 20% writes — 30 workers, 300 requests."""
    read_endpoints = [
        f"{base_url}/agents",
        f"{base_url}/threats",
        f"{base_url}/cloud-detection/alerts",
    ]

    # Pre-fetch IDs
    with httpx.Client(
        headers={"Authorization": f"ApiToken {token}"},
        timeout=30.0,
    ) as client:
        threats_resp = client.get(f"{base_url}/threats")
        agents_resp = client.get(f"{base_url}/agents")

    threat_ids: list[str] = []
    agent_ids: list[str] = []
    if threats_resp.status_code == 200:
        threat_ids = [t["id"] for t in threats_resp.json().get("data", [])]
    if agents_resp.status_code == 200:
        agent_ids = [a["id"] for a in agents_resp.json().get("data", [])]

    if not threat_ids:
        threat_ids = ["fake-threat-id"]
    if not agent_ids:
        agent_ids = ["fake-agent-id"]

    def task(i: int) -> RequestResult:
        with httpx.Client(
            headers={"Authorization": f"ApiToken {token}"},
            timeout=30.0,
        ) as client:
            # 80% reads, 20% writes (deterministic based on index)
            if i % 5 < 4:
                url = read_endpoints[i % len(read_endpoints)]
                return make_get(client, url)
            else:
                if i % 2 == 0:
                    return make_post(
                        client,
                        f"{base_url}/threats/analyst-verdict",
                        {
                            "data": {"analystVerdict": "true_positive"},
                            "filter": {"ids": [threat_ids[i % len(threat_ids)]]},
                        },
                    )
                else:
                    return make_post(
                        client,
                        f"{base_url}/agents/actions/initiate-scan",
                        {
                            "data": {},
                            "filter": {"ids": [agent_ids[i % len(agent_ids)]]},
                        },
                    )

    return run_scenario("Mixed Workload (80/20)", task, workers=30, total_requests=300)


# ── Output formatting ────────────────────────────────────────────────────────


def print_report(report: ScenarioReport) -> None:
    """Print a formatted summary table for one scenario."""
    print(f"\n{'=' * 70}")
    print(f"  {report.name}")
    print(f"  {report.workers} workers, {report.total_requests} total requests")
    print(f"{'=' * 70}")

    if not report.latencies:
        print("  No successful requests.")
        return

    print(f"  {'Metric':<30} {'Value':>15}")
    print(f"  {'-' * 30} {'-' * 15}")
    print(f"  {'Requests/sec (est.)':<30} {report.rps:>15.1f}")
    print(f"  {'p50 latency':<30} {report.p50:>12.1f} ms")
    print(f"  {'p95 latency':<30} {report.p95:>12.1f} ms")
    print(f"  {'p99 latency':<30} {report.p99:>12.1f} ms")
    print(f"  {'Error rate':<30} {report.error_rate:>14.2f}%")
    print(f"  {'Total errors':<30} {report.error_count:>15d}")
    print()
    print(f"  Status code distribution:")
    for code, count in report.status_distribution.items():
        label = f"    HTTP {code}" if code > 0 else "    Connection error"
        print(f"  {label:<30} {count:>15d}")


def evaluate_pass_fail(reports: list[ScenarioReport]) -> bool:
    """Return True if all scenarios pass thresholds (p99 < 500ms, error rate < 1%)."""
    all_pass = True
    print(f"\n{'=' * 70}")
    print("  PASS/FAIL EVALUATION")
    print(f"{'=' * 70}")
    print(f"  {'Scenario':<30} {'p99 < 500ms':>15} {'Errors < 1%':>15} {'Result':>10}")
    print(f"  {'-' * 30} {'-' * 15} {'-' * 15} {'-' * 10}")

    for r in reports:
        p99_ok = r.p99 < 500.0
        err_ok = r.error_rate < 1.0
        passed = p99_ok and err_ok
        if not passed:
            all_pass = False
        print(
            f"  {r.name:<30} "
            f"{r.p99:>11.1f} ms "
            f"{'PASS' if p99_ok else 'FAIL':>4} "
            f"{r.error_rate:>10.2f}% "
            f"{'PASS' if err_ok else 'FAIL':>4} "
            f"{'PASS' if passed else 'FAIL':>6}"
        )

    print()
    return all_pass


# ── Main ─────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(description="Load test the mockdr API server")
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"API base URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--token",
        default=DEFAULT_TOKEN,
        help="API token for authentication (default: admin token)",
    )
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    token: str = args.token

    print(f"Load testing: {base_url}")
    print(f"Token: {token[:20]}...")

    # Verify server is reachable
    try:
        with httpx.Client(
            headers={"Authorization": f"ApiToken {token}"},
            timeout=10.0,
        ) as client:
            resp = client.get(f"{base_url}/agents?limit=1")
            if resp.status_code != 200:
                print(f"ERROR: Server returned {resp.status_code} — is the server running?")
                sys.exit(1)
    except httpx.ConnectError:
        print(f"ERROR: Cannot connect to {base_url} — is the server running?")
        sys.exit(1)

    print("Server is reachable. Starting load tests...\n")

    # Run all three scenarios
    reports: list[ScenarioReport] = []

    wall_start = time.perf_counter()

    r1 = scenario_read_throughput(base_url, token)
    print_report(r1)
    reports.append(r1)

    r2 = scenario_write_contention(base_url, token)
    print_report(r2)
    reports.append(r2)

    r3 = scenario_mixed_workload(base_url, token)
    print_report(r3)
    reports.append(r3)

    wall_elapsed = time.perf_counter() - wall_start
    print(f"\nTotal wall time: {wall_elapsed:.1f}s")

    # Evaluate pass/fail
    all_pass = evaluate_pass_fail(reports)

    if all_pass:
        print("RESULT: ALL SCENARIOS PASSED")
        sys.exit(0)
    else:
        print("RESULT: ONE OR MORE SCENARIOS FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()
