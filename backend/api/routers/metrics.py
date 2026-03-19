"""Prometheus-compatible /metrics endpoint (no auth required)."""
from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import Response

from api.middleware.metrics import BUCKETS, get_metrics_snapshot

router = APIRouter(tags=["Metrics"])


def _render_prometheus() -> str:
    """Render all collected metrics in Prometheus text exposition format."""
    counters, histograms = get_metrics_snapshot()
    lines: list[str] = []

    # ── http_requests_total counter ──────────────────────────────────────
    lines.append("# HELP http_requests_total Total number of HTTP requests.")
    lines.append("# TYPE http_requests_total counter")
    for (method, path, status), count in sorted(counters.items()):
        lines.append(
            f'http_requests_total{{method="{method}",path="{path}",'
            f'status="{status}"}} {count}'
        )

    # ── http_request_duration_seconds histogram ──────────────────────────
    lines.append(
        "# HELP http_request_duration_seconds Request duration in seconds."
    )
    lines.append("# TYPE http_request_duration_seconds histogram")
    for (method, path), hist in sorted(histograms.items()):
        labels = f'method="{method}",path="{path}"'
        cumulative = 0
        for b in BUCKETS:
            cumulative += hist["bucket_counts"][b]
            lines.append(
                f"http_request_duration_seconds_bucket{{{labels},le=\"{b}\"}} {cumulative}"
            )
        # +Inf bucket always equals total count
        lines.append(
            f'http_request_duration_seconds_bucket{{{labels},le="+Inf"}} {hist["count"]}'
        )
        lines.append(
            f"http_request_duration_seconds_sum{{{labels}}} {hist['sum']:.6f}"
        )
        lines.append(
            f"http_request_duration_seconds_count{{{labels}}} {hist['count']}"
        )

    lines.append("")  # trailing newline
    return "\n".join(lines)


@router.get("/metrics", include_in_schema=False)
def metrics_endpoint() -> Response:
    """Expose Prometheus-compatible metrics in text exposition format."""
    return Response(
        content=_render_prometheus(),
        media_type="text/plain; version=0.0.4",
    )
