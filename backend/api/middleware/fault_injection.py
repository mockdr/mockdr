"""ASGI middleware for fault injection: artificial latency and random error responses.

Controlled via module-level config functions and the ``/_dev/fault-injection``
endpoints.  ``/_dev/`` paths are always exempt.
"""
from __future__ import annotations

import asyncio
import json
import random
from dataclasses import dataclass

from starlette.types import ASGIApp, Receive, Scope, Send


@dataclass
class FaultInjectionConfig:
    """Configuration for fault injection middleware.

    Attributes:
        delay_ms: Fixed delay in milliseconds added to every response (0 = disabled).
        delay_jitter_ms: Random jitter added on top of delay_ms (uniform 0..jitter).
        error_rate: Fraction of requests that return an error (0.0–1.0, 0 = disabled).
        error_status: HTTP status code to return for injected errors.
    """

    delay_ms: int = 0
    delay_jitter_ms: int = 0
    error_rate: float = 0.0
    error_status: int = 500


_config = FaultInjectionConfig()


def get_fault_config() -> FaultInjectionConfig:
    """Return the current fault injection configuration."""
    return _config


def set_fault_config(
    delay_ms: int | None = None,
    delay_jitter_ms: int | None = None,
    error_rate: float | None = None,
    error_status: int | None = None,
) -> FaultInjectionConfig:
    """Update fault injection configuration. Only non-None fields are changed."""
    global _config
    _config = FaultInjectionConfig(
        delay_ms=delay_ms if delay_ms is not None else _config.delay_ms,
        delay_jitter_ms=delay_jitter_ms if delay_jitter_ms is not None else _config.delay_jitter_ms,
        error_rate=error_rate if error_rate is not None else _config.error_rate,
        error_status=error_status if error_status is not None else _config.error_status,
    )
    return _config


def reset_fault_config() -> None:
    """Reset fault injection to defaults (all disabled)."""
    global _config
    _config = FaultInjectionConfig()


class FaultInjectionMiddleware:
    """ASGI middleware that injects latency and/or random errors.

    ``/_dev/`` paths are always exempt so the control plane is never affected.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        if "/_dev/" in path:
            await self.app(scope, receive, send)
            return

        cfg = _config

        # Inject delay
        total_delay = cfg.delay_ms
        if cfg.delay_jitter_ms > 0:
            total_delay += random.randint(0, cfg.delay_jitter_ms)
        if total_delay > 0:
            await asyncio.sleep(total_delay / 1000.0)

        # Inject error
        if cfg.error_rate > 0 and random.random() < cfg.error_rate:
            error_body = json.dumps({
                "errors": [{
                    "code": cfg.error_status * 10000 + 10,
                    "detail": "Injected error (fault injection enabled)",
                    "title": "Simulated Error",
                }],
                "data": None,
            }).encode()
            await send({
                "type": "http.response.start",
                "status": cfg.error_status,
                "headers": [(b"content-type", b"application/json")],
            })
            await send({
                "type": "http.response.body",
                "body": error_body,
            })
            return

        await self.app(scope, receive, send)
