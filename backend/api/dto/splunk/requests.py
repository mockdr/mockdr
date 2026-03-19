"""Pydantic request DTOs for Splunk API endpoints.

These models document the expected request shapes for Splunk REST API
endpoints.  Some endpoints (e.g. notable_update) accept both form-encoded
and JSON bodies, so the routers parse manually rather than binding directly
to these DTOs.  The models are still used for validation in JSON-only paths
and serve as canonical schema documentation.
"""
from __future__ import annotations

from pydantic import BaseModel, Field


class SplunkAuthRequest(BaseModel):
    """Login request body (``POST /services/auth/login``).

    The real Splunk login endpoint accepts form-encoded data, so the router
    uses ``Form()`` parameters directly.  This DTO documents the schema.
    """

    username: str = ""
    password: str = ""
    output_mode: str = "json"


class HecEventRequest(BaseModel):
    """Single HEC event payload (``POST /services/collector/event``).

    HEC accepts newline-delimited JSON batches, so the router parses
    the raw body.  This DTO documents the per-event schema.
    """

    event: dict | str = Field(default_factory=dict)
    sourcetype: str = ""
    source: str = ""
    index: str = ""
    host: str = "mockdr"
    time: float | None = None


class NotableUpdateRequest(BaseModel):
    """Notable event update request (``POST /services/notable_update``).

    The router accepts both form-encoded and JSON bodies to match the
    real Splunk API.  This DTO is used for JSON body validation.
    """

    ruleUIDs: list[str] = Field(default_factory=list)
    newUrgency: str = ""
    status: str = ""
    newOwner: str = ""
    comment: str = ""
