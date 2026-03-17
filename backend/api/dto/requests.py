"""Pydantic request models for endpoints that previously accepted raw dicts."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

# ── Webhook ──────────────────────────────────────────────────────────────────

class WebhookCreateBody(BaseModel):
    """POST /webhooks."""
    model_config = ConfigDict(populate_by_name=True)

    url: str
    eventTypes: list[str] = Field(default_factory=list, alias="event_types")
    secret: str = ""
    active: bool = True
    description: str = ""


class WebhookFireBody(BaseModel):
    """POST /webhooks/fire."""
    event_type: str
    payload: dict | None = None


# ── Firewall ─────────────────────────────────────────────────────────────────

class FirewallCreateBody(BaseModel):
    """POST /firewall-control."""
    data: dict = Field(default_factory=dict)
    filter: dict = Field(default_factory=dict)


class FirewallUpdateBody(BaseModel):
    """PUT /firewall-control."""
    data: dict = Field(default_factory=dict)
    filter: dict = Field(default_factory=dict)


class FirewallDeleteBody(BaseModel):
    """DELETE /firewall-control."""
    filter: dict = Field(default_factory=dict)


# ── Device Control ───────────────────────────────────────────────────────────

class DeviceControlCreateBody(BaseModel):
    """POST /device-control."""
    data: dict = Field(default_factory=dict)


class DeviceControlUpdateBody(BaseModel):
    """PUT /device-control/{id}."""
    data: dict = Field(default_factory=dict)


class DeviceControlDeleteBody(BaseModel):
    """DELETE /device-control."""
    filter: dict = Field(default_factory=dict)


# ── Users ────────────────────────────────────────────────────────────────────

class UserCreateBody(BaseModel):
    """POST /users."""
    data: dict = Field(default_factory=dict)


class UserUpdateBody(BaseModel):
    """PUT /users/{id}."""
    data: dict = Field(default_factory=dict)


class UserBulkDeleteBody(BaseModel):
    """POST /users/delete-users."""
    filter: dict = Field(default_factory=dict)


# ── Sites ────────────────────────────────────────────────────────────────────

class SiteCreateBody(BaseModel):
    """POST /sites."""
    data: dict = Field(default_factory=dict)


class SiteUpdateBody(BaseModel):
    """PUT /sites/{id}."""
    data: dict = Field(default_factory=dict)


# ── Groups ───────────────────────────────────────────────────────────────────

class GroupCreateBody(BaseModel):
    """POST /groups."""
    data: dict = Field(default_factory=dict)


class GroupUpdateBody(BaseModel):
    """PUT /groups/{id}."""
    data: dict = Field(default_factory=dict)


class GroupMoveAgentsBody(BaseModel):
    """PUT /groups/{id}/move-agents."""
    filter: dict = Field(default_factory=dict)
    agentIds: list[str] | None = None


# ── Exclusions & Restrictions ────────────────────────────────────────────────

class ExclusionCreateBody(BaseModel):
    """POST /exclusions."""
    data: dict = Field(default_factory=dict)
    filter: dict = Field(default_factory=dict)


class BulkDeleteBody(BaseModel):
    """Generic bulk delete: {"data": {"ids": [...]}}."""
    data: dict = Field(default_factory=dict)


class RestrictionCreateBody(BaseModel):
    """POST /restrictions."""
    data: dict = Field(default_factory=dict)
    filter: dict = Field(default_factory=dict)


# ── IOC ──────────────────────────────────────────────────────────────────────

class IocCreateBody(BaseModel):
    """POST /threat-intelligence/iocs."""
    data: dict | list = Field(default_factory=dict)
    filter: dict = Field(default_factory=dict)


class IocDeleteBody(BaseModel):
    """DELETE /threat-intelligence/iocs."""
    filter: dict = Field(default_factory=dict)


# ── Dev Endpoints ────────────────────────────────────────────────────────────

class DevScenarioBody(BaseModel):
    """POST /_dev/scenario."""
    scenario: str = ""


class DevRateLimitBody(BaseModel):
    """POST /_dev/rate-limit."""
    enabled: bool = False
    requestsPerMinute: int = Field(60, ge=1, le=10000)


class DevPlaybookRunBody(BaseModel):
    """POST /_dev/playbooks/{id}/run."""
    agentId: str


class DevFaultInjectionBody(BaseModel):
    """POST /_dev/fault-injection."""
    delayMs: int = 0
    delayJitterMs: int = 0
    errorRate: float = Field(0.0, ge=0.0, le=1.0)
    errorStatus: int = Field(500, ge=100, le=599)


# ── Accounts ────────────────────────────────────────────────────────────────

class AccountCreateBody(BaseModel):
    """POST /accounts."""
    data: dict = Field(default_factory=dict)


class AccountUpdateBody(BaseModel):
    """PUT /accounts/{id}."""
    data: dict = Field(default_factory=dict)


# ── Tags ────────────────────────────────────────────────────────────────────

class TagCreateBody(BaseModel):
    """POST /tag-manager."""
    data: dict = Field(default_factory=dict)
    filter: dict = Field(default_factory=dict)


class TagUpdateBody(BaseModel):
    """PUT /tag-manager/{id}."""
    data: dict = Field(default_factory=dict)


# ── Policies ────────────────────────────────────────────────────────────────

class PolicyUpdateBody(BaseModel):
    """PUT /policies."""
    data: dict = Field(default_factory=dict)


# ── Agents (fetch-files, remote-scripts) ────────────────────────────────────

class FetchFilesBody(BaseModel):
    """POST /agents/{id}/actions/fetch-files."""
    data: dict = Field(default_factory=dict)


class RemoteScriptBody(BaseModel):
    """POST /remote-scripts/execute."""
    data: dict = Field(default_factory=dict)


# ── Deep Visibility ─────────────────────────────────────────────────────────

class DvInitQueryBody(BaseModel):
    """POST /dv/init-query."""
    query: str
    fromDate: str
    toDate: str
    queryType: list[str] = []


class DvCancelQueryBody(BaseModel):
    """POST /dv/cancel-query."""
    queryId: str


# ── STAR Rules ──────────────────────────────────────────────────────────────

class StarRuleCreateBody(BaseModel):
    """POST /cloud-detection/rules."""
    data: dict = Field(default_factory=dict)


# ── Proxy ───────────────────────────────────────────────────────────────────

class ProxyConfigBody(BaseModel):
    """POST /_dev/proxy/config."""
    mode: str = ""
    base_url: str = ""
    api_token: str = ""
