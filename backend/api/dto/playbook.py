"""Pydantic request models for playbook CRUD endpoints."""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, Field

# ── Step models (discriminated by `action`) ───────────────────────────────────

class _StepBase(BaseModel):
    stepId: str
    label: str
    delayMs: int = 0


class ActivityStep(_StepBase):
    """Playbook step that emits a synthetic activity event."""

    action: Literal["activity"]
    activityType: int = 2
    description: str = ""


class ThreatStep(_StepBase):
    """Playbook step that creates a synthetic threat detection."""

    action: Literal["threat"]
    threatName: str = ""
    fileName: str = ""
    classification: str = "Trojan"
    confidenceLevel: str = "malicious"
    mitreTactic: str = ""
    mitreTechnique: str = ""
    sha1: str = ""


class AlertStep(_StepBase):
    """Playbook step that raises a synthetic STAR rule alert."""

    action: Literal["alert"]
    severity: str = "HIGH"
    category: str = ""
    description: str = ""
    mitreTactic: str = ""
    mitreTechnique: str = ""


class AgentStateStep(_StepBase):
    """Playbook step that mutates the target agent's health state."""

    action: Literal["agent_state"]
    infected: bool = True
    activeThreats: int = 1
    networkStatus: str = "connected"


class SimpleActionStep(_StepBase):
    """Steps with no additional parameters."""
    action: Literal["mitigate", "resolve_all_threats", "heal_all_agents"]


PlaybookStepIn = Annotated[
    ActivityStep | ThreatStep | AlertStep | AgentStateStep | SimpleActionStep,
    Field(discriminator="action"),
]


# ── Playbook request bodies ───────────────────────────────────────────────────

class PlaybookCreateBody(BaseModel):
    """Request body for ``POST /_dev/playbooks``."""
    id: str | None = None
    title: str
    description: str = ""
    category: str = "custom"
    severity: str = "MEDIUM"
    estimatedDurationMs: int = 10000
    steps: list[PlaybookStepIn] = []


class PlaybookUpdateBody(BaseModel):
    """Request body for ``PUT /_dev/playbooks/{id}``."""
    title: str | None = None
    description: str | None = None
    category: str | None = None
    severity: str | None = None
    estimatedDurationMs: int | None = None
    steps: list[PlaybookStepIn] | None = None
