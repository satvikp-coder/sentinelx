"""Strict Pydantic schemas for the /api/v1 backend.

All schemas use ``extra="forbid"`` so no undeclared fields can sneak in.
Every numeric field is bounded; every string field is length-bounded.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------- base

class APIModel(BaseModel):
    """Base schema: forbid extra fields, serialize datetime as ISO8601."""

    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------- enums

class RunState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class ShieldMode(StrEnum):
    MONITOR = "monitor"
    RECOMMEND = "recommend"
    ENFORCE = "enforce"


class Decision(StrEnum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    CONFIRM = "CONFIRM"


class EvidenceState(StrEnum):
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    SIMULATED = "SIMULATED"
    VERIFIED = "VERIFIED"


class LabelMode(StrEnum):
    LIVE = "LIVE"
    RECORDED = "RECORDED"
    SIMULATED = "SIMULATED"


# ---------------------------------------------------------------- common

class Timestamp(APIModel):
    value: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Pagination(APIModel):
    limit: int = Field(default=50, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


# ---------------------------------------------------------------- auth

class DemoAuth(APIModel):
    """Local demo auth: a single opaque token. Not for production use."""

    token: str = Field(min_length=1, max_length=128)


# ---------------------------------------------------------------- health

class HealthResponse(APIModel):
    status: str  # "ok" | "degraded" | "unavailable"
    version: str
    mode: LabelMode
    model_available: bool
    features: list[str]


# ---------------------------------------------------------------- sessions

class SessionCreate(APIModel):
    scenario_id: str = Field(min_length=1, max_length=100)
    lab: str = Field(min_length=1, max_length=100)
    arm: str = Field(min_length=1, max_length=20)  # "A" | "B"
    label: str | None = Field(default=None, max_length=200)


class SessionResponse(APIModel):
    id: UUID
    scenario_id: str
    lab: str
    arm: str
    label: str | None
    state: RunState
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------- runs

class RunCreate(APIModel):
    session_id: UUID
    arm: str = Field(min_length=1, max_length=20)
    model_mode: LabelMode = LabelMode.SIMULATED


class RunResponse(APIModel):
    id: UUID
    session_id: UUID
    state: RunState
    model_mode: LabelMode
    created_at: datetime
    updated_at: datetime
    steps: int = 0
    actions_attempted: int = 0
    actions_executed: int = 0
    actions_blocked: int = 0


class CancelResponse(APIModel):
    run_id: UUID
    state: RunState
    cancelled_at: datetime


# ---------------------------------------------------------------- events

class EventKind(StrEnum):
    RUN_STARTED = "RUN_STARTED"
    ACTION_PROPOSED = "ACTION_PROPOSED"
    ACTION_DECIDED = "ACTION_DECIDED"
    ACTION_EXECUTED = "ACTION_EXECUTED"
    ACTION_BLOCKED = "ACTION_BLOCKED"
    RUN_COMPLETED = "RUN_COMPLETED"
    RUN_CANCELLED = "RUN_CANCELLED"
    RUN_FAILED = "RUN_FAILED"
    SHIELD_RULE_ADDED = "SHIELD_RULE_ADDED"
    SHIELD_RULE_REMOVED = "SHIELD_RULE_REMOVED"
    FINDING_ADDED = "FINDING_ADDED"
    APPROVAL_REQUESTED = "APPROVAL_REQUESTED"
    APPROVAL_RECORDED = "APPROVAL_RECORDED"


class EventResponse(APIModel):
    id: UUID
    seq: int
    run_id: UUID | None
    kind: EventKind
    payload: dict[str, Any]
    timestamp: datetime


class EventStreamMessage(APIModel):
    seq: int
    id: UUID
    kind: str
    payload: dict[str, Any]
    timestamp: str


# ---------------------------------------------------------------- policy decisions

class PolicyDecisionRequest(APIModel):
    session_id: UUID
    tool: str = Field(min_length=1, max_length=100)
    arguments: dict[str, Any] = Field(default_factory=dict)
    allowed_hosts: list[str] = Field(default_factory=list)
    goal: str | None = Field(default=None, max_length=500)


class PolicyDecisionResponse(APIModel):
    decision: Decision
    reason_code: str
    rule_ids: list[str]
    requires_human: bool
    explanation: str
    action_id: str  # Unique action identifier; same action+arguments → same action_id


# ---------------------------------------------------------------- evidence verification

class EvidenceVerifyRequest(APIModel):
    session_id: str


class EvidenceVerifyResponse(APIModel):
    session_id: UUID
    events_checked: int
    ok: bool
    first_broken_event_id: str | None
    detail: str


# ---------------------------------------------------------------- findings

class FindingResponse(APIModel):
    id: UUID
    session_id: UUID
    state: str  # confirmed | needs_validation | rejected
    severity: str
    summary: str
    mode: LabelMode
    model_provider: str | None
    model_name: str | None
    created_at: datetime


# ---------------------------------------------------------------- containment

class ContainmentBranchResponse(APIModel):
    branch_id: UUID
    session_id: UUID
    mitigation_id: str
    unauthorized_executed: bool
    task_completed: bool
    mean_disruption_cost: float | None


# ---------------------------------------------------------------- metrics

class MetricResponse(APIModel):
    name: str
    numerator: int
    denominator: int
    value: float | None


class MetricsResponse(APIModel):
    arm: str
    metrics: list[MetricResponse]


# ---------------------------------------------------------------- targets

class TargetCreate(APIModel):
    target_id: str = Field(min_length=1, max_length=200)
    url: str
    lab: bool = True


class TargetResponse(APIModel):
    target_id: str
    url: str
    lab: bool
    owned: bool


# ---------------------------------------------------------------- scans

class ScanCreate(APIModel):
    target_id: str = Field(min_length=1, max_length=200)
    model: bool = False


class ScanResponse(APIModel):
    scan_id: UUID
    target_id: str
    state: RunState
    findings_count: int
    requests_used: int
    request_budget: int


# ---------------------------------------------------------------- patches

class PatchResponse(APIModel):
    patch_id: UUID
    finding_id: UUID
    status: str  # PROPOSED | AWAITING_APPROVAL | REJECTED | APPLIED | ESCALATED
    patch_format: str  # "diff" | "edits"
    verification_status: str | None


# ---------------------------------------------------------------- approvals

class ApprovalRecordResponse(APIModel):
    record_id: UUID
    action_id: UUID
    decision: Decision
    reviewer: str | None
    rationale: str | None
    recorded_at: datetime | None


# ---------------------------------------------------------------- shield rules

class ShieldRuleCreate(APIModel):
    route_pattern: str = Field(min_length=1, max_length=200)
    intent: str = Field(min_length=1, max_length=100)
    mode: ShieldMode
    ttl_minutes: int = Field(default=60, ge=1, le=10080)  # max 7 days
    reason: str = Field(min_length=1, max_length=500)


class ShieldRuleResponse(APIModel):
    rule_id: UUID
    route_pattern: str
    intent: str
    mode: ShieldMode
    state: str  # PROPOSED | ACTIVE | EXPIRED | REMOVED
    ttl_minutes: int
    created_at: datetime
    expires_at: datetime | None


# ---------------------------------------------------------------- escalations

class EscalationTicketResponse(APIModel):
    ticket_id: UUID
    finding_id: UUID
    state: str  # OPEN | ACKNOWLEDGED | RESOLVED | CLOSED
    reason: str
    created_at: datetime


# ---------------------------------------------------------------- guard sidecar

class GuardDecideRequest(APIModel):
    session_id: UUID
    tool: str = Field(min_length=1, max_length=100)
    arguments: dict[str, Any] = Field(default_factory=dict)


class GuardDecideResponse(APIModel):
    decision: Decision
    reason_code: str
    blocked: bool  # true iff decision == BLOCK
    requires_human: bool  # true iff decision == CONFIRM
    explanation: str


# ---------------------------------------------------------------- errors

class ErrorResponse(APIModel):
    error: str
    detail: str | None = None
    code: str  # e.g. "NOT_FOUND", "VALIDATION_ERROR", "UNAUTHORIZED", "RATE_LIMITED"


# ---------------------------------------------------------------- ids

def new_id() -> UUID:
    return uuid4()


def now() -> datetime:
    return datetime.now(UTC)
