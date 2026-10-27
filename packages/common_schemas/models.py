"""Versioned contracts (schema_version 1.0). Strict: extra fields are forbidden."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, JsonValue, field_validator, model_validator

from .base import SXModel, UTCDatetime
from .enums import (
    ActorRole,
    ApprovalDecision,
    Arm,
    Decision,
    EscalationStatus,
    EvidenceState,
    FindingState,
    IntentLabel,
    ModelMode,
    SessionKind,
    SessionState,
    Severity,
    ShieldStatus,
    TargetStatus,
    VerificationStatus,
)

Id = Annotated[str, Field(min_length=1, max_length=200)]
Text = Annotated[str, Field(min_length=1)]
Confidence = Annotated[float, Field(ge=0.0, le=1.0)]
SHIELD_LABEL = "TEMPORARY SHIELD, NOT A FIX"


# ---------------------------------------------------------------- scenarios / actions
class ForbiddenOutcome(SXModel):
    type: Text
    endpoint: Text


class GoalAssertion(SXModel):
    type: Text
    expected: JsonValue


class ScenarioSpec(SXModel):
    id: Id
    seed: int
    fixture_id: Id
    fixture_version: Text
    goal: Text
    allowed_hosts: list[Text]
    allowed_actions: list[Text]
    attack_surface: Text
    attack_payload_id: Id
    forbidden_outcome: ForbiddenOutcome
    goal_assertion: GoalAssertion

    @field_validator("allowed_hosts")
    @classmethod
    def _exact_hosts(cls, hosts: list[str]) -> list[str]:
        for h in hosts:
            if "*" in h or any(c.isspace() for c in h) or "/" in h:
                raise ValueError(f"allowed_hosts must be exact hosts, got {h!r}")
        return [h.lower() for h in hosts]


class ActionRequest(SXModel):
    session_id: Id
    step: Annotated[int, Field(ge=0)]
    action_id: Id
    timestamp: UTCDatetime
    actor: Text
    tool: Text
    arguments: dict[str, JsonValue]
    origin_observation_ids: list[Id] = []
    intent_id: Id | None = None


class PolicyDecision(SXModel):
    action_id: Id
    decision: Decision
    policy_version: Text
    rule_ids: list[Id]
    reason_code: Text
    explanation: Text
    requires_human: bool


# ---------------------------------------------------------------- evidence
class EvidenceEvent(SXModel):
    id: Id
    session_id: Id
    seq: Annotated[int, Field(ge=1)]
    kind: Text
    timestamp_utc: UTCDatetime
    parent_event_id: Id | None = None
    state: EvidenceState
    source: Text
    payload: dict[str, JsonValue]
    previous_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    event_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class IncidentFinding(SXModel):
    incident_id: Id
    finding: Text
    evidence_event_ids: Annotated[list[Id], Field(min_length=1)]
    confidence: Confidence
    observed: list[Text]
    inferred: list[Text]
    recommended_mitigations: list[Text]


class ContainmentBranch(SXModel):
    branch_id: Id
    parent_session_id: Id
    checkpoint_ref: Text
    mitigation_id: Id
    new_seed: int
    executed_trace_id: Id
    unauthorized_executed: bool
    task_completed: bool
    added_actions: Annotated[int, Field(ge=0)]
    duration_ms: Annotated[int, Field(ge=0)]
    cost_usd: Annotated[float, Field(ge=0)] | None = None
    verifier_version: Text
    was_simulated: bool
    was_executed: bool
    model_mode: ModelMode
    fixture_hash: Text


# ---------------------------------------------------------------- site guard
class TargetScope(SXModel):
    schemes: Annotated[list[Literal["http", "https"]], Field(min_length=1)]
    hosts: Annotated[list[Text], Field(min_length=1)]
    ports: Annotated[list[Annotated[int, Field(ge=1, le=65535)]], Field(min_length=1)]

    @field_validator("hosts")
    @classmethod
    def _exact_hosts(cls, hosts: list[str]) -> list[str]:
        if any("*" in h for h in hosts):
            raise ValueError("scope hosts must be exact")
        return [h.lower() for h in hosts]


class TargetAuthorization(SXModel):
    target_id: Id
    base_url: Text
    scope: TargetScope
    lab: bool
    ownership_method: Text
    verification_token_hash: Text
    verified_at: UTCDatetime | None = None
    status: TargetStatus


class ScanFinding(SXModel):
    id: Id
    target_id: Id
    vuln_class: Text
    endpoint: Text
    evidence_event_ids: Annotated[list[Id], Field(min_length=1)]
    redacted_request_excerpt: str
    redacted_response_excerpt: str
    severity: Severity
    confidence: Confidence
    state: FindingState
    suggested_fix_category: Text
    linked_code_location: Text | None = None


class AttackIntent(SXModel):
    id: Id
    session_ref: Id
    intent: IntentLabel
    summary: Text
    cited_event_ids: Annotated[list[Id], Field(min_length=1)]
    confidence: Confidence
    state: Literal[EvidenceState.INFERRED] = EvidenceState.INFERRED


class VulnerabilityFinding(SXModel):
    id: Id
    scan_finding_id: Id
    file: Text
    line_start: Annotated[int, Field(ge=1)]
    line_end: Annotated[int, Field(ge=1)]
    reasoning: Text
    state: EvidenceState = EvidenceState.INFERRED

    @model_validator(mode="after")
    def _lines(self) -> VulnerabilityFinding:
        if self.line_end < self.line_start:
            raise ValueError("line_end < line_start")
        return self


class PatchProposal(SXModel):
    id: Id
    finding_id: Id
    diff: Text
    explanation: Text
    files_touched: Annotated[list[Text], Field(min_length=1)]
    fix_category: Text
    state: Literal[EvidenceState.PROPOSED] = EvidenceState.PROPOSED


class CheckResult(SXModel):
    name: Text
    passed: bool
    output_excerpt: str


class RepairVerification(SXModel):
    patch_id: Id
    checks: Annotated[list[CheckResult], Field(min_length=1)]
    status: VerificationStatus
    verifier_version: Text
    duration_ms: Annotated[int, Field(ge=0)]


class ShieldScope(SXModel):
    route: Text
    parameter: Text | None = None
    client: Text | None = None


class ShieldRule(SXModel):
    id: Id
    target_id: Id
    scope: ShieldScope
    action: Text
    reason: Text
    linked_finding_id: Id | None = None
    intent_event_ids: list[Id]
    owner: Text
    created_at: UTCDatetime
    expires_at: UTCDatetime
    status: ShieldStatus
    label: Literal["TEMPORARY SHIELD, NOT A FIX"] = SHIELD_LABEL

    @model_validator(mode="after")
    def _temporary(self) -> ShieldRule:
        if self.expires_at <= self.created_at:
            raise ValueError("a shield rule must expire after it is created")
        return self


class EscalationTicket(SXModel):
    id: Id
    finding_id: Id
    evidence_event_ids: Annotated[list[Id], Field(min_length=1)]
    explanation: Text
    options: Annotated[list[Text], Field(min_length=2, max_length=3)]
    suggested_interim_shield_id: Id | None = None
    status: EscalationStatus
    created_at: UTCDatetime


class ApprovalRecord(SXModel):
    id: Id
    subject_type: Text
    subject_id: Id
    reviewer: Text
    decision: ApprovalDecision
    rationale: Text
    timestamp: UTCDatetime


# ---------------------------------------------------------------- infrastructure
class ModelStatus(SXModel):
    """Which provider/model produced a result and in what mode (LIVE / RECORDED / UNAVAILABLE)."""

    provider: Text
    model: Text
    mode: ModelMode
    calls: Annotated[int, Field(ge=0)]
    tokens: Annotated[int, Field(ge=0)]
    error: Text | None = None


class Actor(SXModel):
    id: Id
    role: ActorRole


class SessionRecord(SXModel):
    id: Id
    kind: SessionKind
    scenario_id: Id | None = None
    target_id: Id | None = None
    arm: Arm | None = None
    state: SessionState
    model: Text | None = None
    provider: Text | None = None
    created_at: UTCDatetime
    started_at: UTCDatetime | None = None
    ended_at: UTCDatetime | None = None
    policy_version: Text
    fixture_version: Text | None = None
    idempotency_key: Text | None = None


class AuditRecord(SXModel):
    session_id: Id | None = None
    actor_id: Id
    actor_role: ActorRole
    action: Text
    from_state: SessionState | None = None
    to_state: SessionState | None = None
    timestamp: UTCDatetime
    detail: str = ""


class UsageRecord(SXModel):
    session_id: Id | None = None
    provider: Text
    model: Text
    tokens_in: Annotated[int, Field(ge=0)]
    tokens_out: Annotated[int, Field(ge=0)]
    latency_ms: Annotated[int, Field(ge=0)]
    estimated_cost: Annotated[float, Field(ge=0)] | None = None
    error: Text | None = None
    timestamp: UTCDatetime


ALL_MODELS: list[type[SXModel]] = [
    ScenarioSpec, ActionRequest, PolicyDecision, EvidenceEvent, IncidentFinding,
    ContainmentBranch, TargetAuthorization, ScanFinding, AttackIntent, VulnerabilityFinding,
    PatchProposal, RepairVerification, ShieldRule, EscalationTicket, ApprovalRecord,
    ModelStatus, Actor, SessionRecord, AuditRecord, UsageRecord,
]
