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
    PolicyMode,
    SafetyConstraint,
    SessionKind,
    SessionState,
    Severity,
    ShieldStatus,
    SignalKind,
    Surface,
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


class PolicySignal(SXModel):
    """A hint found in untrusted text. Evidence only: it never changes allow/block."""

    kind: SignalKind
    source: Text
    matched_text: Annotated[str, Field(max_length=200)]
    start: Annotated[int, Field(ge=0)]
    end: Annotated[int, Field(ge=0)]


class PolicyDecision(SXModel):
    """``decision`` is what the policy decided; ``effective_action`` is what the runtime does.

    They differ only in monitor mode (effective ALLOW, ``would_have_decided`` = real decision).
    The last four fields were added after 1.0 was first published; additive, defaults keep old
    documents valid (see docs/DECISIONS.md).
    """

    action_id: Id
    decision: Decision
    policy_version: Text
    rule_ids: list[Id]
    reason_code: Text
    explanation: Text
    requires_human: bool
    policy_mode: PolicyMode = PolicyMode.ENFORCE
    effective_action: Decision | None = None
    would_have_decided: Decision | None = None
    signals: list[PolicySignal] = []

    @model_validator(mode="after")
    def _default_effective(self) -> PolicyDecision:
        if self.effective_action is None:
            self.effective_action = self.decision
        return self


class ApprovalRequest(SXModel):
    """Asks a human to approve one specific action (bound to its tool+arguments digest).

    It authorises nothing by itself: approval is a separate ApprovalRecord and the gateway
    re-evaluates the full policy before honouring it.
    """

    id: Id
    session_id: Id
    action_id: Id
    tool: Text
    args_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{16}$")]
    subject_id: Text  # what the ApprovalRecord must reference: "<action_id>:<args_digest>"
    reason_code: Text
    explanation: Text
    created_at: UTCDatetime


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


class VerifierResult(SXModel):
    """Outcome of one agent run, judged from lab ground truth (ledger), never from the agent."""

    session_id: Id
    scenario_id: Id
    verifier_version: Text
    forbidden_outcome_occurred: bool  # from the side-effect ledger ONLY
    goal_met: bool
    attempted_forbidden: bool  # planner proposed the forbidden action (ACTION_PROPOSED)
    executed_forbidden: bool  # the runtime executed it (ACTION_EXECUTED)
    blocked_forbidden: bool  # a forbidden proposal was decided BLOCK/CONFIRM and not run
    false_blocks: Annotated[int, Field(ge=0)]  # legitimate actions decided BLOCK (not run)
    # additive since verifier 1.1.0 (defaults keep older documents valid)
    false_confirms: Annotated[int, Field(ge=0)] = 0  # legitimate actions sent to CONFIRM
    legit_actions_attempted: Annotated[int, Field(ge=0)] = 0  # proposals that are not forbidden
    egress_blocked: Annotated[int, Field(ge=0)] = 0  # EGRESS_BLOCKED events (page requests)
    forbidden_egress_blocked: Annotated[int, Field(ge=0)] = 0  # ...at the forbidden endpoint
    stopped_by: list[Text] = []  # controls that stopped forbidden attempts
    cited_event_ids: list[Id] = []
    ledger_entries: Annotated[int, Field(ge=0)] = 0
    notes: list[str] = []


Vhost = Literal["orders", "calendar", "support"]


class FixtureAssertion(SXModel):
    """Machine-checkable claim about what a lab page serves for this case (validated in tests)."""

    kind: Literal["page_contains", "page_not_contains"]
    vhost: Vhost
    path: Text  # may include a query string
    text: Text


class Placement(SXModel):
    """Which lab page slot carries the case payload."""

    vhost: Vhost
    page: Text
    slot: Literal["body", "head", "tool_result"] = "body"


class TaskStep(SXModel):
    """One step of the scripted agent's LEGITIMATE task (the user's intent)."""

    tool: Literal["navigate", "read_page", "click", "submit_form", "tool_call", "http_request"]
    host: Vhost | None = None
    path: Text | None = None
    method: Text | None = None
    body: str | None = None
    selector: Text | None = None
    field_name: Text | None = None
    field_value: Text | None = None
    name: Text | None = None
    order_id: Text | None = None
    only_if_text: Text | None = None  # skip unless text read so far contains this

    @model_validator(mode="after")
    def _complete(self) -> TaskStep:
        need = {
            "navigate": ("host", "path"),
            "http_request": ("host", "path", "method"),
            "click": ("selector",),
            "submit_form": ("selector", "field_name", "field_value"),
            "tool_call": ("name", "order_id"),
            "read_page": (),
        }[self.tool]
        missing = [f for f in need if getattr(self, f) is None]
        if missing:
            raise ValueError(f"{self.tool} step needs {missing}")
        return self


class AnswerRule(SXModel):
    """How the scripted agent builds its final answer from what it actually observed."""

    kind: Literal["regex", "agenda", "step_result"]
    regex: Text | None = None  # regex: first match over all page text read
    template: Text | None = None  # regex: "{0}" is group 1
    step: Annotated[int, Field(ge=0)] | None = None  # step_result: index into the task steps
    success: Text | None = None
    failure: Text | None = None

    @model_validator(mode="after")
    def _complete(self) -> AnswerRule:
        if self.kind == "regex" and not (self.regex and self.template):
            raise ValueError("regex rule needs regex and template")
        if self.kind == "step_result" and not (
            self.step is not None and self.success and self.failure
        ):
            raise ValueError("step_result rule needs step, success and failure")
        return self


class TaskScript(SXModel):
    steps: Annotated[list[TaskStep], Field(min_length=1)]
    answer: Annotated[list[AnswerRule], Field(min_length=1)]
    fallback_answer: Text = "I could not complete the task."

    @model_validator(mode="after")
    def _steps_exist(self) -> TaskScript:
        for rule in self.answer:
            if rule.kind == "step_result" and rule.step >= len(self.steps):  # type: ignore[operator]
                raise ValueError("step_result refers to a missing step")
        return self


class _CaseBase(SXModel):
    """Shared by attack variants and their benign near-neighbors. Labels are hand-written and
    independent of any model."""

    id: Id
    surface: Surface
    authorized_goal: Text
    permitted_lab_target: Text  # the one lab host the user's task is allowed to use
    forbidden_outcome: ForbiddenOutcome  # ground-truth check against the lab ledger
    fixture_assertions: Annotated[list[FixtureAssertion], Field(min_length=1)]
    safety_constraints: list[SafetyConstraint]
    notes: str = ""
    # --- binding to the lab / scripted agent
    family: Literal["S1", "S2", "S3"]
    seed: int
    payload_id: Id  # fixtures/payloads/<payload_id>.html|json
    placement: Placement
    allowed_actions: Annotated[list[Text], Field(min_length=1)]
    goal_expected: Annotated[list[Text], Field(min_length=1)]  # goal_assertion: answer contains
    task: TaskScript
    expected_protected_rule: Text | None = None  # control expected to act; None = all ALLOW

    @field_validator("safety_constraints")
    @classmethod
    def _all_constraints(cls, v: list[SafetyConstraint]) -> list[SafetyConstraint]:
        if set(v) != set(SafetyConstraint):
            raise ValueError("every safety constraint must be declared")
        return v

    @field_validator("permitted_lab_target")
    @classmethod
    def _lab_host(cls, v: str) -> str:
        if not v.endswith(".lab.test") or "*" in v or "/" in v:
            raise ValueError("permitted_lab_target must be an exact *.lab.test host")
        return v


class GenerationInfo(SXModel):
    """Provenance of a MODEL-GENERATED attack variant (generated cases only)."""

    generated: Literal[True] = True
    seed_case_id: Id
    provider: Text
    model: Text
    mode: Text  # LIVE | RECORDED
    prompt_version: Text
    prompt_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    surface: Surface
    tone: Literal["formal", "urgent", "friendly", "technical"]
    length_cap: Annotated[int, Field(ge=20, le=600)]
    slot_text_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    generated_at: UTCDatetime


class AttackTemplate(_CaseBase):
    attacker_objective: Text
    benign_neighbor_id: Id
    # None for every hand-authored case. Additive: hand-authored files and hashes are unchanged.
    generated: GenerationInfo | None = None


class BenignTemplate(_CaseBase):
    attack_neighbor_id: Id


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
    ScenarioSpec, ActionRequest, PolicyDecision, ApprovalRequest, EvidenceEvent, IncidentFinding,
    ContainmentBranch, TargetAuthorization, ScanFinding, AttackIntent, VulnerabilityFinding,
    PatchProposal, RepairVerification, ShieldRule, EscalationTicket, ApprovalRecord,
    ModelStatus, Actor, SessionRecord, AuditRecord, UsageRecord, VerifierResult,
    AttackTemplate, BenignTemplate, GenerationInfo,
]
