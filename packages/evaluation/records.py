"""Per-run records written by the experiment runner and consumed by the metrics."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import ConfigDict, Field

from sentinelx.common_schemas import EvidenceEvent, SXModel, VerifierResult

PLANNER_LABEL = "SIMULATED scripted"


class PlannerInfo(SXModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    kind: str
    label: str = PLANNER_LABEL
    is_llm: bool = False
    provider: str = "none"
    model: str = "none"
    mode: str = "SIMULATED"
    prompt_version: str | None = None


class RunRecord(SXModel):
    """One executed run (valid or invalid). Metrics use ONLY verifier output and these
    evidence-derived fields; nothing the agent said is used except through the verifier."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    case_id: str
    arm: Literal["A", "B"]
    rep: Annotated[int, Field(ge=0)] = 0
    label: Literal["attack", "benign"]
    scenario: Literal["S1", "S2", "S3"]
    surface: str
    order_index: Annotated[int, Field(ge=0)]
    seed: int
    session_id: str | None = None
    valid: bool
    invalid_reason: str | None = None
    retried: bool = False
    first_attempt_error: str | None = None
    fixture_hash: str | None = None
    policy_version: str | None = None
    verifier_version: str | None = None
    planner: PlannerInfo
    provider: str = "none"
    model: str = "none"
    mode: str = "SIMULATED"
    started_at: str
    ended_at: str
    total_ms: float = 0.0
    gateway_decision_ms: list[float] = []  # evaluate() time per action decision (arm B only)
    page_policy_ms: list[float] = []  # per page-request decision (arm B only)
    end_state: str | None = None
    abort_reason: str | None = None
    chain_ok: bool | None = None
    leaked_processes: int | None = None
    # model-driven planners only (all zero / empty for the scripted planner)
    model_calls: int = 0  # HTTP requests sent to the model (retries included)
    model_tokens_in: int = 0
    model_tokens_out: int = 0
    model_latency_ms: list[float] = []  # per logical call, HTTP time only
    model_rate_limit_hits: int = 0
    model_retries: int = 0
    model_invalid_outputs: int = 0
    verifier: VerifierResult | None = None
    # real (non-shadow) non-ALLOW decisions in this run, by controlling rule
    block_rules: dict[str, int] = {}

    @property
    def stopped_by(self) -> list[str]:
        return list(self.verifier.stopped_by) if self.verifier else []


def block_rules_from_events(events: list[EvidenceEvent]) -> dict[str, int]:
    """Count REAL non-ALLOW action decisions and page-egress blocks by rule.

    SHADOW_DECISION events (arm A, state SIMULATED) are never counted."""
    counts: dict[str, int] = {}
    for e in events:
        if e.kind == "ACTION_DECIDED":
            decision = e.payload.get("decision", {})
            if decision.get("effective_action", decision.get("decision")) != "ALLOW":
                rule = (decision.get("rule_ids") or ["UNKNOWN"])[-1]
                counts[rule] = counts.get(rule, 0) + 1
        elif e.kind == "EGRESS_BLOCKED":
            counts["EGRESS_BLOCKED"] = counts.get("EGRESS_BLOCKED", 0) + 1
    return dict(sorted(counts.items()))


def to_jsonable(record: RunRecord) -> dict[str, Any]:
    return record.model_dump(mode="json")
