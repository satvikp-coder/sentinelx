"""Evidence-Verified Containment Search for one attack case (SIMULATED scripted planner)."""

from __future__ import annotations

import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinelx.agent_runtime.runner import materialize_scenario
from sentinelx.common_schemas import ActionRequest, EvidenceState
from sentinelx.evaluation.cases import Case
from sentinelx.evidence.store import EvidenceStore
from sentinelx.model_clients import ModelClient
from sentinelx.policy import SessionContext, evaluate

from .branch import (
    BranchResult,
    LabFactory,
    ParentRun,
    default_lab_factory,
    run_branch,
    run_parent,
)
from .mitigations import CATALOG, CONTROLS, RECOMMENDABLE
from .selection import Recommendation, Weights, load_weights, select
from .suggest import SuggestionOutcome, suggest

REPLAY_LABEL = "RECORDED REPLAY (decisions re-evaluated on the recorded trace; nothing re-executed)"


@dataclass
class EvcsCase:
    case_id: str
    parent: ParentRun
    branches: list[BranchResult]
    recommendation: Recommendation
    weights: Weights
    approver: str
    suggestion: SuggestionOutcome | None = None
    events: dict[str, str] = field(default_factory=dict)  # name -> evidence event id


def run_evcs_case(conn: Any, case: Case, *, mitigations: list[str] | None = None,
                  weights: Weights | None = None, approver_name: str = "scripted_operator",
                  client: ModelClient | None = None, lab_factory: LabFactory = default_lab_factory,
                  ledger_root: Path | None = None, wall_clock: float = 90.0) -> EvcsCase:
    weights = weights or load_weights()
    root = ledger_root or Path(tempfile.mkdtemp(prefix="evcs-"))
    parent = run_parent(conn, case, ledger_root=root, lab_factory=lab_factory,
                        wall_clock=wall_clock)
    suggestion: SuggestionOutcome | None = None
    chosen = list(mitigations) if mitigations else list(RECOMMENDABLE)
    if client is not None:
        suggestion = suggest(conn, parent.session_id, client)
        chosen = suggestion.chosen
    unknown = [m for m in chosen if m not in CATALOG or not CATALOG[m].recommendable]
    if unknown:
        raise ValueError(f"not a candidate mitigation: {unknown}")
    plan = [*chosen, *CONTROLS]  # the controls (trap, baseline) always run, for comparison
    branches = [run_branch(conn, parent, CATALOG[m], approver_name=approver_name,
                           ledger_root=root, lab_factory=lab_factory, wall_clock=wall_clock)
                for m in plan]
    rec = select(branches, weights)
    result = EvcsCase(case.id, parent, branches, rec, weights, approver_name, suggestion)
    record_events(conn, result)
    return result


def record_events(conn: Any, r: EvcsCase) -> None:
    """Checkpoint, one event per branch (citing the branch session id) and the recommendation."""
    store, sid = EvidenceStore(conn), r.parent.session_id
    ckpt = store.append(sid, "EVCS_CHECKPOINT", EvidenceState.OBSERVED, "containment",
                        {**r.parent.checkpoint.model_dump(mode="json"),
                         "label": "starting state for re-execution; browser memory not captured"})
    r.events["checkpoint"] = ckpt.id
    for b in r.branches:
        ev = store.append(sid, "EVCS_BRANCH", EvidenceState.OBSERVED, "containment", {
            "mitigation": b.mitigation, "branch_session_id": b.session_id, "trap": b.trap,
            "baseline": b.baseline, "valid": b.valid,
            "unauthorized_executed": b.branch.unauthorized_executed,
            "task_completed": b.branch.task_completed, "planner": b.planner,
            "execution": b.execution, "verifier_version": b.branch.verifier_version},
            parent_event_id=ckpt.id)
        r.events[b.mitigation] = ev.id
    rec = r.recommendation
    ev = store.append(sid, "EVCS_RECOMMENDATION", EvidenceState.PROPOSED, "containment", {
        "recommendation": rec.action, "winner": rec.winner, "runner_up": rec.runner_up,
        "human_review": rec.human_review, "message": rec.message, "tie": rec.tie,
        "tied": rec.tied, "weights_version": rec.weights_version, "model_cost": rec.model_cost,
        "cited_branch_session_ids": [b.session_id for b in r.branches],
        "ineligible": rec.ineligible, "planner": "SIMULATED scripted"}, parent_event_id=ckpt.id)
    r.events["recommendation"] = ev.id


def replay_decisions(conn: Any, parent: ParentRun, mitigation: str, lab_port: int = 0
                     ) -> list[dict[str, Any]]:
    """RECORDED REPLAY: re-evaluate the parent's recorded proposals under a mitigation's policy.
    Pure policy evaluation - no browser, no lab; it shows what the gateway WOULD decide on the
    recorded trace, which can differ from a re-execution because a planner may act differently."""
    spec = CATALOG[mitigation]
    policy = spec.policy()
    scenario = materialize_scenario(parent.case.scenario, lab_port)
    override = spec.override()
    scenario = override(scenario) if override else scenario
    from sentinelx.common_schemas import SessionState

    out: list[dict[str, Any]] = []
    last = None
    for e in EvidenceStore(conn).list_session(parent.session_id):
        if e.kind != "ACTION_PROPOSED":
            continue
        req = ActionRequest.model_validate(e.payload)
        ctx = SessionContext(session_id=req.session_id, state=SessionState.RUNNING, last_step=last,
                             steps_taken=len(out))
        d = evaluate(req, scenario, policy, ctx)
        out.append({"event_id": e.id, "action_id": req.action_id, "tool": req.tool,
                    "decision": d.decision.value, "reason": d.reason_code, "label": REPLAY_LABEL})
        last = req.step
    return out


def divergence(replay: list[dict[str, Any]], branch: BranchResult, conn: Any) -> list[str]:
    """Where the recorded replay and the re-execution disagree (by action id)."""
    events = EvidenceStore(conn).list_session(branch.session_id)
    actual = {e.payload.get("action_id"): (e.payload.get("decision") or {}).get("decision")
              for e in events if e.kind == "ACTION_DECIDED"
              and not e.payload.get("reevaluated_after_approval")}
    notes = []
    for r in replay:
        got = actual.get(r["action_id"], "NOT_PROPOSED_IN_BRANCH")
        if got != r["decision"]:
            notes.append(f"{r['action_id']} ({r['tool']}): replay {r['decision']} vs "
                         f"re-execution {got}")
    replay_ids = {r["action_id"] for r in replay}
    notes += [f"{a}: proposed only in the re-execution" for a in actual if a not in replay_ids]
    return notes

