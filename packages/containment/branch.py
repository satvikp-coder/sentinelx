"""Checkpoints and branches.

A checkpoint captures what is needed to recreate the same STARTING STATE in a fresh lab (scenario,
seed, fixture hash, policy, planner script); it does not snapshot browser memory. A branch is a
RE-EXECUTION of the SIMULATED scripted planner from that checkpoint with one mitigation applied,
in its own freshly started lab (own ledger file, own process state), judged by the independent
verifier. Nothing real is rolled back: effects the parent run produced stay in the parent."""

from __future__ import annotations

import hashlib
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from sentinelx.agent_runtime import RunConfig, ScriptedNaivePlanner, run_session_sync
from sentinelx.agent_runtime.approvers import Approver, make_approver
from sentinelx.common_schemas import (
    Arm,
    ContainmentBranch,
    EvidenceEvent,
    ModelMode,
    SessionKind,
    SessionState,
    VerifierResult,
)
from sentinelx.evaluation.cases import Case
from sentinelx.evidence.records import RecordStore
from sentinelx.evidence.store import EvidenceStore

from .mitigations import MitigationSpec

PLANNER_LABEL = "SIMULATED scripted"
EXECUTION_MODE = "RE-EXECUTION (fresh lab, nothing real is rolled back)"
LabFactory = Callable[[Path], Any]


def default_lab_factory(ledger_dir: Path) -> Any:
    from apps.fixture_lab.server import LabServer

    return LabServer(ledger_dir).start()


class Checkpoint(BaseModel):
    """Everything needed to recreate the same starting state in a fresh lab."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    case_id: str
    seed: int
    fixture_hash: str
    policy_version: str
    planner: str = PLANNER_LABEL
    script_version: str
    step_index_of_decision: int | None  # step of the first forbidden proposal in the parent
    parent_session_id: str
    trace_event_ids: list[str]
    ref: str


@dataclass
class ParentRun:
    case: Case
    session_id: str
    fixture_hash: str
    verifier: VerifierResult
    proposals: int
    checkpoint: Checkpoint
    events: list[EvidenceEvent] = field(default_factory=list)


@dataclass
class BranchResult:
    mitigation: str
    branch: ContainmentBranch
    session_id: str
    valid: bool
    invalid_reason: str | None
    blocked_legitimate: int
    confirmed_legitimate: int
    stripped_chars: int
    strip_spans: list[dict[str, Any]]
    proposals: int
    approvals: list[dict[str, Any]]
    stopped_by: list[str]
    goal_met: bool
    trap: bool = False
    baseline: bool = False
    planner: str = PLANNER_LABEL
    execution: str = EXECUTION_MODE
    chain_ok: bool = True


def script_version(case: Case) -> str:
    doc = case.template.task.model_dump_json()
    return hashlib.sha256(doc.encode("utf-8")).hexdigest()[:12]


def _forbidden_closure(events: list[EvidenceEvent], verifier: VerifierResult) -> set[str]:
    ids = set(verifier.cited_event_ids)
    ids |= {e.id for e in events if e.parent_event_id in ids}
    return ids


def _run(conn: Any, case: Case, spec: MitigationSpec | None, approver: Approver | None,
         arm: Arm, kind: SessionKind, note: dict[str, Any], ledger_root: Path,
         lab_factory: LabFactory, policy: Any, wall_clock: float) -> tuple[Any, Any, float]:
    lab = lab_factory(Path(tempfile.mkdtemp(prefix="evcs-ledger-", dir=ledger_root)))
    try:
        fixture_hash = lab.reset(case.scenario.id, case.template.seed)
        assert lab.read_ledger() == [], "a branch must start with an empty ledger"
        planner = ScriptedNaivePlanner(case.id, lab.port, task=case.template.task)
        config = RunConfig(
            arm=arm, seed=case.template.seed, wall_clock_seconds=wall_clock, approver=approver,
            scenario_override=spec.override() if spec else None,
            observation_filter=spec.observation_filter() if spec else None,
            session_kind=kind, run_note={**note, "fixture_hash_expected": fixture_hash})
        started = time.perf_counter()
        result = run_session_sync(conn, lab, case.scenario, planner, config, policy)
        return result, fixture_hash, (time.perf_counter() - started) * 1000.0
    finally:
        lab.stop()


def run_parent(conn: Any, case: Case, *, ledger_root: Path | None = None,
               lab_factory: LabFactory = default_lab_factory, wall_clock: float = 90.0
               ) -> ParentRun:
    """The recorded attack session: the SIMULATED scripted planner, no gateway (arm A)."""
    from .mitigations import CATALOG

    policy = CATALOG["BLOCK_ONLY"].policy()
    root = ledger_root or Path(tempfile.mkdtemp(prefix="evcs-"))
    result, fixture_hash, _ = _run(conn, case, None, None, Arm.UNPROTECTED,
                                   SessionKind.AGENT_RUN, {"containment_role": "parent"}, root,
                                   lab_factory, policy, wall_clock)
    assert result.verifier is not None, "the parent run produced no verifier result"
    events = EvidenceStore(conn).list_session(result.session_id)
    related = _forbidden_closure(events, result.verifier)
    first = next((e for e in events if e.kind == "ACTION_PROPOSED" and e.id in related), None)
    trace = [e.id for e in events if e.kind in {"ACTION_PROPOSED", "ACTION_EXECUTED"}]
    ckpt = Checkpoint(
        scenario_id=case.scenario.id, case_id=case.id, seed=case.template.seed,
        fixture_hash=fixture_hash, policy_version=policy.policy_version,
        script_version=script_version(case),
        step_index_of_decision=(first.payload.get("step") if first else None),
        parent_session_id=result.session_id, trace_event_ids=trace,
        ref=f"ckpt:{case.id}:{case.template.seed}:{fixture_hash[:12]}")
    proposals = sum(e.kind == "ACTION_PROPOSED" for e in events)
    return ParentRun(case, result.session_id, fixture_hash, result.verifier, proposals, ckpt,
                     events)


def run_branch(conn: Any, parent: ParentRun, spec: MitigationSpec, *, approver_name: str,
               ledger_root: Path | None = None, lab_factory: LabFactory = default_lab_factory,
               wall_clock: float = 90.0) -> BranchResult:
    """Re-execute the scripted planner from the parent's checkpoint with `spec` applied."""
    case, ckpt = parent.case, parent.checkpoint
    name = "always_reject" if spec.approver == "always_reject" else approver_name
    approver = make_approver(name, case.id)
    root = ledger_root or Path(tempfile.mkdtemp(prefix="evcs-"))
    note = {"containment_role": "branch", "mitigation": spec.id, "trap": spec.trap,
            "baseline": spec.baseline, "parent_session_id": ckpt.parent_session_id,
            "checkpoint_ref": ckpt.ref, "containment_planner": PLANNER_LABEL,
            "execution": EXECUTION_MODE}
    result, fixture_hash, duration = _run(
        conn, case, spec, approver, spec.arm, SessionKind.CONTAINMENT, note, root, lab_factory,
        spec.policy(), wall_clock)
    assert fixture_hash == ckpt.fixture_hash, "branch fixture differs from the parent's"
    store = EvidenceStore(conn)
    events = store.list_session(result.session_id)
    chain_ok = store.verify_chain(result.session_id).ok
    v = result.verifier
    reason = None
    if result.state is not SessionState.COMPLETED:
        reason = f"state {result.state.value}: {result.abort_reason}"
    elif v is None:
        reason = "verifier did not run"
    elif not chain_ok:
        reason = "evidence chain failed verification"
    forbidden = _forbidden_closure(events, v) if v else set()
    proposals = [e for e in events if e.kind == "ACTION_PROPOSED"]
    decided = [e for e in events if e.kind == "ACTION_DECIDED"
               and not e.payload.get("reevaluated_after_approval")]
    confirmed_legit = sum(1 for e in decided if e.parent_event_id not in forbidden
                          and (e.payload.get("decision") or {}).get("decision") == "CONFIRM")
    strips = [e.payload for e in events if e.kind == "INSTRUCTIONS_STRIPPED"]
    approvals = [{"outcome": e.payload.get("outcome"), "approver": e.payload.get("approver"),
                  "simulated": e.payload.get("simulated"), "event_id": e.id}
                 for e in events if e.kind == "APPROVAL_RECORDED"]
    branch = ContainmentBranch(
        branch_id=f"br_{result.session_id}", parent_session_id=ckpt.parent_session_id,
        checkpoint_ref=ckpt.ref, mitigation_id=spec.id, new_seed=case.template.seed,
        executed_trace_id=result.session_id,
        unauthorized_executed=bool(v and v.forbidden_outcome_occurred),
        task_completed=bool(v and v.goal_met),
        added_actions=max(0, len(proposals) - len(case.template.task.steps)),
        duration_ms=int(duration), verifier_version=v.verifier_version if v else "none",
        was_simulated=False, was_executed=True, model_mode=ModelMode.NONE,
        fixture_hash=fixture_hash)
    RecordStore(conn).insert(branch)
    return BranchResult(
        mitigation=spec.id, branch=branch, session_id=result.session_id, valid=reason is None,
        invalid_reason=reason, blocked_legitimate=(v.false_blocks if v else 0),
        confirmed_legitimate=confirmed_legit,
        stripped_chars=sum(int(s.get("stripped_chars", 0)) for s in strips),
        strip_spans=[sp for s in strips for sp in s.get("spans", [])],
        proposals=len(proposals), approvals=approvals, stopped_by=list(v.stopped_by) if v else [],
        goal_met=bool(v and v.goal_met), trap=spec.trap, baseline=spec.baseline,
        chain_ok=chain_ok)
