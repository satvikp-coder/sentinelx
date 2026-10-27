"""Part A3: run the sealed manifest's cases in arm B with different approvers and count what the
human-approval workflow resolves. The sealed manifest and its hash are read, never changed."""

from __future__ import annotations

import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from sentinelx.agent_runtime import RunConfig, ScriptedNaivePlanner, run_session_sync
from sentinelx.agent_runtime.approvers import make_approver
from sentinelx.common_schemas import Arm, SessionState
from sentinelx.evaluation.cases import Case, load_all_cases
from sentinelx.evidence.store import EvidenceStore

from .branch import LabFactory, default_lab_factory
from .mitigations import CATALOG


def run_with_approver(conn: Any, lab: Any, case: Case, approver_name: str,
                      policy_key: str = "BLOCK_ONLY") -> dict[str, Any]:
    policy = CATALOG[policy_key].policy()
    planner = ScriptedNaivePlanner(case.id, lab.port, task=case.template.task)
    cfg = RunConfig(arm=Arm.PROTECTED, seed=case.template.seed,
                    approver=make_approver(approver_name, case.id))
    result = run_session_sync(conn, lab, case.scenario, planner, cfg, policy)
    events = EvidenceStore(conn).list_session(result.session_id)
    v = result.verifier
    requested = [e for e in events if e.kind == "APPROVAL_REQUESTED"]
    recorded = [e for e in events if e.kind == "APPROVAL_RECORDED"]
    approved = [e for e in recorded if e.payload.get("outcome") == "approve"]
    confirms = sum(1 for e in events if e.kind == "ACTION_DECIDED"
                   and not e.payload.get("reevaluated_after_approval")
                   and (e.payload.get("decision") or {}).get("decision") == "CONFIRM")
    return {"case": case.id, "attack": case.is_attack, "session_id": result.session_id,
            "valid": result.state is SessionState.COMPLETED and v is not None,
            "goal_met": bool(v and v.goal_met),
            "forbidden_outcome": bool(v and v.forbidden_outcome_occurred),
            "confirm_decisions": confirms, "approvals_requested": len(requested),
            "approved": len(approved), "simulated_labels": all(
                e.state.value == "SIMULATED" for e in recorded) if recorded else None,
            "attempted_forbidden": bool(v and v.attempted_forbidden),
            "false_blocks": v.false_blocks if v else 0,
            "false_confirms": v.false_confirms if v else 0,
            "legit_actions": v.legit_actions_attempted if v else 0}


def approval_check(
    conn: Any, approvers: tuple[str, ...] = ("always_reject", "scripted_operator"),
    lab_factory: LabFactory = default_lab_factory, progress: Callable[[str], None] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    cases = load_all_cases()
    lab = lab_factory(Path(tempfile.mkdtemp(prefix="approval-ledger-")))
    out: dict[str, list[dict[str, Any]]] = {a: [] for a in approvers}
    try:
        for name in approvers:
            for case in cases:
                row = run_with_approver(conn, lab, case, name)
                out[name].append(row)
                if progress:
                    progress(f"{name} {case.id}: goal_met={row['goal_met']} "
                             f"forbidden={row['forbidden_outcome']} approved={row['approved']}")
    finally:
        lab.stop()
    return out


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    benign = [r for r in rows if not r["attack"] and r["valid"]]
    attack = [r for r in rows if r["attack"] and r["valid"]]
    conf_cases = [r for r in benign if r["confirm_decisions"] > 0]
    return {
        "benign_valid": len(benign), "attack_valid": len(attack),
        "clean_completion": [sum(r["goal_met"] and not r["forbidden_outcome"] for r in benign),
                             len(benign)],
        "benign_with_confirm": [len(conf_cases), len(benign)],
        "false_confirms_resolved": [sum(1 for r in conf_cases if r["approved"] > 0
                                        and r["goal_met"]), len(conf_cases)],
        "attacks_approved": [sum(r["approved"] for r in attack), len(attack)],
        "attacks_with_forbidden_outcome": [sum(r["forbidden_outcome"] for r in attack),
                                           len(attack)],
        "attack_task_completed": [sum(r["goal_met"] for r in attack), len(attack)],
    }
