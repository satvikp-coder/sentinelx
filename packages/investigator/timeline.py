"""Ordered timeline with parent links, state labels and short causal chains. Deterministic."""

from __future__ import annotations

import sqlite3
from typing import Any

from pydantic import BaseModel, ConfigDict

from sentinelx.evidence.store import EvidenceStore

LABEL_BY_STATE = {
    "OBSERVED": "OBSERVED", "INFERRED": "INFERRED", "PROPOSED": "PROPOSED",
    "SIMULATED": "SIMULATED (not executed)", "VERIFIED": "VERIFIED", "APPLIED": "APPLIED",
}
BLOCKING = {"BLOCK", "CONFIRM"}


class TimelineEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    seq: int
    event_id: str
    kind: str
    state: str
    label: str
    parent_event_id: str | None
    summary: str


class CausalChain(BaseModel):
    """proposal -> decision -> execution / block, for ONE proposed action."""

    model_config = ConfigDict(extra="forbid")

    action_id: str | None
    tool: str | None
    proposal_event_id: str
    decision_event_id: str | None
    decision: str | None  # ALLOW | BLOCK | CONFIRM | None (unprotected arm)
    reason_code: str | None
    executed_event_id: str | None
    outcome: str  # executed | blocked | not_executed
    shadow_event_id: str | None = None  # SIMULATED analysis only


class Timeline(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str
    entries: list[TimelineEntry]
    chains: list[CausalChain]


def _summary(kind: str, p: dict[str, Any]) -> str:
    if kind == "ACTION_PROPOSED":
        return f"proposed {p.get('tool')}"
    if kind in {"ACTION_DECIDED", "SHADOW_DECISION"}:
        d = p.get("decision") if isinstance(p.get("decision"), dict) else {}
        return f"{d.get('decision')} ({d.get('reason_code')})"
    if kind == "ACTION_EXECUTED":
        return f"executed {p.get('tool')} ok={p.get('ok')}"
    if kind in {"EGRESS_BLOCKED", "SANDBOX_BLOCKED"}:
        return f"{kind.split('_')[0].lower()} blocked ({p.get('reason')})"
    if kind == "VERIFIER_RESULT":
        r = p.get("result") if isinstance(p.get("result"), dict) else {}
        return (f"forbidden_outcome_occurred={r.get('forbidden_outcome_occurred')} "
                f"goal_met={r.get('goal_met')}")
    if kind == "RUN_STARTED":
        return f"run started in arm {p.get('arm')}"
    return kind.lower().replace("_", " ")


def build_timeline(conn: sqlite3.Connection, session_id: str) -> Timeline:
    events = EvidenceStore(conn).list_session(session_id)
    entries = [TimelineEntry(
        seq=e.seq, event_id=e.id, kind=e.kind, state=e.state.value,
        label=LABEL_BY_STATE.get(e.state.value, e.state.value), parent_event_id=e.parent_event_id,
        summary=_summary(e.kind, e.payload)) for e in events]
    children: dict[str, list[Any]] = {}
    for e in events:
        if e.parent_event_id:
            children.setdefault(e.parent_event_id, []).append(e)
    chains: list[CausalChain] = []
    for e in events:
        if e.kind != "ACTION_PROPOSED":
            continue
        kids = children.get(e.id, [])
        decided = next((k for k in kids if k.kind == "ACTION_DECIDED"), None)
        shadow = next((k for k in kids if k.kind == "SHADOW_DECISION"), None)
        executed = next((k for k in kids if k.kind == "ACTION_EXECUTED"), None)
        d = decided.payload.get("decision") if decided is not None else None
        d = d if isinstance(d, dict) else {}
        decision = d.get("decision")
        outcome = ("executed" if executed is not None
                   else "blocked" if decision in BLOCKING else "not_executed")
        chains.append(CausalChain(
            action_id=e.payload.get("action_id"), tool=e.payload.get("tool"),
            proposal_event_id=e.id, decision_event_id=decided.id if decided else None,
            decision=decision, reason_code=d.get("reason_code"),
            executed_event_id=executed.id if executed else None, outcome=outcome,
            shadow_event_id=shadow.id if shadow else None))
    return Timeline(session_id=session_id, entries=entries, chains=chains)
