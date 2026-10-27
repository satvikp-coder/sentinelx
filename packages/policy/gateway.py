"""decide_and_record: evaluate() plus its two evidence events, in one transaction.

evaluate() stays pure; this is the only place in the policy package that touches storage.
Import it as ``sentinelx.policy.gateway`` (it is not re-exported from ``sentinelx.policy`` to
keep the pure core free of any storage dependency).
"""

from __future__ import annotations

import sqlite3
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sentinelx.common_schemas import (
    ActionRequest,
    ApprovalRequest,
    Decision,
    EvidenceState,
    PolicyDecision,
)
from sentinelx.evidence.db import transaction
from sentinelx.evidence.store import EvidenceStore

from .config import LoadedPolicy
from .engine import approval_subject_id, args_digest, evaluate

PROPOSED_KIND = "ACTION_PROPOSED"
DECIDED_KIND = "ACTION_DECIDED"


@dataclass(frozen=True)
class GatewayResult:
    decision: PolicyDecision
    approval_request: ApprovalRequest | None
    proposed_event_id: str
    decided_event_id: str
    decision_ms: float = 0.0  # time spent in evaluate() only (no storage)


def make_approval_request(
    request: ActionRequest, decision: PolicyDecision, session_id: str, now: datetime | None = None
) -> ApprovalRequest:
    """Describe the approval a human must record (as an ApprovalRecord) for a CONFIRM decision."""
    return ApprovalRequest(
        id=f"apr_{uuid.uuid4().hex}",
        session_id=session_id,
        action_id=request.action_id,
        tool=request.tool,
        args_digest=args_digest(request.tool, request.arguments),
        subject_id=approval_subject_id(request.action_id, request.tool, request.arguments),
        reason_code=decision.reason_code,
        explanation=decision.explanation,
        created_at=now or datetime.now(UTC),
    )


def decide_and_record(
    conn: sqlite3.Connection,
    session_id: str,
    action_request: Any,
    scenario: Any,
    policy: LoadedPolicy,
    session_context: Any,
    *,
    now: datetime | None = None,
) -> GatewayResult:
    """evaluate + append ACTION_PROPOSED then ACTION_DECIDED (parent-linked), atomically."""
    t0 = time.perf_counter()
    decision = evaluate(action_request, scenario, policy, session_context)
    decision_ms = (time.perf_counter() - t0) * 1000.0
    request = _as_request(action_request)
    proposal_payload: dict[str, Any] = (
        request.model_dump(mode="json")
        if request is not None
        else {"malformed": True, "raw": repr(action_request)[:500]}
    )
    store = EvidenceStore(conn)
    with transaction(conn):
        proposed = store.append(
            session_id, PROPOSED_KIND, EvidenceState.PROPOSED, "policy_gateway", proposal_payload,
            timestamp=now,
        )
        decided = store.append(
            session_id, DECIDED_KIND, EvidenceState.OBSERVED, "policy_gateway",
            {"decision": decision.model_dump(mode="json")},
            parent_event_id=proposed.id, timestamp=now,
        )
    approval = None
    if decision.decision is Decision.CONFIRM and request is not None:
        approval = make_approval_request(request, decision, session_id, now)
    return GatewayResult(decision, approval, proposed.id, decided.id, decision_ms)


def _as_request(raw: Any) -> ActionRequest | None:
    try:
        if isinstance(raw, ActionRequest):
            return ActionRequest.model_validate(raw.model_dump(mode="python"))
        if isinstance(raw, dict):
            return ActionRequest.model_validate(raw)
    except Exception:
        return None
    return None
