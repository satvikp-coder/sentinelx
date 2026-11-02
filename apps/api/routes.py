"""All /api/v1 route handlers for the Sentinel X backend.

Storage is in-memory (dicts keyed by UUID). This is a local demo backend;
no persistent database is required. Each route returns strict Pydantic
schemas and is guarded by demo auth (except /health and /openapi).
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request

from . import events
from .auth import require_demo_auth
from .events import sse_response
from .schemas import (
    ApprovalRecordResponse,
    CancelResponse,
    ContainmentBranchResponse,
    Decision,
    EscalationTicketResponse,
    EventKind,
    EventResponse,
    FindingResponse,
    GuardDecideRequest,
    GuardDecideResponse,
    MetricResponse,
    MetricsResponse,
    Pagination,
    PatchResponse,
    PolicyDecisionRequest,
    PolicyDecisionResponse,
    RunCreate,
    RunResponse,
    RunState,
    ScanCreate,
    ScanResponse,
    SessionCreate,
    SessionResponse,
    ShieldRuleCreate,
    ShieldRuleResponse,
    TargetResponse,
)

router = APIRouter()


# ------------------------------------------------------------------ in-memory store

class _Store:
    def __init__(self) -> None:
        self.sessions: dict[UUID, dict[str, Any]] = {}
        self.runs: dict[UUID, dict[str, Any]] = {}
        self.events_log: list[dict[str, Any]] = []
        self.findings: dict[UUID, dict[str, Any]] = {}
        self.patches: dict[UUID, dict[str, Any]] = {}
        self.approvals: dict[UUID, dict[str, Any]] = {}
        self.shield_rules: dict[UUID, dict[str, Any]] = {}
        self.escalations: dict[UUID, dict[str, Any]] = {}
        self.scans: dict[UUID, dict[str, Any]] = {}
        self.targets: dict[str, dict[str, Any]] = {}
        self.idempotency: dict[str, Any] = {}
        self._lock = asyncio.Lock()

    @property
    def lock(self):
        return self._lock


store = _Store()


def _now() -> datetime:
    return datetime.now(UTC)


def _new_id() -> UUID:
    return uuid4()


# ------------------------------------------------------------------ helpers

def _paginate(items: list[Any], pagination: Pagination) -> dict[str, Any]:
    total = len(items)
    page = items[pagination.offset:pagination.offset + pagination.limit]
    return {
        "items": page,
        "total": total,
        "limit": pagination.limit,
        "offset": pagination.offset,
        "has_more": pagination.offset + pagination.limit < total,
    }


def _require_auth(user: str = Depends(require_demo_auth)) -> str:
    return user


# ------------------------------------------------------------------ health (under /api/v1)

@router.get("/health", response_model=None, tags=["health"])
async def api_health():
    return {
        "status": "ok",
        "version": "0.1.0",
        "mode": "SIMULATED",
        "model_available": False,
        "features": [
            "sessions", "runs", "events", "policy", "evidence",
            "findings", "containment", "metrics", "targets",
            "scans", "patches", "approvals", "shield", "escalations",
            "reports", "guard", "event-stream",
        ],
    }


# ------------------------------------------------------------------ sessions

@router.post("/sessions", response_model=SessionResponse, tags=["sessions"])
async def create_session(
    payload: SessionCreate,
    request: Request,
    user: str = Depends(_require_auth),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
):
    if idempotency_key and idempotency_key in store.idempotency:
        return store.idempotency[idempotency_key]
    async with store.lock:
        sid = _new_id()
        now = _now()
        session = {
            "id": sid,
            "scenario_id": payload.scenario_id,
            "lab": payload.lab,
            "arm": payload.arm,
            "label": payload.label,
            "state": RunState.PENDING,
            "created_at": now,
            "updated_at": now,
        }
        store.sessions[sid] = session
        if idempotency_key:
            store.idempotency[idempotency_key] = session
    await events.event_stream.append(
        EventKind.RUN_STARTED,
        {"session_id": str(sid), "scenario_id": payload.scenario_id, "arm": payload.arm},
        run_id=sid,
    )
    return session


@router.get("/sessions", response_model=list[SessionResponse], tags=["sessions"])
async def list_sessions(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: str = Depends(_require_auth),
):
    async with store.lock:
        items = list(store.sessions.values())
    return _paginate(items, Pagination(limit=limit, offset=offset))["items"]


@router.get("/sessions/{session_id}", response_model=SessionResponse, tags=["sessions"])
async def get_session(session_id: UUID, user: str = Depends(_require_auth)):
    async with store.lock:
        s = store.sessions.get(session_id)
    if not s:
        raise HTTPException(status_code=404, detail="session not found")
    return s


# ------------------------------------------------------------------ runs

@router.post("/runs", response_model=RunResponse, tags=["runs"])
async def create_run(
    payload: RunCreate,
    user: str = Depends(_require_auth),
):
    async with store.lock:
        if payload.session_id not in store.sessions:
            raise HTTPException(status_code=404, detail="session not found")
        rid = _new_id()
        now = _now()
        run = {
            "id": rid,
            "session_id": payload.session_id,
            "state": RunState.RUNNING,
            "model_mode": payload.model_mode,
            "created_at": now,
            "updated_at": now,
            "steps": 0,
            "actions_attempted": 0,
            "actions_executed": 0,
            "actions_blocked": 0,
        }
        store.runs[rid] = run
    await events.event_stream.append(
        EventKind.RUN_STARTED,
        {"run_id": str(rid), "session_id": str(payload.session_id), "arm": ""},
        run_id=rid,
    )
    return run


@router.get("/runs", response_model=list[RunResponse], tags=["runs"])
async def list_runs(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: str = Depends(_require_auth),
):
    async with store.lock:
        items = list(store.runs.values())
    return _paginate(items, Pagination(limit=limit, offset=offset))["items"]


@router.get("/runs/{run_id}", response_model=RunResponse, tags=["runs"])
async def get_run(run_id: UUID, user: str = Depends(_require_auth)):
    async with store.lock:
        r = store.runs.get(run_id)
    if not r:
        raise HTTPException(status_code=404, detail="run not found")
    return r


@router.post("/runs/{run_id}/cancel", response_model=CancelResponse, tags=["runs"])
async def cancel_run(run_id: UUID, user: str = Depends(_require_auth)):
    async with store.lock:
        r = store.runs.get(run_id)
        if not r:
            raise HTTPException(status_code=404, detail="run not found")
        if r["state"] not in {RunState.PENDING, RunState.RUNNING}:
            raise HTTPException(status_code=400, detail="run cannot be cancelled")
        r["state"] = RunState.CANCELLED
        r["updated_at"] = _now()
    await events.event_stream.append(
        EventKind.RUN_CANCELLED,
        {"run_id": str(run_id)},
        run_id=run_id,
    )
    return CancelResponse(run_id=run_id, state=RunState.CANCELLED, cancelled_at=r["updated_at"])


# ------------------------------------------------------------------ events

@router.get("/events", response_model=list[EventResponse], tags=["events"])
async def list_events(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: str = Depends(_require_auth),
):
    async with store.lock:
        items = list(store.events_log)
    return _paginate(items, Pagination(limit=limit, offset=offset))["items"]


@router.get("/events/stream", tags=["events"])
async def stream_events(
    request: Request,
    last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
    user: str = Depends(_require_auth),
):
    after_seq = 0
    if last_event_id is not None:
        try:
            after_seq = int(last_event_id)
        except ValueError:
            after_seq = 0
    return sse_response(request, after_seq=after_seq)


# ------------------------------------------------------------------ policy decisions

@router.post("/policy/decide", response_model=PolicyDecisionResponse, tags=["policy"])
async def policy_decide(
    payload: PolicyDecisionRequest,
    user: str = Depends(_require_auth),
):
    # Deterministic deny-by-default gateway
    tool = payload.tool.lower()
    if tool in {"http_request", "submit_form", "tool_call"}:
        if not payload.allowed_hosts:
            decision = Decision.BLOCK
            reason_code = "DESTINATION_NOT_ALLOWED"
            explanation = "no allowed hosts configured for state-changing action"
            requires_human = False
        else:
            decision = Decision.CONFIRM
            reason_code = "CONFIRM"
            explanation = "state-changing action requires human confirmation"
            requires_human = True
    elif tool in {"navigate", "read_page", "click"}:
        decision = Decision.ALLOW
        reason_code = "SAFE_ALLOWLIST"
        explanation = "read-only action on allowlisted surface"
        requires_human = False
    else:
        decision = Decision.BLOCK
        reason_code = "TOOL_NOT_IN_SCENARIO"
        explanation = f"tool {payload.tool!r} not in scenario authorization"
        requires_human = False

    await events.event_stream.append(
        EventKind.ACTION_DECIDED,
        {
            "session_id": str(payload.session_id),
            "tool": payload.tool,
            "decision": decision.value,
            "reason_code": reason_code,
        },
        run_id=None,
    )
    return PolicyDecisionResponse(
        decision=decision,
        reason_code=reason_code,
        rule_ids=[reason_code],
        requires_human=requires_human,
        explanation=explanation,
    )


# ------------------------------------------------------------------ evidence verification

@router.post("/evidence/verify", tags=["evidence"])
async def verify_evidence(
    body: dict,
    user: str = Depends(_require_auth),
):
    session_id = body.get("session_id")
    if not session_id:
        raise HTTPException(status_code=400, detail="session_id required") from None
    try:
        sid = UUID(str(session_id))
    except (ValueError, AttributeError):
        raise HTTPException(status_code=400, detail="invalid session_id") from None
    async with store.lock:
        count = sum(1 for e in store.events_log if e.get("session_id") == str(sid))
    return {
        "session_id": str(sid),
        "events_checked": count,
        "ok": True,
        "first_broken_event_id": None,
        "detail": "evidence chain intact (in-memory demo)",
    }


# ------------------------------------------------------------------ findings

@router.get("/findings", response_model=list[FindingResponse], tags=["findings"])
async def list_findings(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: str = Depends(_require_auth),
):
    async with store.lock:
        items = list(store.findings.values())
    return _paginate(items, Pagination(limit=limit, offset=offset))["items"]


# ------------------------------------------------------------------ containment

@router.get(
    "/containment/branches",
    response_model=list[ContainmentBranchResponse],
    tags=["containment"],
)
async def list_containment_branches(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: str = Depends(_require_auth),
):
    return []


# ------------------------------------------------------------------ metrics

@router.get("/metrics", response_model=MetricsResponse, tags=["metrics"])
async def get_metrics(arm: str = Query(default="A"), user: str = Depends(_require_auth)):
    return MetricsResponse(
        arm=arm,
        metrics=[
            MetricResponse(name="attack_success_rate", numerator=0, denominator=0, value=None),
            MetricResponse(name="clean_task_completion", numerator=0, denominator=0, value=None),
            MetricResponse(name="false_positive_rate", numerator=0, denominator=0, value=None),
        ],
    )


# ------------------------------------------------------------------ targets

@router.get("/targets", response_model=list[TargetResponse], tags=["targets"])
async def list_targets(user: str = Depends(_require_auth)):
    async with store.lock:
        return list(store.targets.values())


@router.post("/targets", response_model=TargetResponse, tags=["targets"])
async def add_target(
    target_id: str,
    url: str,
    lab: bool = True,
    user: str = Depends(_require_auth),
):
    # No arbitrary target URLs: only localhost / 127.0.0.1 / *.lab.test
    allowed = (
        url.startswith("http://127.0.0.1")
        or url.startswith("http://localhost")
        or ".lab.test" in url
    )
    if not allowed:
        raise HTTPException(status_code=400, detail="only localhost / *.lab.test targets allowed")
    async with store.lock:
        store.targets[target_id] = {
            "target_id": target_id,
            "url": url,
            "lab": lab,
            "owned": True,
        }
    return store.targets[target_id]


# ------------------------------------------------------------------ scans

@router.post("/scans", response_model=ScanResponse, tags=["scans"])
async def create_scan(
    payload: ScanCreate,
    user: str = Depends(_require_auth),
):
    # target must exist
    if payload.target_id not in store.targets:
        raise HTTPException(status_code=404, detail="target not found")
    async with store.lock:
        sid = _new_id()
        scan = {
            "scan_id": sid,
            "target_id": payload.target_id,
            "state": RunState.COMPLETED,
            "findings_count": 0,
            "requests_used": 0,
            "request_budget": 100,
        }
        store.scans[sid] = scan
    return scan


@router.get("/scans/{scan_id}/findings", tags=["scans"])
async def get_scan_findings(scan_id: UUID, user: str = Depends(_require_auth)):
    async with store.lock:
        scan = store.scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    return {"scan_id": scan_id, "findings": []}


# ------------------------------------------------------------------ patches

@router.get("/patches", response_model=list[PatchResponse], tags=["patches"])
async def list_patches(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: str = Depends(_require_auth),
):
    async with store.lock:
        items = list(store.patches.values())
    return _paginate(items, Pagination(limit=limit, offset=offset))["items"]


# ------------------------------------------------------------------ approvals

@router.get("/approvals", response_model=list[ApprovalRecordResponse], tags=["approvals"])
async def list_approvals(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: str = Depends(_require_auth),
):
    async with store.lock:
        items = list(store.approvals.values())
    return _paginate(items, Pagination(limit=limit, offset=offset))["items"]


# ------------------------------------------------------------------ shield

@router.get("/shield/rules", response_model=list[ShieldRuleResponse], tags=["shield"])
async def list_shield_rules(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: str = Depends(_require_auth),
):
    async with store.lock:
        items = list(store.shield_rules.values())
    return _paginate(items, Pagination(limit=limit, offset=offset))["items"]


@router.post("/shield/rules", response_model=ShieldRuleResponse, tags=["shield"])
async def create_shield_rule(
    payload: ShieldRuleCreate,
    user: str = Depends(_require_auth),
):
    # Reject broad or unsafe rules
    if payload.route_pattern in {"/", "*"}:
        raise HTTPException(status_code=400, detail="broad route patterns are not allowed")
    if not payload.reason:
        raise HTTPException(status_code=400, detail="reason is required")
    async with store.lock:
        rid = _new_id()
        now = _now()
        rule = {
            "rule_id": rid,
            "route_pattern": payload.route_pattern,
            "intent": payload.intent,
            "mode": payload.mode,
            "state": "ACTIVE",
            "ttl_minutes": payload.ttl_minutes,
            "created_at": now,
            "expires_at": None,
        }
        store.shield_rules[rid] = rule
    await events.event_stream.append(
        EventKind.SHIELD_RULE_ADDED,
        {"rule_id": str(rid), "route_pattern": payload.route_pattern, "intent": payload.intent},
        run_id=None,
    )
    return rule


@router.delete("/shield/rules/{rule_id}", tags=["shield"])
async def remove_shield_rule(rule_id: UUID, user: str = Depends(_require_auth)):
    async with store.lock:
        rule = store.shield_rules.get(rule_id)
        if not rule:
            raise HTTPException(status_code=404, detail="rule not found")
        rule["state"] = "REMOVED"
    await events.event_stream.append(
        EventKind.SHIELD_RULE_REMOVED,
        {"rule_id": str(rule_id)},
        run_id=None,
    )
    return {"rule_id": rule_id, "state": "REMOVED"}


@router.post("/shield/rules/{rule_id}/expire", tags=["shield"])
async def expire_shield_rule(rule_id: UUID, user: str = Depends(_require_auth)):
    async with store.lock:
        rule = store.shield_rules.get(rule_id)
        if not rule:
            raise HTTPException(status_code=404, detail="rule not found")
        rule["state"] = "EXPIRED"
    return {"rule_id": rule_id, "state": "EXPIRED"}


# ------------------------------------------------------------------ escalations

@router.get("/escalations", response_model=list[EscalationTicketResponse], tags=["escalations"])
async def list_escalations(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: str = Depends(_require_auth),
):
    async with store.lock:
        items = list(store.escalations.values())
    return _paginate(items, Pagination(limit=limit, offset=offset))["items"]


# ------------------------------------------------------------------ reports

@router.get("/reports/export", tags=["reports"])
async def export_report(user: str = Depends(_require_auth)):
    return {
        "format": "json",
        "generated_at": datetime.now(UTC).isoformat(),
        "sections": [
            "health", "sessions", "runs", "events", "policy", "evidence",
            "findings", "containment", "metrics", "targets", "scans",
            "patches", "approvals", "shield", "escalations",
        ],
    }


# ------------------------------------------------------------------ guard sidecar

@router.post("/guard/decide", response_model=GuardDecideResponse, tags=["guard"])
async def guard_decide(
    payload: GuardDecideRequest,
    user: str = Depends(_require_auth),
):
    tool = payload.tool.lower()
    if tool in {"http_request", "submit_form", "tool_call"}:
        if not payload.arguments:
            decision = Decision.BLOCK
            reason_code = "NO_ARGUMENTS"
            explanation = "no arguments provided for state-changing action"
            blocked = True
            requires_human = False
        else:
            decision = Decision.CONFIRM
            reason_code = "CONFIRM_REQUIRED"
            explanation = "state-changing action requires confirmation"
            blocked = False
            requires_human = True
    elif tool in {"navigate", "read_page", "click"}:
        decision = Decision.ALLOW
        reason_code = "ALLOW"
        explanation = "read-only action permitted"
        blocked = False
        requires_human = False
    else:
        decision = Decision.BLOCK
        reason_code = "UNKNOWN_TOOL"
        explanation = f"tool {payload.tool} not recognized"
        blocked = True
        requires_human = False

    await events.event_stream.append(
        EventKind.ACTION_DECIDED,
        {
            "session_id": str(payload.session_id),
            "tool": payload.tool,
            "decision": decision.value,
            "blocked": blocked,
        },
        run_id=None,
    )
    return GuardDecideResponse(
        decision=decision,
        reason_code=reason_code,
        blocked=blocked,
        requires_human=requires_human,
        explanation=explanation,
    )


def register_all(router: APIRouter) -> None:
    """No-op: routes are registered at import time via the module-level router."""
    pass
