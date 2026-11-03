"""All /api/v1 route handlers for the Sentinel X backend.

Storage is in-memory (dicts keyed by UUID). This is a local demo backend;
no persistent database is required. Each route returns strict Pydantic
schemas and is guarded by demo auth (except /health and /openapi).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlparse
from uuid import UUID, uuid4

from fastapi import (
    APIRouter,
    Cookie,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import ValidationError

from sentinelx.common_schemas import (
    ActionRequest,
    ApprovalRecord,
    EvidenceState,
    PolicyDecision,
    ScenarioSpec,
    SessionState,
    TargetAuthorization,
    TargetScope,
    TargetStatus,
)
from sentinelx.common_schemas import (
    Decision as _CommonDecision,
)
from sentinelx.evidence.db import migrate as _evidence_migrate
from sentinelx.evidence.store import EvidenceStore
from sentinelx.policy import (
    LoadedPolicy,
    SessionContext,
    evaluate,
    load_policy,
)
from sentinelx.policy.engine import approval_subject_id
from sentinelx.policy.redaction import redact
from sentinelx.scanner.models import load_profile as _load_scan_profile
from sentinelx.scanner.orchestrate import run_scan

from . import events
from .auth import (
    _SSE_TTL_SECONDS,
    DEMO_TOKEN,
    _bearer,
    _sign_sse_session,
    _verify_sse_session,
    require_demo_auth,
)
from .events import event_stream, sse_response
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
    LabelMode,
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
    TargetCreate,
    TargetResponse,
)

router = APIRouter()

# ------------------------------------------------------------------ policy gateway
# Load the default policy once at startup. It is immutable (frozen models), so a
# single load is safe for the life of the process. Every API policy decision is
# routed through ``sentinelx.policy.evaluate`` — the API never grants
# authorization independently of the gateway.
_POLICY_PATH = Path(__file__).resolve().parents[2] / "configs" / "policy" / "default.yaml"
_POLICY: LoadedPolicy = load_policy(_POLICY_PATH)

# Persistent evidence store for decisions. Hash-chained and redacted on write.
# The connection is created per-request (see _evidence_store()) because SQLite
# connections cannot be shared across threads, and the test client runs each
# request in a different thread.
_EVIDENCE_DB_PATH = Path(__file__).resolve().parents[2] / "evaluations" / "final" / "evidence.db"
_EVIDENCE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def _evidence_store() -> EvidenceStore:
    """Open a fresh EvidenceStore connection for the current request.

    SQLite connections cannot cross threads; each request runs in its own
    thread under the test client, so we create a new connection per call.
    Migrations are applied to ensure the schema exists. Foreign keys are
    intentionally not enabled: the API manages session integrity through its
    own in-memory store, and the evidence store's integrity comes from its
    hash chain, not from FK constraints.
    """
    conn = sqlite3.connect(str(_EVIDENCE_DB_PATH), isolation_level=None, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    _evidence_migrate(conn)
    return EvidenceStore(conn)


# Trusted scenario definitions loaded from fixtures/scenarios/*.json at startup.
# These are immutable and content-addressed; the API never fabricates a scenario
# from client input. A session is bound to exactly one scenario at creation time.
_SCENARIOS: dict[str, ScenarioSpec] = {}


def _load_scenarios() -> dict[str, ScenarioSpec]:
    """Load all trusted scenario definitions from fixtures/scenarios/*.json.

    Raises at import time if any scenario file is invalid, so a corrupted or
    missing scenario definition never silently degrades into a fabricated one.
    """
    scenarios: dict[str, ScenarioSpec] = {}
    fixtures_dir = Path(__file__).resolve().parents[2] / "fixtures" / "scenarios"
    if not fixtures_dir.is_dir():
        raise RuntimeError(f"scenarios directory not found: {fixtures_dir}")
    for path in sorted(fixtures_dir.glob("*.json")):
        spec = ScenarioSpec.model_validate_json(path.read_text(encoding="utf-8"))
        scenarios[spec.id] = spec
    return scenarios


_SCENARIOS = _load_scenarios()

# Per-session trusted scenario binding. Populated at session creation time and
# never rewritten. Used by _session_scenario() to look up the exact authorized
# hosts/actions for the session's scenario.
_SESSION_SCENARIOS: dict[UUID, ScenarioSpec] = {}

# Per-session runtime state tracking (step counters, rate-limit windows,
# kill-switch, user restrictions, approvals). Populated at session creation
# and updated on each decision. Never derived from client input.
_SESSION_STATE: dict[UUID, dict[str, Any]] = {}

# Scan cancellation events - one per active scan. Set by the cancel endpoint
# to request scan termination. Checked by run_scan() via the cancel_event parameter.
_SCAN_CANCEL_EVENTS: dict[UUID, threading.Event] = {}

# Target lab name mapping - internal metadata not exposed in public responses.
# Maps target_id -> lab directory name for scan execution.
_TARGET_LABS: dict[str, str] = {}

# Scan lab name mapping - internal metadata not exposed in public responses.
# Maps scan_id -> lab directory name for scan execution.
_SCAN_LABS: dict[UUID, str] = {}

# Scan internal metadata - not exposed in public ScanResponse schema.
# Maps scan_id -> dict of internal fields (target_url, stop_reason, duration_ms, error).
_SCAN_META: dict[UUID, dict[str, Any]] = {}


def _session_scenario(session: dict[str, Any]) -> ScenarioSpec:
    """Return the trusted scenario bound to this session at creation time.

    The scenario_id stored on the session is only a reference; the actual
    authorized hosts/actions come from the immutable registry lookup. If the
    session has no bound scenario (legacy or malformed), fail closed.
    """
    sid = session["id"]
    spec = _SESSION_SCENARIOS.get(sid)
    if spec is None:
        raise HTTPException(
            status_code=404,
            detail="session has no trusted scenario binding",
        )
    return spec


def _session_context(session: dict[str, Any]) -> SessionContext:
    """Build a server-owned :class:`SessionContext` from session data.

    All fields come from the server-side per-session state, never from the
    client request. The API ``RunState`` enum uses lowercase values while the
    policy ``SessionState`` enum uses uppercase values, so we normalize here.
    Step counters, rate-limit windows, kill-switch state, user restrictions,
    and approvals are tracked per-session and updated on each decision.
    """
    sid = session["id"]
    state = _SESSION_STATE.get(sid)
    if state is None:
        raise HTTPException(
            status_code=404,
            detail="session has no runtime state",
        )

    state_val = session.get("state", "PENDING")
    if hasattr(state_val, "value"):
        state_str = state_val.value
    else:
        state_str = str(state_val)
    try:
        session_state = SessionState(state_str.upper())
    except ValueError:
        session_state = SessionState.CREATED

    # Prune request timestamps older than one minute.
    now_ts = datetime.now(UTC)
    window_start = now_ts.timestamp() - 60.0
    timestamps = [
        t for t in state["request_timestamps"] if t > window_start
    ]
    state["request_timestamps"] = timestamps

    # Convert stored approval records to ApprovalRecord objects for the
    # SessionContext (extra="forbid" requires exact schema match).
    # Never silently skip malformed records: a skipped rejection would leave
    # a prior approval active, which is a security bypass.
    approval_records = []
    for rec in state.get("approvals", []):
        approval_records.append(ApprovalRecord.model_validate(rec))

    return SessionContext.model_validate(
        {
            "session_id": str(session["id"]),
            "state": session_state,
            "last_step": state["last_step"],
            "steps_taken": state["steps_taken"],
            "requests_last_minute": len(timestamps),
            "kill_switch": state["kill_switch"],
            "page_origin": state["page_origin"],
            "user_restrictions": state["user_restrictions"],
            "approvals": tuple(approval_records),
            "untrusted_texts": [],
        }
    )


async def _gateway_decide(
    session_id: UUID, tool: str, arguments: dict[str, Any]
) -> PolicyDecision:
    """Route a single action decision through the real policy gateway.

    Validates that the session exists in the server-side store, builds a
    server-owned scenario and session context from the trusted per-session
    state, calls ``sentinelx.policy.evaluate``, records the decision as an
    ACTION_DECIDED evidence event (persisted to the evidence store and
    broadcast on the SSE stream, both with redacted payloads), and updates
    per-session step/rate-limit counters. Raises HTTP 404 when the session
    does not exist. Never returns ALLOW for a nonexistent or invalid session.

    All state reads and writes are performed under the per-session lock to
    prevent concurrent requests from observing stale counters and bypassing
    rate limits or step limits.
    """
    session = store.sessions.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="session not found")

    scenario = _session_scenario(session)

    state = _SESSION_STATE.get(session_id)
    if state is None:
        raise HTTPException(status_code=404, detail="session has no runtime state")
    with state["lock"]:
        # Re-read state under the lock (another task may have updated it).
        ctx = _session_context(session)

        # Step number is strictly increasing per session.
        next_step = (state["last_step"] or 0) + 1

        # Arguments used for policy evaluation are the raw values (so secret
        # detection works). Arguments stored in evidence are redacted.
        redacted_args = redact(arguments).value

        # Deterministic action_id derived from tool+arguments so that retries
        # with the same inputs produce the same action_id. This enables the
        # approval workflow: a CONFIRM decision can be approved via POST
        # /api/v1/approvals, and a subsequent retry with the same action_id
        # + arguments will be allowed by the gateway (which checks
        # SessionContext.approvals).
        canonical = json.dumps({"tool": tool, "arguments": arguments},
                               sort_keys=True)
        action_id = f"api-{hashlib.sha256(canonical.encode()).hexdigest()[:12]}"

        action_request = ActionRequest.model_validate(
            {
                "session_id": str(session_id),
                "step": next_step,
                "action_id": action_id,
                "timestamp": datetime.now(UTC),
                "actor": "api",
                "tool": tool,
                "arguments": arguments,
            }
        )

        decision = evaluate(action_request, scenario, _POLICY, ctx)

        # Update per-session runtime state after the decision is recorded.
        state["steps_taken"] = state["steps_taken"] + 1
        state["last_step"] = next_step
        state["request_timestamps"].append(datetime.now(UTC).timestamp())

    # Persist the decision durably BEFORE broadcasting on SSE.
    # If persistence fails, the client never sees an ALLOW that wasn't recorded.
    redacted_tool = redact(tool).value
    ev_payload = {
        "session_id": str(session_id),
        "action_id": action_request.action_id,
        "tool": redacted_tool,
        "decision": decision.decision.value,
        "reason_code": decision.reason_code,
        "rule_ids": decision.rule_ids,
        "requires_human": decision.requires_human,
        "policy_version": decision.policy_version,
        "scenario_id": session["scenario_id"],
        "arguments": redacted_args,
    }
    ev_store = _evidence_store()
    ev_store.append(
        str(session_id),
        "ACTION_DECIDED",
        EvidenceState.OBSERVED,
        "policy_gateway",
        ev_payload,
    )
    # Also mirror into the in-memory events log so the /events list endpoint
    # (and the evidence timeline UI) can surface persisted decisions.
    # Use a proper UUID for the event id; keep action_request.action_id in the
    # payload for cross-referencing with the decision that produced it.
    async with store.lock:
        store.events_log.append(
            {
                "id": str(uuid4()),
                "seq": state["last_step"],
                "run_id": None,
                "kind": EventKind.ACTION_DECIDED,
                "payload": ev_payload,
                "timestamp": datetime.now(UTC),
            }
        )
    await event_stream.append(
        EventKind.ACTION_DECIDED,
        ev_payload,
        run_id=None,
    )

    return decision


# Map gateway decisions to the API's Decision enum (same StrEnum values).
def _api_decision(gw_decision: _CommonDecision) -> Decision:
    return Decision(gw_decision.value)


# ------------------------------------------------------------------ approvals
# Per-session approval records. Maps (action_id, tool, arguments) → ApprovalRecord.
# Populated when a human approves a CONFIRM decision via POST /api/v1/approvals.
# _gateway_decide checks this store to allow retries of previously approved actions.
_APPROVALS: dict[UUID, dict[tuple[str, str], dict[str, Any]]] = {}


def _approval_key(tool: str, arguments: dict[str, Any]) -> tuple[str, str]:
    """Deterministic key for an action+arguments pair."""
    import json
    canonical = json.dumps({"tool": tool, "arguments": arguments}, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False)
    return (tool, canonical)


def _record_approval(session_id: UUID, action_id: str, tool: str,
                     arguments: dict[str, Any], reviewer: str, rationale: str,
                     approved: bool = True) -> None:
    """Record an approval for an action+arguments pair."""
    key = _approval_key(tool, arguments)
    if session_id not in _APPROVALS:
        _APPROVALS[session_id] = {}
    subject = approval_subject_id(action_id, tool, arguments)
    _APPROVALS[session_id][key] = {
        "id": f"appr-{uuid4().hex[:12]}",
        "subject_type": "action",
        "subject_id": subject,
        "reviewer": reviewer,
        "decision": "approve" if approved else "reject",
        "rationale": rationale,
        "timestamp": datetime.now(UTC),
    }
    # Also store in per-session state for SessionContext (as list of dicts)
    # that get converted to ApprovalRecord objects.



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
    # Validate the scenario_id against the trusted registry before creating
    # the session. Unknown scenarios fail closed — we never fabricate a
    # scenario from client input.
    spec = _SCENARIOS.get(payload.scenario_id)
    if spec is None:
        raise HTTPException(
            status_code=404,
            detail=f"unknown scenario: {payload.scenario_id}",
        )
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
        # Bind the trusted scenario to this session. Authorized hosts/actions
        # come only from this immutable spec. Deep-copy so that later
        # mutations to the registry cannot alter existing session authorization.
        _SESSION_SCENARIOS[sid] = spec.model_copy(deep=True)
        # Initialize per-session runtime state for the gateway context.
        _SESSION_STATE[sid] = {
            "steps_taken": 0,
            "last_step": None,
            "request_timestamps": [],  # timestamps of requests in the last minute
            "kill_switch": False,
            "user_restrictions": {
                "forbidden_tools": (),
                "forbidden_arguments": (),
                "blocked_destinations": (),
            },
            "approvals": [],  # list of ApprovalRecord-compatible dicts
            "page_origin": None,
            "lock": threading.Lock(),  # per-session lock for concurrency safety
        }
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
    sid = payload.session_id
    async with store.lock:
        if sid not in store.sessions:
            raise HTTPException(status_code=404, detail="session not found")
        session = store.sessions[sid]
        if session["state"] != RunState.PENDING:
            raise HTTPException(
                status_code=400,
                detail=f"session is in {session['state']} state, cannot start run",
            )
        rid = _new_id()
        now = _now()
        run = {
            "id": rid,
            "session_id": sid,
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
        # Transition session to RUNNING state
        session["state"] = RunState.RUNNING
        state = _SESSION_STATE.get(sid)
        if state is not None:
            state["steps_taken"] = 0
            state["last_step"] = None
            state["request_timestamps"] = []
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
        # Revoke session authorization: transition session back to PENDING
        # so that subsequent policy decisions return SESSION_NOT_RUNNING.
        sid = r["session_id"]
        session = store.sessions.get(sid)
        if session is not None:
            session["state"] = RunState.PENDING
            session["updated_at"] = _now()
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


@router.post("/events/session", tags=["events"])
async def create_sse_session(
    response: Response,
    user: str = Depends(_require_auth),
):
    """Create an SSE session. Sets an HttpOnly cookie that the SSE stream
    endpoint reads for authentication, avoiding query-param tokens that
    would appear in server access logs."""
    sid = secrets.token_hex(16)
    token = _sign_sse_session(sid)
    response.set_cookie(
        key="sse_token",
        value=token,
        httponly=True,
        secure=False,  # local dev only; set True behind HTTPS
        samesite="lax",
        path="/api/v1/events/stream",
        max_age=_SSE_TTL_SECONDS,
    )
    return {"status": "ok"}


@router.get("/events/stream", tags=["events"])
async def stream_events(
    request: Request,
    sse_token: str | None = Cookie(default=None),
    last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None,
):
    # Auth: bearer header takes precedence; SSE session cookie is used by
    # EventSource (which cannot set custom headers). Avoids query-param
    # tokens that would appear in access logs.
    authenticated = False
    if creds is not None and creds.credentials:
        if secrets.compare_digest(creds.credentials, DEMO_TOKEN):
            authenticated = True
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
    if not authenticated and sse_token is not None:
        if _verify_sse_session(sse_token):
            authenticated = True
    if not authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
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
    # Route through the real deterministic policy gateway. Client-supplied
    # ``allowed_hosts`` is intentionally ignored — only server-owned scenario
    # data is used. A nonexistent session cannot receive ALLOW.
    gw = await _gateway_decide(payload.session_id, payload.tool, payload.arguments)
    return PolicyDecisionResponse(
        decision=_api_decision(gw.decision),
        reason_code=gw.reason_code,
        rule_ids=gw.rule_ids,
        requires_human=gw.requires_human,
        explanation=gw.explanation,
        action_id=gw.action_id,
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
    sid_str = str(sid)
    ev_store = _evidence_store()
    chain = ev_store.verify_chain(sid_str)
    return {
        "session_id": sid_str,
        "events_checked": chain.events_checked,
        "ok": chain.ok,
        "first_broken_event_id": chain.first_broken_event_id,
        "first_broken_seq": chain.first_broken_seq,
        "detail": chain.detail,
        "chain_status": chain.status.value,
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
    payload: TargetCreate,
    user: str = Depends(_require_auth),
):
    # No arbitrary target URLs: only http://localhost or http://127.0.0.1 / *.lab.test
    url = payload.url
    parsed = urlparse(url)
    if parsed.scheme != "http":
        raise HTTPException(status_code=400, detail="only http:// URLs are allowed")
    url_host = parsed.hostname or ""
    allowed = (
        url_host == "127.0.0.1"
        or url_host == "localhost"
        or url_host.endswith(".lab.test")
    )
    if not allowed:
        raise HTTPException(status_code=400, detail="only localhost / *.lab.test targets allowed")
    async with store.lock:
        store.targets[payload.target_id] = {
            "target_id": payload.target_id,
            "url": url,
            "lab": payload.lab,
            "owned": False,  # ownership not verified by registration alone
        }
    if payload.lab:
        _TARGET_LABS[payload.target_id] = "vibe_notes_node"
    return store.targets[payload.target_id]


# ------------------------------------------------------------------ scans

@router.post("/scans", response_model=ScanResponse, tags=["scans"])
async def create_scan(
    payload: ScanCreate,
    user: str = Depends(_require_auth),
):
    # target must exist
    if payload.target_id not in store.targets:
        raise HTTPException(status_code=404, detail="target not found")

    target_entry = store.targets[payload.target_id]

    # Only lab targets can be scanned through this API.
    # Non-lab targets require ownership verification (not yet supported).
    if not target_entry.get("lab"):
        raise HTTPException(
            status_code=403,
            detail="non-lab targets require ownership verification",
        )

    lab_name = _TARGET_LABS.get(payload.target_id)
    if not lab_name:
        raise HTTPException(
            status_code=400,
            detail="target has no associated lab",
        )

    async with store.lock:
        sid = _new_id()
        cancel_event = threading.Event()
        _SCAN_CANCEL_EVENTS[sid] = cancel_event
        _SCAN_LABS[sid] = lab_name
        _SCAN_META[sid] = {"target_url": target_entry["url"]}
        store.scans[sid] = {
            "scan_id": sid,
            "target_id": payload.target_id,
            "state": RunState.PENDING,
            "findings_count": 0,
            "requests_used": 0,
            "request_budget": 100,
            "note": "Scan queued",
        }

    # Start scan execution in the background. Returns immediately with PENDING
    # state; the background task updates state when the scan completes/fails.
    asyncio.create_task(_run_scan_background(sid, target_entry, cancel_event))

    return store.scans[sid]


async def _run_scan_background(
    scan_id: UUID,
    target_entry: dict[str, Any],
    cancel_event: threading.Event,
) -> None:
    """Run a scan in the background and update the scan record with results.
    Any exception is caught and recorded as a FAILED state."""
    lab_name = _SCAN_LABS.get(scan_id)
    if not lab_name:
        async with store.lock:
            scan = store.scans.get(scan_id)
            if scan is not None:
                scan["state"] = RunState.FAILED
                scan["error"] = "no lab associated with scan"
        _SCAN_CANCEL_EVENTS.pop(scan_id, None)
        return

    try:
        result = await asyncio.to_thread(
            _execute_scan, scan_id, target_entry, lab_name, cancel_event
        )
    except Exception as exc:
        async with store.lock:
            scan = store.scans.get(scan_id)
            if scan is not None:
                scan["state"] = RunState.FAILED
            _SCAN_META[scan_id] = {"error": str(exc)[:300]}
        _SCAN_CANCEL_EVENTS.pop(scan_id, None)
        return

    # Update scan record with results
    async with store.lock:
        scan = store.scans.get(scan_id)
        if scan is None:
            _SCAN_CANCEL_EVENTS.pop(scan_id, None)
            _SCAN_LABS.pop(scan_id, None)
            _SCAN_META.pop(scan_id, None)
            return

        stop_reason = result.stop_reason.lower()
        if stop_reason == "completed":
            scan["state"] = RunState.COMPLETED
        elif stop_reason == "cancelled":
            scan["state"] = RunState.CANCELLED
        else:
            scan["state"] = RunState.FAILED

        scan["findings_count"] = len(result.findings)
        scan["requests_used"] = result.requests_used

        # Store internal metadata separately (not in ScanResponse schema)
        _SCAN_META[scan_id].update({
            "stop_reason": result.stop_reason,
            "duration_ms": result.duration_ms,
        })

        # Persist findings associated with this scan
        for finding in result.findings:
            fid = _new_id()
            store.findings[fid] = {
                "id": fid,
                "session_id": result.session_id,
                "target_id": target_entry["target_id"],
                "scan_id": scan_id,
                "state": finding.verification.state,
                "severity": finding.candidate.severity.value,
                "summary": finding.candidate.summary,
                "mode": LabelMode.SIMULATED,
                "model_provider": None,
                "model_name": None,
                "created_at": datetime.now(UTC),
            }

    _SCAN_CANCEL_EVENTS.pop(scan_id, None)


def _execute_scan(
    scan_id: UUID,
    target_entry: dict[str, Any],
    lab_name: str,
    cancel_event: threading.Event,
) -> Any:
    """Run a scan in a worker thread. Creates its own SQLite connection
    (connections cannot cross threads)."""

    # Build TargetAuthorization from the stored target entry
    parsed = urlparse(target_entry["url"])
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 80

    target = TargetAuthorization(
        target_id=target_entry["target_id"],
        base_url=target_entry["url"],
        scope=TargetScope(
            schemes=["http"],
            hosts=[host],
            ports=[port],
        ),
        lab=True,
        ownership_method="lab_registration",
        verification_token_hash="",
        verified_at=None,
        status=TargetStatus.VERIFIED,
    )

    # Load scan profile
    profile = _load_scan_profile()

    # Create a fresh SQLite connection for this scan (cannot cross threads)
    db_path = Path(__file__).resolve().parents[2] / "evaluations" / "final" / "evidence.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), isolation_level=None, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    _evidence_migrate(conn)

    try:
        labs_root = Path(__file__).resolve().parents[2] / "labs"
        result = run_scan(
            target=target,
            profile=profile,
            labs_root=labs_root,
            lab_name=lab_name,
            conn=conn,
            cancel_event=cancel_event,
        )
        return result
    finally:
        conn.close()


@router.post("/scans/{scan_id}/cancel", tags=["scans"])
async def cancel_scan(
    scan_id: UUID,
    user: str = Depends(_require_auth),
):
    """Request cancellation of a running scan. Sets the cancel event that
    run_scan() checks between checks. The scan stops at the next check
    boundary and leaves honest evidence of what was completed."""
    async with store.lock:
        scan = store.scans.get(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="scan not found")
        if scan["state"] not in (RunState.PENDING, RunState.RUNNING):
            raise HTTPException(
                status_code=400,
                detail=f"scan is in {scan['state']} state, cannot cancel",
            )
        cancel_event = _SCAN_CANCEL_EVENTS.get(scan_id)
        if cancel_event is not None:
            cancel_event.set()
        scan["state"] = RunState.CANCELLED

    return {"scan_id": scan_id, "state": RunState.CANCELLED}


@router.get("/scans/{scan_id}/findings", response_model=list[FindingResponse], tags=["scans"])
async def get_scan_findings(
    scan_id: UUID,
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: str = Depends(_require_auth),
):
    """Return findings for a given scan.

    Unknown scan IDs return 404. Known scans in PENDING state have no
    findings yet (scan execution not yet integrated); completed scans
    return their actual findings.
    """
    async with store.lock:
        scan = store.scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")

    # Unknown scan: 404 (raised above). Known pending scan: honest empty response.
    # Completed scan: return findings associated with THIS scan only.
    if scan["state"] != RunState.COMPLETED:
        return []

    async with store.lock:
        items = [f for f in store.findings.values() if f.get("scan_id") == scan_id]
    return _paginate(items, Pagination(limit=limit, offset=offset))["items"]


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


@router.post("/approvals", response_model=dict, tags=["approvals"])
async def submit_approval(
    body: dict,
    user: str = Depends(_require_auth),
):
    """Record a human approval/rejection/revocation for an action.

    Body fields: session_id, action_id, tool, arguments, reviewer, rationale,
    decision (approve|reject|revoke). Stores the approval in both the per-session
    _SESSION_STATE (checked by _gateway_decide) and the global _APPROVALS store.
    """
    session_id_raw = body.get("session_id")
    action_id = body.get("action_id")
    tool = body.get("tool")
    arguments = body.get("arguments", {})
    reviewer = body.get("reviewer", "api")
    rationale = body.get("rationale", "")
    decision = body.get("decision", "approve")

    if not session_id_raw or not action_id or not tool:
        raise HTTPException(status_code=400, detail="session_id, action_id, and tool are required")

    try:
        sid = UUID(str(session_id_raw))
    except (ValueError, AttributeError):
        raise HTTPException(status_code=400, detail="invalid session_id") from None

    session = store.sessions.get(sid)
    if session is None:
        raise HTTPException(status_code=404, detail="session not found")

    state = _SESSION_STATE.get(sid)
    if state is None:
        raise HTTPException(status_code=404, detail="session has no runtime state")

    approved = decision == "approve"
    record = {
        "id": f"appr-{uuid4().hex[:12]}",
        "subject_type": "action",
        "subject_id": approval_subject_id(action_id, tool, arguments),
        "reviewer": reviewer,
        "decision": "approve" if approved else "reject",
        "rationale": rationale,
        "timestamp": datetime.now(UTC),
    }

    # Validate the approval record before storing it.
    # Never silently store malformed approvals — a rejected/revoked record
    # must be enforceable, not silently discarded.
    # Never echo the raw ValidationError in the response: it may reflect
    # caller-supplied secrets back to the client.
    try:
        ApprovalRecord.model_validate(record)
    except ValidationError:
        raise HTTPException(
            status_code=400, detail="invalid approval record"
        ) from None

    with state["lock"]:
        state["approvals"].append(record)

    _record_approval(sid, action_id, tool, arguments, reviewer, rationale,
                     approved=approved)

    return {"status": "ok", "action_id": action_id, "approved": approved, "record_id": str(sid)}


# ------------------------------------------------------------------ shield

@router.get("/shield/rules", response_model=list[ShieldRuleResponse], tags=["shield"])
async def list_shield_rules(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: str = Depends(_require_auth),
):
    async with store.lock:
        items = list(store.shield_rules.values())
    # Explicitly serialize each rule to ShieldRuleResponse so internal
    # store fields (updated_at, approved_by, etc.) never leak into the
    # public response and trigger a schema-validation 500.
    page = _paginate(items, Pagination(limit=limit, offset=offset))["items"]
    return [
        ShieldRuleResponse(
            rule_id=rule["rule_id"],
            route_pattern=rule["route_pattern"],
            intent=rule["intent"],
            mode=rule["mode"],
            state=rule["state"],
            ttl_minutes=rule["ttl_minutes"],
            created_at=rule["created_at"],
            expires_at=rule.get("expires_at"),
            note=rule.get("note"),
        )
        for rule in page
    ]


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
        from datetime import timedelta
        expires_at = now + timedelta(minutes=payload.ttl_minutes)
        rule = {
            "rule_id": rid,
            "route_pattern": payload.route_pattern,
            "intent": payload.intent,
            "mode": payload.mode,
            "state": "PROPOSED",  # not ACTIVE until benign-replay gate passes
            "ttl_minutes": payload.ttl_minutes,
            "created_at": now,
            "expires_at": expires_at,
            "note": "Shield activation not yet integrated; rule remains PROPOSED",
        }
        store.shield_rules[rid] = rule
    await events.event_stream.append(
        EventKind.SHIELD_RULE_ADDED,
        {
            "rule_id": str(rid),
            "route_pattern": payload.route_pattern,
            "intent": payload.intent,
            "state": "PROPOSED",
        },
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


@router.post("/shield/rules/{rule_id}/approve", response_model=ShieldRuleResponse, tags=["shield"])
async def approve_shield_rule(
    rule_id: UUID,
    body: dict,
    user: str = Depends(_require_auth),
):
    """Record a human approval for a shield rule and activate it.

    Shield activation is not yet integrated. This endpoint intentionally
    fails closed: every approval request is rejected with 400 and the rule
    remains PROPOSED. No ACTIVE state, no ACTIVE events, no proxy
    activation, and no success metadata are ever produced until genuine
    activation (scoped approval, benign-replay gate, proxy runtime, durable
    evidence) is implemented.
    """
    action_id = body.get("action_id")
    tool = body.get("tool", "shield_rule")
    decision = body.get("decision", "approve")

    if not action_id or not tool:
        raise HTTPException(status_code=400, detail="action_id and tool are required")
    if decision != "approve":
        raise HTTPException(status_code=400, detail="only 'approve' decisions are accepted")
    if action_id != str(rule_id):
        raise HTTPException(status_code=400, detail="action_id must match rule_id")

    # Fail closed: shield activation is not yet integrated. Reject every
    # approval request regardless of stored approvals, session, tool,
    # arguments, or revocation state. The rule remains PROPOSED.
    raise HTTPException(
        status_code=400,
        detail="shield activation not yet integrated; rule remains PROPOSED",
    )


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
    # Route through the real deterministic policy gateway. The gateway is the
    # ONLY authority for allow/block/confirm — the API never grants
    # authorization independently. A nonexistent session cannot receive ALLOW,
    # and external navigation to a forbidden host returns BLOCK.
    gw = await _gateway_decide(payload.session_id, payload.tool, payload.arguments)
    blocked = gw.decision is _CommonDecision.BLOCK
    return GuardDecideResponse(
        decision=_api_decision(gw.decision),
        reason_code=gw.reason_code,
        blocked=blocked,
        requires_human=gw.requires_human,
        explanation=gw.explanation,
    )


def register_all(router: APIRouter) -> None:
    """No-op: routes are registered at import time via the module-level router."""
    pass
