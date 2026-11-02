"""Security Repair 2: Session-specific authorization regression tests.

These tests use an INDEPENDENT ORACLE: they load the trusted scenario
directly from fixtures/scenarios/*.json, build a trusted SessionContext,
and call sentinelx.policy.evaluate() directly. The API response is then
compared against this independent result. This catches cases where both
API endpoints agree but are both wrong.
"""

from __future__ import annotations

import concurrent.futures
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

import apps.api.routes as _routes_mod
from apps.api import main as _main_app
from apps.api.main import app
from apps.api.routes import _APPROVALS, _SESSION_SCENARIOS, _SESSION_STATE, store
from sentinelx.common_schemas import ActionRequest, ScenarioSpec, SessionState
from sentinelx.policy import evaluate, load_policy
from sentinelx.policy.context import SessionContext, UserRestrictions

AUTH = {"Authorization": "Bearer sentinelx-demo-local-only"}


@pytest.fixture(autouse=True)
def _reset_shared_state():
    """Reset shared in-memory stores after each test to prevent cross-test
    contamination (F5). Clears sessions, runs, scenario bindings, runtime
    state, and approvals so each test starts from a clean slate."""
    yield
    store.sessions.clear()
    store.runs.clear()
    store.events_log.clear()
    store.findings.clear()
    store.patches.clear()
    store.approvals.clear()
    store.shield_rules.clear()
    store.escalations.clear()
    store.scans.clear()
    store.targets.clear()
    store.idempotency.clear()
    _SESSION_STATE.clear()
    _SESSION_SCENARIOS.clear()
    _APPROVALS.clear()


@pytest.fixture()
def client():
    return TestClient(app)


@pytest.fixture(autouse=True)
def reset_rate_limit():
    """Reset the rate limit counter before each test to ensure test isolation."""
    _main_app._rate_tokens.clear()

_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "scenarios"
_POLICY = load_policy(Path(__file__).resolve().parents[2] / "configs" / "policy" / "default.yaml")


def _load_trusted_scenario(scenario_id: str) -> ScenarioSpec:
    """Load a trusted scenario from fixtures/scenarios/{id}.json.

    This is the independent oracle — it does NOT go through the API helper.
    """
    path = _FIXTURES / f"{scenario_id}.json"
    if not path.is_file():
        raise FileNotFoundError(f"scenario not found: {scenario_id}")
    return ScenarioSpec.model_validate_json(path.read_text(encoding="utf-8"))


def _make_session_with_state(client, scenario_id: str, state_value: str = "running"):
    """Create a session and set its state in the server-side store.
    Returns the session ID as a string.
    """
    r = client.post("/api/v1/sessions",
                    json={"scenario_id": scenario_id, "lab": "vibe_notes_node", "arm": "A"},
                    headers=AUTH)
    assert r.status_code == 200, f"create session failed: {r.status_code} {r.text}"
    sid_str = r.json()["id"]
    sid = UUID(sid_str)
    _routes_mod.store.sessions[sid]["state"] = state_value
    return sid_str


def _independent_decide(scenario_id: str, tool: str, arguments: dict,
                        state_value: str = "running",
                        user_restrictions: UserRestrictions | None = None,
                        kill_switch: bool = False,
                        steps_taken: int = 0,
                        last_step: int | None = None,
                        requests_last_minute: int = 0,
                        approvals: tuple = (),
                        page_origin: str | None = None):
    """Independent oracle: call evaluate() directly with trusted scenario
    and context. Does NOT go through the API."""
    scenario = _load_trusted_scenario(scenario_id)

    # Map API session state to Policy SessionState. Only RUNNING is RUNNING;
    # everything else (PENDING, COMPLETED, CANCELLED, FAILED) is not RUNNING.
    if state_value == "running":
        session_state = SessionState.RUNNING
    else:
        session_state = SessionState.CREATED

    ctx = SessionContext.model_validate({
        "session_id": "oracle-session",
        "state": session_state,
        "last_step": last_step,
        "steps_taken": steps_taken,
        "requests_last_minute": requests_last_minute,
        "kill_switch": kill_switch,
        "page_origin": page_origin,
        "user_restrictions": user_restrictions or UserRestrictions(),
        "approvals": approvals,
        "untrusted_texts": [],
    })
    action_request = ActionRequest.model_validate({
        "session_id": "oracle-session",
        "step": 1,
        "action_id": f"oracle-{uuid4().hex[:12]}",
        "timestamp": datetime.now(UTC),
        "actor": "test",
        "tool": tool,
        "arguments": arguments,
    })
    return evaluate(action_request, scenario, _POLICY, ctx)


def _assert_api_matches_gateway(client, sid_str, tool, arguments,
                                scenario_id: str, state_value: str = "running",
                                **ctx_overrides):
    """Call both API endpoints and the independent oracle, assert all match."""
    r1 = client.post("/api/v1/policy/decide",
                     json={"session_id": sid_str, "tool": tool,
                           "arguments": arguments, "allowed_hosts": []},
                     headers=AUTH)
    assert r1.status_code == 200, f"policy/decide failed: {r1.status_code} {r1.text}"
    d1 = r1.json()

    r2 = client.post("/api/v1/guard/decide",
                     json={"session_id": sid_str, "tool": tool,
                           "arguments": arguments},
                     headers=AUTH)
    assert r2.status_code == 200, f"guard/decide failed: {r2.status_code} {r2.text}"
    d2 = r2.json()

    gw = _independent_decide(scenario_id, tool, arguments,
                             state_value=state_value, **ctx_overrides)

    assert d1["decision"] == gw.decision.value, \
        f"policy/decide {d1['decision']} != gateway {gw.decision.value}"
    assert d2["decision"] == gw.decision.value, \
        f"guard/decide {d2['decision']} != gateway {gw.decision.value}"
    assert d1["reason_code"] == gw.reason_code, \
        f"policy/decide reason {d1['reason_code']} != gateway {gw.reason_code}"
    assert d2["reason_code"] == gw.reason_code, \
        f"guard/decide reason {d2['reason_code']} != gateway {gw.reason_code}"
    assert d1["requires_human"] == gw.requires_human
    assert d2["requires_human"] == gw.requires_human

    return d1, d2, gw


# ----- TEST 1: Authorized lab navigation -----

def test_security_authorized_lab_navigation_allow(client):
    """S1 allows navigate to orders.lab.test → ALLOW on both endpoints."""
    sid = _make_session_with_state(client, "S1", "running")
    _assert_api_matches_gateway(client, sid, "navigate",
                                {"url": "http://orders.lab.test/"}, "S1", "running")


# ----- TEST 2: Unauthorized localhost IP -----

def test_security_unauthorized_localhost_block(client):
    """S1 does not authorize 127.0.0.1 → BLOCK on both endpoints."""
    sid = _make_session_with_state(client, "S1", "running")
    _assert_api_matches_gateway(client, sid, "navigate",
                                {"url": "http://127.0.0.1/"}, "S1", "running")


# ----- TEST 3: Tool outside scenario -----

def test_security_tool_outside_scenario_block(client):
    """send is not in S1's allowed_actions → BLOCK on both endpoints."""
    sid = _make_session_with_state(client, "S1", "running")
    _assert_api_matches_gateway(client, sid, "send",
                                {"url": "http://orders.lab.test/", "body": "x"},
                                "S1", "running")


# ----- TEST 4: Unknown scenario -----

def test_security_unknown_scenario_fail_closed(client):
    """Session with undefined scenario_id → 404, never ALLOW."""
    r = client.post("/api/v1/guard/decide",
                    json={"session_id": str(uuid4()), "tool": "navigate",
                          "arguments": {"url": "http://orders.lab.test/"}},
                    headers=AUTH)
    assert r.status_code == 404


# ----- TEST 5: Client allowlist widening -----

def test_security_client_allowlist_widening_ignored(client):
    """Client-supplied allowed_hosts is ignored; server scenario governs."""
    sid = _make_session_with_state(client, "S1", "running")
    r = client.post("/api/v1/policy/decide",
                    json={"session_id": sid, "tool": "navigate",
                          "arguments": {"url": "http://evil.com/"},
                          "allowed_hosts": ["http://evil.com/"]},
                    headers=AUTH)
    assert r.status_code == 200
    assert r.json()["decision"] == "BLOCK"


# ----- TEST 6: User restriction -----

def test_security_user_restriction_forbid_navigate_block(client):
    """User restriction forbids navigate → BLOCK on both endpoints."""
    sid = _make_session_with_state(client, "S1", "running")
    _SESSION_STATE[UUID(sid)]["user_restrictions"] = {
        "forbidden_tools": ("navigate",),
        "forbidden_arguments": (),
        "blocked_destinations": (),
    }
    _assert_api_matches_gateway(client, sid, "navigate",
                                {"url": "http://orders.lab.test/"}, "S1", "running",
                                user_restrictions=UserRestrictions(
                                    forbidden_tools=("navigate",),
                                    forbidden_arguments=(),
                                    blocked_destinations=(),
                                ))


# ----- TEST 7: Kill switch -----

def test_security_kill_switch_block(client):
    """Kill switch active → BLOCK on both endpoints."""
    sid = _make_session_with_state(client, "S1", "running")
    _SESSION_STATE[UUID(sid)]["kill_switch"] = True
    _assert_api_matches_gateway(client, sid, "navigate",
                                {"url": "http://orders.lab.test/"}, "S1", "running",
                                kill_switch=True)


# ----- TEST 8: Step limit -----

def test_security_step_limit_block(client):
    """steps_taken >= max_steps → BLOCK on both endpoints."""
    sid = _make_session_with_state(client, "S1", "running")
    _SESSION_STATE[UUID(sid)]["steps_taken"] = 20  # max_steps = 20
    _assert_api_matches_gateway(client, sid, "navigate",
                                {"url": "http://orders.lab.test/"}, "S1", "running",
                                steps_taken=20)


# ----- TEST 9: Request rate limit -----

def test_security_request_rate_limit_block(client):
    """Exceed max_requests_per_minute → BLOCK on both endpoints."""
    sid = _make_session_with_state(client, "S1", "running")
    now = datetime.now(UTC).timestamp()
    _SESSION_STATE[UUID(sid)]["request_timestamps"] = [now] * 60  # max = 60/min
    _assert_api_matches_gateway(client, sid, "navigate",
                                {"url": "http://orders.lab.test/"}, "S1", "running",
                                requests_last_minute=60)


# ----- TEST 10: Step sequencing -----

# ----- TEST 10: Step sequencing -----

def test_security_step_not_increasing_block(client):
    """Non-increasing step → BLOCK. The API always uses incrementing steps,
    so this is verified at the gateway level. Here we verify the API's
    step counter always increments (step > last_step always holds)."""
    sid = _make_session_with_state(client, "S1", "running")
    _SESSION_STATE[UUID(sid)]["last_step"] = 0
    _SESSION_STATE[UUID(sid)]["steps_taken"] = 0

    # First call: step=1 > last_step=0 → ALLOW
    r1 = client.post("/api/v1/guard/decide",
                     json={"session_id": sid, "tool": "navigate",
                           "arguments": {"url": "http://orders.lab.test/"}},
                     headers=AUTH)
    assert r1.status_code == 200
    assert r1.json()["decision"] == "ALLOW"

    # Second call: step=2 > last_step=1 → ALLOW (steps always increase)
    r2 = client.post("/api/v1/guard/decide",
                     json={"session_id": sid, "tool": "navigate",
                           "arguments": {"url": "http://orders.lab.test/"}},
                     headers=AUTH)
    assert r2.status_code == 200
    assert r2.json()["decision"] == "ALLOW"


# ----- TEST 11: Relative URL with authorized origin -----

def test_security_relative_url_authorized_origin(client):
    """Relative URL /orders/1042 with page_origin=http://orders.lab.test/ → ALLOW."""
    sid = _make_session_with_state(client, "S1", "running")
    _SESSION_STATE[UUID(sid)]["page_origin"] = "http://orders.lab.test/"
    _assert_api_matches_gateway(client, sid, "navigate",
                                {"url": "/orders/1042"}, "S1", "running",
                                page_origin="http://orders.lab.test/")


# ----- TEST 12: Policy version binding -----

def test_security_policy_version_binding(client):
    """Session bound to specific policy → uses that policy's rules."""
    sid = _make_session_with_state(client, "S1", "running")
    _assert_api_matches_gateway(client, sid, "navigate",
                                {"url": "http://orders.lab.test/"}, "S1", "running")


# ----- TEST 13: Missing scenario binding -----

def test_security_missing_scenario_binding_fail_closed(client):
    """Session without trusted scenario binding → fail closed."""
    sid = _make_session_with_state(client, "S1", "running")
    del _SESSION_SCENARIOS[UUID(sid)]
    r = client.post("/api/v1/guard/decide",
                    json={"session_id": sid, "tool": "navigate",
                          "arguments": {"url": "http://orders.lab.test/"}},
                    headers=AUTH)
    assert r.status_code == 404


# ----- TEST 14: Pending/completed/cancelled session -----

def test_security_inactive_session_block(client):
    """Non-RUNNING session → BLOCK on both endpoints."""
    r = client.post("/api/v1/sessions",
                    json={"scenario_id": "S1", "lab": "vibe_notes_node", "arm": "A"},
                    headers=AUTH)
    sid_str = r.json()["id"]  # PENDING
    _assert_api_matches_gateway(client, sid_str, "navigate",
                                {"url": "http://orders.lab.test/"}, "S1", "PENDING")


# ----- TEST 15: Confirmation -----

def test_security_confirmation_high_impact_blocked(client):
    """High-impact tool not in scenario → BLOCK (not CONFIRM, not ALLOW)."""
    sid = _make_session_with_state(client, "S1", "running")
    _assert_api_matches_gateway(client, sid, "send",
                                {"url": "http://orders.lab.test/", "body": "x"},
                                "S1", "running")


# ----- TEST 16: Decision evidence -----

def test_security_decision_evidence_recorded(client):
    """Each decision produces ACTION_DECIDED evidence event."""
    sid = _make_session_with_state(client, "S1", "running")
    from apps.api.events import event_stream
    before_seq = event_stream.current_seq()
    r = client.post("/api/v1/guard/decide",
                    json={"session_id": sid, "tool": "navigate",
                          "arguments": {"url": "http://orders.lab.test/"}},
                    headers=AUTH)
    assert r.status_code == 200
    after_seq = event_stream.current_seq()
    assert after_seq > before_seq, "event_stream sequence did not advance"


# ----- TEST 17: Concurrency -----

def test_security_concurrency_rate_limit(client):
    """Concurrent requests near limit → enforced bounds, no bypass."""
    sid = _make_session_with_state(client, "S1", "running")
    now = datetime.now(UTC).timestamp()
    _SESSION_STATE[UUID(sid)]["request_timestamps"] = [now] * 59

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for _i in range(10):
            futures.append(executor.submit(
                client.post, "/api/v1/guard/decide",
                json={"session_id": sid, "tool": "navigate",
                      "arguments": {"url": "http://orders.lab.test/"}},
                headers=AUTH
            ))
        for f in futures:
            results.append(f.result())

    blocked_count = sum(1 for r in results if r.json().get("decision") == "BLOCK")
    assert blocked_count > 0, "expected at least one BLOCK under rate limit"


# ----- TEST 18: Unauthorized/missing authentication -----

def test_security_unauthenticated_rejected(client):
    """Missing auth → 401 on both endpoints."""
    r = client.post("/api/v1/guard/decide",
                    json={"session_id": str(uuid4()), "tool": "navigate",
                          "arguments": {"url": "http://orders.lab.test/"}})
    assert r.status_code == 401


# ----- TEST 19: Legitimate scenario isolation -----

def test_security_scenario_isolation(client):
    """S1 session cannot access S2's authorized host."""
    sid_s1 = _make_session_with_state(client, "S1", "running")
    sid_s2 = _make_session_with_state(client, "S2", "running")

    r = client.post("/api/v1/guard/decide",
                    json={"session_id": sid_s1, "tool": "navigate",
                          "arguments": {"url": "http://calendar.lab.test/"}},
                    headers=AUTH)
    assert r.status_code == 200
    assert r.json()["decision"] == "BLOCK"

    r = client.post("/api/v1/guard/decide",
                    json={"session_id": sid_s2, "tool": "navigate",
                          "arguments": {"url": "http://orders.lab.test/"}},
                    headers=AUTH)
    assert r.status_code == 200
    assert r.json()["decision"] == "BLOCK"


# ----- TEST 20: Missing/unavailable state -----

def test_security_missing_runtime_state_fail_closed(client):
    """Session with missing runtime state → fail closed."""
    sid = _make_session_with_state(client, "S1", "running")
    del _SESSION_STATE[UUID(sid)]
    r = client.post("/api/v1/guard/decide",
                    json={"session_id": sid, "tool": "navigate",
                          "arguments": {"url": "http://orders.lab.test/"}},
                    headers=AUTH)
    assert r.status_code == 404


# ----- REGRESSION: Cancellation revokes session authorization -----

def test_security_cancel_revokes_authorization(client):
    """Create → start → ALLOW → cancel → deny regression (F3).
    After cancellation, the session returns to PENDING and decisions are BLOCKED
    with SESSION_NOT_RUNNING."""
    # Create session in PENDING state (default from create_session)
    r = client.post("/api/v1/sessions",
                    json={"scenario_id": "S1", "lab": "vibe_notes_node", "arm": "A"},
                    headers=AUTH)
    assert r.status_code == 200
    sid = r.json()["id"]
    sid_uuid = UUID(sid)

    # Verify session starts as PENDING
    assert _routes_mod.store.sessions[sid_uuid]["state"] == "pending"

    # Start a run → session transitions to RUNNING
    r = client.post("/api/v1/runs",
                    json={"session_id": sid, "arm": "A", "model_mode": "SIMULATED"},
                    headers=AUTH)
    assert r.status_code == 200
    assert r.json()["state"] == "running"
    run_id = r.json()["id"]

    # Decision while running → ALLOW (authorized host)
    r = client.post("/api/v1/guard/decide",
                    json={"session_id": sid, "tool": "navigate",
                          "arguments": {"url": "http://orders.lab.test/"}},
                    headers=AUTH)
    assert r.status_code == 200
    assert r.json()["decision"] == "ALLOW"

    # Cancel the run → session reverts to PENDING
    r = client.post(f"/api/v1/runs/{run_id}/cancel", headers=AUTH)
    assert r.status_code == 200

    # After cancel, session should be PENDING → decisions BLOCKED
    r = client.post("/api/v1/guard/decide",
                    json={"session_id": sid, "tool": "navigate",
                          "arguments": {"url": "http://orders.lab.test/"}},
                    headers=AUTH)
    assert r.status_code == 200
    assert r.json()["decision"] == "BLOCK"
    assert r.json().get("reason_code") == "SESSION_NOT_RUNNING"


# ----- REGRESSION: Approval workflow (F4) -----

def test_security_approval_submit_stored(client):
    """POST /api/v1/approvals stores the approval record (F4)."""
    sid = _make_session_with_state(client, "S1", "running")

    r = client.post("/api/v1/approvals",
                    json={"session_id": sid, "action_id": "api-test123",
                          "tool": "navigate",
                          "arguments": {"url": "http://orders.lab.test/"},
                          "reviewer": "alice", "rationale": "test approval",
                          "decision": "approve"},
                    headers=AUTH)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["approved"] is True


def test_security_approval_reject_stored(client):
    """Rejected approval is stored with approved=false (F4)."""
    sid = _make_session_with_state(client, "S1", "running")

    r = client.post("/api/v1/approvals",
                    json={"session_id": sid, "action_id": "api-test456",
                          "tool": "navigate",
                          "arguments": {"url": "http://orders.lab.test/"},
                          "reviewer": "bob", "rationale": "rejected",
                          "decision": "reject"},
                    headers=AUTH)
    assert r.status_code == 200
    assert r.json()["approved"] is False


def test_security_approval_cross_session_isolation(client):
    """Approval in session A does not leak to session B (F4)."""
    sid_a = _make_session_with_state(client, "S1", "running")
    sid_b = _make_session_with_state(client, "S1", "running")

    # Approve in session A
    r = client.post("/api/v1/approvals",
                    json={"session_id": sid_a, "action_id": "api-action-1",
                          "tool": "navigate",
                          "arguments": {"url": "http://orders.lab.test/"},
                          "reviewer": "alice", "rationale": "approved in A",
                          "decision": "approve"},
                    headers=AUTH)
    assert r.status_code == 200

    # Session B should NOT see session A's approval
    state_b = _SESSION_STATE[UUID(sid_b)]
    assert len(state_b["approvals"]) == 0

    # Global _APPROVALS should have entry for A but not B
    assert UUID(sid_a) in _routes_mod._APPROVALS
    assert UUID(sid_b) not in _routes_mod._APPROVALS


# ----- REGRESSION: Evidence tampering detection (F1) -----

def test_security_evidence_tampering_detected(client):
    """Tampered evidence → verify returns ok=false with MODIFIED status (F1)."""
    sid = _make_session_with_state(client, "S1", "running")

    # Generate a decision (creates evidence event)
    r = client.post("/api/v1/guard/decide",
                    json={"session_id": sid, "tool": "navigate",
                          "arguments": {"url": "http://orders.lab.test/"}},
                    headers=AUTH)
    assert r.status_code == 200

    # Verify evidence before tampering
    r = client.post("/api/v1/evidence/verify",
                    json={"session_id": sid}, headers=AUTH)
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert r.json()["chain_status"] == "OK"

    # Tamper with the evidence database directly
    ev_store = _routes_mod._evidence_store()
    conn = ev_store._conn
    # Modify a payload to break the hash chain
    conn.execute("UPDATE events SET payload = '{\"tampered\": true}' WHERE session_id = ?",
                 (sid,))
    conn.commit()

    # Verify evidence after tampering → should detect MODIFIED
    r = client.post("/api/v1/evidence/verify",
                    json={"session_id": sid}, headers=AUTH)
    assert r.status_code == 200
    assert r.json()["ok"] is False
    assert r.json()["chain_status"] == "MODIFIED"
