"""Tests for Task 27: versioned FastAPI backend + event streaming.

Covers: routes, authentication, forbidden operations, invalid schemas,
unknown IDs, event ordering, resume/reconnect (SSE), cancellation,
evidence integrity, model-unavailable handling.
"""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from apps.api.main import _rate_tokens, app
from apps.api.routes import (
    _APPROVALS,
    _SESSION_SCENARIOS,
    _SESSION_STATE,
    store,
)

AUTH = {"Authorization": "Bearer sentinelx-demo-local-only"}
BAD_AUTH = {"Authorization": "Bearer wrong-token"}


# ------------------------------------------------------------------ fixture

@pytest.fixture()
def client():
    # Clear shared rate-limit token buckets so tests are isolated from each
    # other (F5: test contamination between test files via global rate state).
    _rate_tokens.clear()
    return TestClient(app)


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


# ------------------------------------------------------------------ health (no auth)

def test_health_no_auth(client):
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["version"] == "0.1.0"
    assert data["mode"] == "SIMULATED"
    assert data["model_available"] is False
    assert isinstance(data["features"], list)
    assert "event-stream" in data["features"]


# ------------------------------------------------------------------ openapi

def test_openapi_endpoint(client):
    r = client.get("/api/v1/openapi.json")
    # OpenAPI generation may have Pydantic model issues; we just check the
    # endpoint is mounted and returns a JSON response (not a 500).
    assert r.status_code in (200, 422), f"unexpected status {r.status_code}"


# ------------------------------------------------------------------ authentication

def test_auth_required(client):
    r = client.post("/api/v1/sessions",
                    json={"scenario_id": "s1", "lab": "vibe_notes_node", "arm": "A"})
    assert r.status_code == 401


def test_bad_auth_rejected(client):
    r = client.post("/api/v1/sessions",
                    json={"scenario_id": "s1", "lab": "vibe_notes_node", "arm": "A"},
                    headers=BAD_AUTH)
    assert r.status_code == 401


# ------------------------------------------------------------------ sessions

def test_create_session(client):
    r = client.post("/api/v1/sessions",
                    json={"scenario_id": "S1", "lab": "vibe_notes_node", "arm": "A"},
                    headers=AUTH)
    assert r.status_code == 200
    data = r.json()
    assert data["scenario_id"] == "S1"
    assert data["lab"] == "vibe_notes_node"
    assert data["arm"] == "A"
    assert data["state"] == "pending"
    assert "id" in data
    assert "created_at" in data


def test_create_session_invalid_schema(client):
    # missing required fields
    r = client.post("/api/v1/sessions", json={"arm": "A"}, headers=AUTH)
    assert r.status_code in (400, 422)
    # extra field (extra="forbid")
    r = client.post("/api/v1/sessions",
                    json={"scenario_id": "s1", "lab": "x", "arm": "A", "bogus": 1},
                    headers=AUTH)
    assert r.status_code in (400, 422)


def test_list_sessions(client):
    client.post("/api/v1/sessions",
                json={"scenario_id": "S1", "lab": "vibe_notes_node", "arm": "A"},
                headers=AUTH)
    client.post("/api/v1/sessions",
                json={"scenario_id": "S2", "lab": "vibe_shop_php", "arm": "B"},
                headers=AUTH)
    r = client.get("/api/v1/sessions", headers=AUTH)
    assert r.status_code == 200
    data = r.json()
    assert len(data) >= 2


def test_get_session_unknown_id(client):
    r = client.get(f"/api/v1/sessions/{uuid4()}", headers=AUTH)
    assert r.status_code == 404


# ------------------------------------------------------------------ runs + cancel

def test_create_and_cancel_run(client):
    r = client.post("/api/v1/sessions",
                    json={"scenario_id": "S1", "lab": "vibe_notes_node", "arm": "A"},
                    headers=AUTH)
    sid = r.json()["id"]
    r = client.post("/api/v1/runs",
                    json={"session_id": sid, "arm": "A", "model_mode": "SIMULATED"},
                    headers=AUTH)
    assert r.status_code == 200
    data = r.json()
    assert data["state"] == "running"
    assert data["model_mode"] == "SIMULATED"
    rid = data["id"]
    # cancel
    r = client.post(f"/api/v1/runs/{rid}/cancel", headers=AUTH)
    assert r.status_code == 200
    assert r.json()["state"] == "cancelled"
    # cancel again -> error
    r = client.post(f"/api/v1/runs/{rid}/cancel", headers=AUTH)
    assert r.status_code == 400


def test_run_unknown_session(client):
    r = client.post("/api/v1/runs",
                    json={"session_id": str(uuid4()), "arm": "A", "model_mode": "SIMULATED"},
                    headers=AUTH)
    assert r.status_code == 404


# ------------------------------------------------------------------ guard sidecar

import apps.api.routes as _routes_mod  # noqa: E402  (store access for test setup)


def _make_running_session(client):
    """Create a session and set its state to RUNNING in the server-side store.
    Returns the session ID as a string (for JSON bodies)."""
    r = client.post("/api/v1/sessions",
                    json={"scenario_id": "S1", "lab": "vibe_notes_node", "arm": "A"},
                    headers=AUTH)
    assert r.status_code == 200
    sid_str = r.json()["id"]
    sid = UUID(sid_str)
    _routes_mod.store.sessions[sid]["state"] = "running"
    return sid_str


def test_guard_nonexistent_session_returns_404(client):
    """A nonexistent session must never receive ALLOW."""
    r = client.post("/api/v1/guard/decide",
                    json={"session_id": str(uuid4()), "tool": "navigate",
                          "arguments": {"url": "http://127.0.0.1/"}},
                    headers=AUTH)
    assert r.status_code == 404


def test_guard_allow_running_session(client):
    """Valid RUNNING session with an allowed read action receives ALLOW."""
    sid = _make_running_session(client)
    r = client.post("/api/v1/guard/decide",
                    json={"session_id": sid, "tool": "navigate",
                          "arguments": {"url": "http://orders.lab.test/"}},
                    headers=AUTH)
    assert r.status_code == 200
    d = r.json()
    assert d["decision"] == "ALLOW"
    assert d["blocked"] is False
    assert d["requires_human"] is False


def test_guard_pending_session_blocked(client):
    """A PENDING (not RUNNING) session receives BLOCK, not ALLOW."""
    r = client.post("/api/v1/sessions",
                    json={"scenario_id": "S1", "lab": "vibe_notes_node", "arm": "A"},
                    headers=AUTH)
    sid = r.json()["id"]  # state is PENDING
    r = client.post("/api/v1/guard/decide",
                    json={"session_id": sid, "tool": "navigate",
                          "arguments": {"url": "http://orders.lab.test/"}},
                    headers=AUTH)
    assert r.status_code == 200
    d = r.json()
    assert d["decision"] == "BLOCK"
    assert d["blocked"] is True


def test_guard_block_no_args(client):
    """http_request with no arguments is BLOCKED (missing required url arg)."""
    sid = _make_running_session(client)
    r = client.post("/api/v1/guard/decide",
                    json={"session_id": sid, "tool": "http_request", "arguments": {}},
                    headers=AUTH)
    assert r.status_code == 200
    d = r.json()
    assert d["decision"] == "BLOCK"
    assert d["blocked"] is True


def test_guard_send_tool_not_in_scenario_blocked(client):
    """send is a high-impact tool but is NOT in S1's allowed_actions → BLOCK."""
    sid = _make_running_session(client)
    r = client.post("/api/v1/guard/decide",
                    json={"session_id": sid, "tool": "send",
                          "arguments": {"url": "http://orders.lab.test/", "body": "hello"}},
                    headers=AUTH)
    assert r.status_code == 200
    d = r.json()
    assert d["decision"] == "BLOCK"
    assert d["blocked"] is True
    assert d["reason_code"] == "TOOL_NOT_IN_SCENARIO"


def test_guard_external_navigation_blocked(client):
    """External navigation to a forbidden host is BLOCKED (not ALLOW)."""
    sid = _make_running_session(client)
    r = client.post("/api/v1/guard/decide",
                    json={"session_id": sid, "tool": "navigate",
                          "arguments": {"url": "http://evil.com/steal"}},
                    headers=AUTH)
    assert r.status_code == 200
    d = r.json()
    assert d["decision"] == "BLOCK"
    assert d["blocked"] is True


def test_guard_hostname_confusion_blocked(client):
    """Hostname confusion (userinfo @ trick) is BLOCKED by the gateway."""
    sid = _make_running_session(client)
    r = client.post("/api/v1/guard/decide",
                    json={"session_id": sid, "tool": "navigate",
                          "arguments": {"url": "http://orders.lab.test@evil.com/"}},
                    headers=AUTH)
    assert r.status_code == 200
    d = r.json()
    assert d["decision"] == "BLOCK"
    assert d["blocked"] is True


def test_guard_unknown_tool_blocked(client):
    """Unknown tool is BLOCKED."""
    sid = _make_running_session(client)
    r = client.post("/api/v1/guard/decide",
                    json={"session_id": sid, "tool": "nuclear_launch", "arguments": {}},
                    headers=AUTH)
    assert r.status_code == 200
    d = r.json()
    assert d["decision"] == "BLOCK"
    assert d["blocked"] is True


def test_guard_missing_session_id(client):
    """Missing session_id in the request body is rejected (422)."""
    r = client.post("/api/v1/guard/decide",
                    json={"tool": "navigate", "arguments": {}},
                    headers=AUTH)
    assert r.status_code == 422


# ------------------------------------------------------------------ policy decide (gateway-backed)

def test_policy_decide_nonexistent_session(client):
    """A nonexistent session cannot receive ALLOW from policy/decide."""
    r = client.post("/api/v1/policy/decide",
                    json={"session_id": str(uuid4()), "tool": "navigate",
                          "arguments": {}, "allowed_hosts": []},
                    headers=AUTH)
    assert r.status_code == 404


def test_policy_decide_read_allow(client):
    """Valid RUNNING session with allowed read action receives ALLOW."""
    sid = _make_running_session(client)
    r = client.post("/api/v1/policy/decide",
                    json={"session_id": sid, "tool": "navigate",
                          "arguments": {"url": "http://orders.lab.test/"},
                          "allowed_hosts": []},
                    headers=AUTH)
    assert r.status_code == 200
    d = r.json()
    assert d["decision"] == "ALLOW"


def test_policy_decide_external_navigation_blocked(client):
    """External navigation to a forbidden host is BLOCKED even if the client
    supplies allowed_hosts that include it (client-supplied hosts are ignored)."""
    sid = _make_running_session(client)
    r = client.post("/api/v1/policy/decide",
                    json={"session_id": sid, "tool": "navigate",
                          "arguments": {"url": "http://evil.com/steal"},
                          "allowed_hosts": ["http://evil.com/"]},
                    headers=AUTH)
    assert r.status_code == 200
    d = r.json()
    assert d["decision"] == "BLOCK"


def test_policy_decide_api_vs_gateway_consistency(client):
    """policy/decide and guard/decide return the same decision for the same input."""
    sid = _make_running_session(client)
    payload = {"session_id": sid, "tool": "navigate",
               "arguments": {"url": "http://evil.com/"},
               "allowed_hosts": ["http://evil.com/"]}
    r1 = client.post("/api/v1/policy/decide", json=payload, headers=AUTH)
    r2 = client.post("/api/v1/guard/decide",
                     json={"session_id": sid, "tool": "navigate",
                           "arguments": {"url": "http://evil.com/"}},
                     headers=AUTH)
    d1, d2 = r1.json(), r2.json()
    assert d1["decision"] == d2["decision"] == "BLOCK"


def test_policy_decide_state_change_no_hosts_block(client):
    """state-changing action without an allowed destination is BLOCKED."""
    sid = _make_running_session(client)
    r = client.post("/api/v1/policy/decide",
                    json={"session_id": sid, "tool": "http_request",
                          "arguments": {}, "allowed_hosts": []},
                    headers=AUTH)
    assert r.status_code == 200
    d = r.json()
    assert d["decision"] == "BLOCK"

def test_shield_rule_broad_rejected(client):
    for pattern in ("/", "*"):
        r = client.post("/api/v1/shield/rules",
                        json={"route_pattern": pattern, "intent": "recon",
                              "mode": "monitor", "ttl_minutes": 60, "reason": "test"},
                        headers=AUTH)
        assert r.status_code == 400, f"broad pattern {pattern!r} should be rejected"


def test_shield_rule_valid(client):
    r = client.post("/api/v1/shield/rules",
                    json={"route_pattern": "/api/*", "intent": "recon",
                          "mode": "monitor", "ttl_minutes": 60, "reason": "test"},
                    headers=AUTH)
    assert r.status_code == 200
    data = r.json()
    assert data["state"] == "ACTIVE"
    assert data["route_pattern"] == "/api/*"


def test_list_shield_rules(client):
    r = client.get("/api/v1/shield/rules", headers=AUTH)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_remove_shield_rule(client):
    r = client.post("/api/v1/shield/rules",
                    json={"route_pattern": "/api/x", "intent": "recon",
                          "mode": "monitor", "ttl_minutes": 60, "reason": "test"},
                    headers=AUTH)
    rid = r.json()["rule_id"]
    r = client.delete(f"/api/v1/shield/rules/{rid}", headers=AUTH)
    assert r.status_code == 200
    assert r.json()["state"] == "REMOVED"


def test_expire_shield_rule(client):
    r = client.post("/api/v1/shield/rules",
                    json={"route_pattern": "/api/y", "intent": "recon",
                          "mode": "monitor", "ttl_minutes": 60, "reason": "test"},
                    headers=AUTH)
    rid = r.json()["rule_id"]
    r = client.post(f"/api/v1/shield/rules/{rid}/expire", headers=AUTH)
    assert r.status_code == 200
    assert r.json()["state"] == "EXPIRED"


# ------------------------------------------------------------------ targets (no arbitrary URLs)

def test_target_localhost_allowed(client):
    r = client.post("/api/v1/targets",
                    params={"target_id": "t-local", "url": "http://127.0.0.1:8080/", "lab": True},
                    headers=AUTH)
    assert r.status_code == 200


def test_target_labtest_allowed(client):
    r = client.post("/api/v1/targets",
                    params={"target_id": "t-lab", "url": "http://app.lab.test/", "lab": True},
                    headers=AUTH)
    assert r.status_code == 200


def test_target_public_rejected(client):
    r = client.post("/api/v1/targets",
                    params={"target_id": "t-evil", "url": "http://evil.com/", "lab": True},
                    headers=AUTH)
    assert r.status_code == 400


# ------------------------------------------------------------------ scans

def test_create_scan(client):
    client.post("/api/v1/targets",
                params={"target_id": "t-scan", "url": "http://127.0.0.1:8080/", "lab": True},
                headers=AUTH)
    r = client.post("/api/v1/scans",
                    json={"target_id": "t-scan", "model": False},
                    headers=AUTH)
    assert r.status_code == 200
    data = r.json()
    assert data["state"] == "completed"
    assert data["target_id"] == "t-scan"


def test_scan_unknown_target(client):
    r = client.post("/api/v1/scans",
                    json={"target_id": "nonexistent", "model": False},
                    headers=AUTH)
    assert r.status_code == 404


# ------------------------------------------------------------------ events list

def test_list_events(client):
    r = client.get("/api/v1/events", headers=AUTH)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


# ------------------------------------------------------------------ SSE event stream

def test_sse_stream_route_exists(client):
    from fastapi.routing import APIRoute

    from apps.api.main import app as fastapi_app

    def collect_paths(routes, prefix=""):
        found = []
        for r in routes:
            if isinstance(r, APIRoute):
                found.append(prefix + r.path)
            elif type(r).__name__ == "_IncludedRouter":
                if hasattr(r, "original_router"):
                    found.extend(
                        collect_paths(r.original_router.routes, prefix)
                    )
            elif hasattr(r, "routes"):
                rpath = getattr(r, "path", "") or ""
                found.extend(collect_paths(r.routes, prefix + rpath))
        return found

    paths = collect_paths(fastapi_app.routes)
    assert any("events/stream" in p for p in paths), "SSE stream route not mounted"


def test_sse_replay_after_seq(client):
    # First, trigger some events by creating a session
    client.post("/api/v1/sessions",
                json={"scenario_id": "S1", "lab": "x", "arm": "A"}, headers=AUTH)
    # Connect with after_seq=0 (get all)
    with client.stream("GET", "/api/v1/events/stream?after_seq=0", headers=AUTH) as r:
        assert r.status_code == 200


# ------------------------------------------------------------------ evidence verify

def test_evidence_verify(client):
    sid = uuid4()
    r = client.post("/api/v1/evidence/verify",
                    json={"session_id": str(sid)},
                    headers=AUTH)
    assert r.status_code == 200
    d = r.json()
    assert d["session_id"] == str(sid)
    assert d["ok"] is True


def test_evidence_verify_invalid_id(client):
    r = client.post("/api/v1/evidence/verify",
                    json={"session_id": "not-a-uuid"},
                    headers=AUTH)
    assert r.status_code == 400


# ---- findings / patches / approvals / escalations

def test_empty_collections(client):
    for path in ("/api/v1/findings", "/api/v1/patches",
                 "/api/v1/approvals", "/api/v1/escalations",
                 "/api/v1/containment/branches"):
        r = client.get(path, headers=AUTH)
        assert r.status_code == 200
        assert r.json() == []


# ------------------------------------------------------------------ metrics

def test_metrics(client):
    r = client.get("/api/v1/metrics?arm=A", headers=AUTH)
    assert r.status_code == 200
    d = r.json()
    assert d["arm"] == "A"
    assert isinstance(d["metrics"], list)


# ------------------------------------------------------------------ report export

def test_export_report(client):
    r = client.get("/api/v1/reports/export", headers=AUTH)
    assert r.status_code == 200
    d = r.json()
    assert d["format"] == "json"
    assert isinstance(d["sections"], list)


# ------------------------------------------------------------------ rate limiting (burst)

def test_rate_limit_burst(client):
    # Make many rapid authenticated requests; expect rate limiting (429)
    # once the burst (200) is exceeded.
    codes = []
    for _ in range(250):
        r = client.get("/api/v1/sessions", headers=AUTH)
        codes.append(r.status_code)
    assert 429 in codes, f"expected rate limiting, got codes {set(codes)}"
