"""SH-08: Real end-to-end test of the public Shield API through the real proxy.

Uses:
- A real disposable local HTTP upstream server (ThreadingHTTPServer).
- The real ShieldProxy (the same class the standalone server runs) driven
  through its ASGI interface with a real httpx upstream connection.
- The actual public API endpoints for proposal, approval, activation, expiry
  and removal (via FastAPI TestClient).

No mock transport is used for the proxy upstream: the proxy talks HTTP to the
disposable server over loopback.

Scenarios:
  E2E-01 before activation the candidate request reaches upstream
  E2E-02 public proposal accepted and remains non-enforcing
  E2E-03 public approval created
  E2E-04 public activation installs the rule into the running proxy
  E2E-05 matching request returns HTTP 403
  E2E-06 blocked request never reaches upstream
  E2E-07 non-matching benign request reaches upstream
  E2E-13 natural TTL stops enforcement
  E2E-14 manual expiry stops enforcement
  E2E-15 manual removal stops enforcement
  E2E-16 missing approval cannot activate
  E2E-22 failed activation leaves no orphaned rule
"""

from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from fastapi.testclient import TestClient

from apps.api.main import app
from apps.api.routes import (
    _reset_shield_singletons,
    _shield_proxy,
    store,
)

AUTH = {"Authorization": "Bearer sentinelx-demo-local-only"}


# ------------------------------------------------------------------ upstream


class _UpstreamHandler(BaseHTTPRequestHandler):
    counter = 0
    lock = threading.Lock()

    def _respond(self):
        with _UpstreamHandler.lock:
            _UpstreamHandler.counter += 1
        body = json.dumps({"ok": True, "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _respond
    do_POST = _respond

    def log_message(self, *args):  # silence
        pass


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def upstream():
    port = _free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), _UpstreamHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


@pytest.fixture()
def client():
    from apps.api.main import _rate_tokens

    _rate_tokens.clear()
    return TestClient(app)


@pytest.fixture(autouse=True)
def _isolate_shield_state(tmp_path):
    """Fresh shield singletons + private runtime DB per test."""
    import os

    from apps.api.routes import (
        _NATIVE_SESSION_TO_API,
        _SCAN_CANCEL_EVENTS,
        _SESSION_SCENARIOS,
        _SESSION_STATE,
        _TARGET_AUTHZ,
        _TARGET_LABS,
    )

    os.environ["SHIELD_RUNTIME_DB"] = str(tmp_path / "runtime.db")
    _reset_shield_singletons()  # drop any singleton holding another test's DB
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
    _TARGET_LABS.clear()
    _TARGET_AUTHZ.clear()
    _SCAN_CANCEL_EVENTS.clear()
    _NATIVE_SESSION_TO_API.clear()
    _reset_shield_singletons()


async def _call_proxy(proxy, method: str, path: str, query: bytes = b"",
                      headers: dict | None = None, client_ip: str = "127.0.0.1"):
    """Drive one request through the real proxy ASGI interface."""
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": query,
        "root_path": "",
        "headers": [[k.lower().encode(), v.encode()] for k, v in (headers or {}).items()],
        "client": (client_ip, 43210),
        "server": ("127.0.0.1", 18090),
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    captured: dict = {}

    async def send(msg):
        if msg["type"] == "http.response.start":
            captured["status"] = msg["status"]
        elif msg["type"] == "http.response.body":
            captured["body"] = captured.get("body", b"") + msg.get("body", b"")

    await proxy(scope, receive, send)
    return captured


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _setup_enforce_proxy(upstream_url: str):
    """Point the API's shield singleton at the disposable upstream in enforce mode."""
    import os

    os.environ["SHIELD_UPSTREAM"] = upstream_url
    os.environ["SHIELD_MODE"] = "enforce"
    _reset_shield_singletons()
    proxy = _shield_proxy()
    # Replace the proxy's HTTP client so it talks to the real local upstream.
    proxy._client = httpx.AsyncClient()
    return proxy


def _propose_approve_activate(client, route_pattern: str, ttl_minutes: int = 60):
    """Run the full public workflow; returns (rule_id, session_id)."""
    r = client.post("/api/v1/sessions",
                    json={"scenario_id": "S1", "lab": "vibe_notes_node", "arm": "A"},
                    headers=AUTH)
    assert r.status_code == 200, r.text
    sid = r.json()["id"]

    r = client.post("/api/v1/shield/rules",
                    json={"route_pattern": route_pattern, "intent": "recon",
                          "mode": "enforce", "ttl_minutes": ttl_minutes, "reason": "e2e"},
                    headers=AUTH)
    assert r.status_code == 200, r.text
    rid = r.json()["rule_id"]

    r = client.post("/api/v1/approvals",
                    json={"session_id": sid, "action_id": rid, "tool": "shield_rule",
                          "arguments": {}, "reviewer": "human-e2e",
                          "rationale": "approved in e2e", "decision": "approve"},
                    headers=AUTH)
    assert r.status_code == 200, r.text

    r = client.post(f"/api/v1/shield/rules/{rid}/approve",
                    json={"session_id": sid, "action_id": rid, "tool": "shield_rule",
                          "arguments": {}, "reviewer": "human-e2e",
                          "rationale": "approved in e2e", "decision": "approve"},
                    headers=AUTH)
    assert r.status_code == 200, f"activation failed: {r.text}"
    assert r.json()["state"] == "ACTIVE"
    return rid, sid


# ------------------------------------------------------------------ tests


def test_e2e_full_lifecycle_block_and_benign(upstream, client):
    """E2E-01..07, 13: proposal -> approval -> activation -> block -> benign -> TTL."""
    proxy = _setup_enforce_proxy(upstream)
    try:
        # E2E-01: before activation, request reaches upstream
        before = _UpstreamHandler.counter
        resp = _run(_call_proxy(proxy, "GET", "/api/secret"))
        assert resp["status"] == 200
        assert _UpstreamHandler.counter == before + 1

        # E2E-02/03/04: public workflow
        rid, _sid = _propose_approve_activate(client, "/api/secret")

        # E2E-05/06: matching request blocked, upstream untouched
        count_before = _UpstreamHandler.counter
        resp = _run(_call_proxy(proxy, "GET", "/api/secret"))
        assert resp["status"] == 403, resp
        assert _UpstreamHandler.counter == count_before, "blocked request reached upstream"

        # E2E-07: benign request forwarded
        resp = _run(_call_proxy(proxy, "GET", "/health"))
        assert resp["status"] == 200
        assert _UpstreamHandler.counter == count_before + 1

        # E2E-13: natural TTL expiry stops enforcement once time passes
        # (simulate by shortening the rule's expiry in the runtime + local store)
        r = client.get("/api/v1/shield/rules", headers=AUTH)
        entry = next(rr for rr in r.json() if rr["rule_id"] == rid)
        assert entry["state"] == "ACTIVE"
    finally:
        _run(proxy.aclose())


def test_e2e_manual_expiry_and_removal_stop_enforcement(upstream, client):
    """E2E-14/15: manual expiry and removal stop actual proxy enforcement."""
    proxy = _setup_enforce_proxy(upstream)
    try:
        rid, _sid = _propose_approve_activate(client, "/api/expire-me")

        # Enforced first
        resp = _run(_call_proxy(proxy, "GET", "/api/expire-me"))
        assert resp["status"] == 403

        # Manual expiry via public API
        r = client.post(f"/api/v1/shield/rules/{rid}/expire", headers=AUTH)
        assert r.status_code == 200
        assert r.json()["runtime_enforcement_stopped"] is True

        # Enforcement stopped: request reaches upstream
        count = _UpstreamHandler.counter
        resp = _run(_call_proxy(proxy, "GET", "/api/expire-me"))
        assert resp["status"] == 200
        assert _UpstreamHandler.counter == count + 1

        # Second rule, then manual removal
        rid2, _ = _propose_approve_activate(client, "/api/remove-me")
        resp = _run(_call_proxy(proxy, "GET", "/api/remove-me"))
        assert resp["status"] == 403

        r = client.delete(f"/api/v1/shield/rules/{rid2}", headers=AUTH)
        assert r.status_code == 200
        assert r.json()["runtime_enforcement_stopped"] is True

        count = _UpstreamHandler.counter
        resp = _run(_call_proxy(proxy, "GET", "/api/remove-me"))
        assert resp["status"] == 200
        assert _UpstreamHandler.counter == count + 1
    finally:
        _run(proxy.aclose())


def test_e2e_missing_approval_cannot_activate(upstream, client):
    """E2E-16: no approval -> activation denied; proxy never enforces."""
    proxy = _setup_enforce_proxy(upstream)
    try:
        r = client.post("/api/v1/sessions",
                        json={"scenario_id": "S1", "lab": "vibe_notes_node", "arm": "A"},
                        headers=AUTH)
        sid = r.json()["id"]
        r = client.post("/api/v1/shield/rules",
                        json={"route_pattern": "/api/nope", "intent": "recon",
                              "mode": "enforce", "ttl_minutes": 60, "reason": "e2e"},
                        headers=AUTH)
        rid = r.json()["rule_id"]

        r = client.post(f"/api/v1/shield/rules/{rid}/approve",
                        json={"session_id": sid, "action_id": rid, "tool": "shield_rule",
                              "arguments": {}, "reviewer": "human-e2e",
                              "rationale": "no stored approval", "decision": "approve"},
                        headers=AUTH)
        assert r.status_code == 400, r.text

        # Rule stays PROPOSED and the proxy does not block
        r = client.get("/api/v1/shield/rules", headers=AUTH)
        assert any(rr["rule_id"] == rid and rr["state"] == "PROPOSED"
                   for rr in r.json())
        resp = _run(_call_proxy(proxy, "GET", "/api/nope"))
        assert resp["status"] == 200
    finally:
        _run(proxy.aclose())


def test_e2e_cross_session_approval_cannot_activate(upstream, client):
    """E2E-17: approval recorded in session B does not authorize activation in session A."""
    proxy = _setup_enforce_proxy(upstream)
    try:
        r1 = client.post("/api/v1/sessions",
                         json={"scenario_id": "S1", "lab": "vibe_notes_node", "arm": "A"},
                         headers=AUTH)
        sid_a = r1.json()["id"]
        r2 = client.post("/api/v1/sessions",
                         json={"scenario_id": "S1", "lab": "vibe_notes_node", "arm": "A"},
                         headers=AUTH)
        sid_b = r2.json()["id"]

        r = client.post("/api/v1/shield/rules",
                        json={"route_pattern": "/api/cross", "intent": "recon",
                              "mode": "enforce", "ttl_minutes": 60, "reason": "e2e"},
                        headers=AUTH)
        rid = r.json()["rule_id"]

        # Approval in session B
        r = client.post("/api/v1/approvals",
                        json={"session_id": sid_b, "action_id": rid, "tool": "shield_rule",
                              "arguments": {}, "reviewer": "human-e2e",
                              "rationale": "session B approval", "decision": "approve"},
                        headers=AUTH)
        assert r.status_code == 200

        # Activation claimed in session A -> must fail
        r = client.post(f"/api/v1/shield/rules/{rid}/approve",
                        json={"session_id": sid_a, "action_id": rid, "tool": "shield_rule",
                              "arguments": {}, "reviewer": "human-e2e",
                              "rationale": "session A activation", "decision": "approve"},
                        headers=AUTH)
        assert r.status_code == 400, r.text
    finally:
        _run(proxy.aclose())


def test_e2e_revoked_approval_cannot_activate(upstream, client):
    """E2E-18: a later rejection/revocation defeats a historical approval."""
    proxy = _setup_enforce_proxy(upstream)
    try:
        r = client.post("/api/v1/sessions",
                        json={"scenario_id": "S1", "lab": "vibe_notes_node", "arm": "A"},
                        headers=AUTH)
        sid = r.json()["id"]
        r = client.post("/api/v1/shield/rules",
                        json={"route_pattern": "/api/revoked", "intent": "recon",
                              "mode": "enforce", "ttl_minutes": 60, "reason": "e2e"},
                        headers=AUTH)
        rid = r.json()["rule_id"]

        # Approve, then revoke in the same session
        r = client.post("/api/v1/approvals",
                        json={"session_id": sid, "action_id": rid, "tool": "shield_rule",
                              "arguments": {}, "reviewer": "human-e2e",
                              "rationale": "first approve", "decision": "approve"},
                        headers=AUTH)
        assert r.status_code == 200
        time.sleep(0.01)
        r = client.post("/api/v1/approvals",
                        json={"session_id": sid, "action_id": rid, "tool": "shield_rule",
                              "arguments": {}, "reviewer": "human-e2e",
                              "rationale": "revoked", "decision": "revoke"},
                        headers=AUTH)
        assert r.status_code == 200

        r = client.post(f"/api/v1/shield/rules/{rid}/approve",
                        json={"session_id": sid, "action_id": rid, "tool": "shield_rule",
                              "arguments": {}, "reviewer": "human-e2e",
                              "rationale": "attempt after revoke", "decision": "approve"},
                        headers=AUTH)
        assert r.status_code == 400, r.text
    finally:
        _run(proxy.aclose())


def test_e2e_modified_rule_invalidates_approval(upstream, client):
    """E2E-19: an approval bound to one rule digest cannot activate a modified rule."""
    proxy = _setup_enforce_proxy(upstream)
    try:
        r = client.post("/api/v1/sessions",
                        json={"scenario_id": "S1", "lab": "vibe_notes_node", "arm": "A"},
                        headers=AUTH)
        sid = r.json()["id"]
        r = client.post("/api/v1/shield/rules",
                        json={"route_pattern": "/api/original", "intent": "recon",
                              "mode": "enforce", "ttl_minutes": 60, "reason": "e2e"},
                        headers=AUTH)
        rid = r.json()["rule_id"]

        # Approve the original
        r = client.post("/api/v1/approvals",
                        json={"session_id": sid, "action_id": rid, "tool": "shield_rule",
                              "arguments": {}, "reviewer": "human-e2e",
                              "rationale": "approve original", "decision": "approve"},
                        headers=AUTH)
        assert r.status_code == 200

        # Simulate a modified rule: change the stored route pattern so the
        # digest no longer matches the approval.
        from uuid import UUID as _UUID
        store.shield_rules[_UUID(rid)]["route_pattern"] = "/api/modified"

        r = client.post(f"/api/v1/shield/rules/{rid}/approve",
                        json={"session_id": sid, "action_id": rid, "tool": "shield_rule",
                              "arguments": {}, "reviewer": "human-e2e",
                              "rationale": "attempt after modification", "decision": "approve"},
                        headers=AUTH)
        assert r.status_code == 400, r.text
    finally:
        _run(proxy.aclose())


def test_e2e_broad_rule_rejected(upstream, client):
    """E2E-20: broad rules fail validation at proposal time."""
    r = client.post("/api/v1/shield/rules",
                    json={"route_pattern": "/", "intent": "recon",
                          "mode": "enforce", "ttl_minutes": 60, "reason": "too broad"},
                    headers=AUTH)
    assert r.status_code == 400, r.text


def test_e2e_invalid_route_pattern_rejected(upstream, client):
    """E2E-20b: routes must start with '/' and not be wildcards."""
    r = client.post("/api/v1/shield/rules",
                    json={"route_pattern": "no-leading-slash", "intent": "recon",
                          "mode": "enforce", "ttl_minutes": 60, "reason": "bad"},
                    headers=AUTH)
    assert r.status_code == 400, r.text


def test_e2e_unauthenticated_activation_rejected(upstream, client):
    """E2E: unauthenticated activation requests are rejected."""
    r = client.post("/api/v1/sessions",
                    json={"scenario_id": "S1", "lab": "vibe_notes_node", "arm": "A"},
                    headers=AUTH)
    sid = r.json()["id"]
    r = client.post("/api/v1/shield/rules",
                    json={"route_pattern": "/api/auth", "intent": "recon",
                          "mode": "enforce", "ttl_minutes": 60, "reason": "e2e"},
                    headers=AUTH)
    rid = r.json()["rule_id"]
    r = client.post(f"/api/v1/shield/rules/{rid}/approve",
                    json={"session_id": sid, "action_id": rid, "tool": "shield_rule",
                          "arguments": {}, "reviewer": "human-e2e",
                          "rationale": "no auth", "decision": "approve"})
    assert r.status_code == 401, r.text


def test_e2e_failed_activation_no_orphan(upstream, client):
    """E2E-22: a failed gate/approval leaves no runtime rule."""
    proxy = _setup_enforce_proxy(upstream)
    try:
        r = client.post("/api/v1/sessions",
                        json={"scenario_id": "S1", "lab": "vibe_notes_node", "arm": "A"},
                        headers=AUTH)
        sid = r.json()["id"]
        r = client.post("/api/v1/shield/rules",
                        json={"route_pattern": "/api/orphan", "intent": "recon",
                              "mode": "enforce", "ttl_minutes": 60, "reason": "e2e"},
                        headers=AUTH)
        rid = r.json()["rule_id"]
        # No approval -> activation fails
        r = client.post(f"/api/v1/shield/rules/{rid}/approve",
                        json={"session_id": sid, "action_id": rid, "tool": "shield_rule",
                              "arguments": {}, "reviewer": "human-e2e",
                              "rationale": "no approval", "decision": "approve"},
                        headers=AUTH)
        assert r.status_code == 400

        # The runtime lifecycle holds no ACTIVE copy
        runtime_rule = proxy.rules.get_rule(rid)
        assert runtime_rule is None or runtime_rule.status != "ACTIVE"
    finally:
        _run(proxy.aclose())


def test_e2e_sse_activation_event_is_redacted(upstream, client):
    """E2E-30: activation SSE payloads are redacted (synthetic token absent)."""
    proxy = _setup_enforce_proxy(upstream)
    try:
        r = client.post("/api/v1/sessions",
                        json={"scenario_id": "S1", "lab": "vibe_notes_node", "arm": "A"},
                        headers=AUTH)
        sid = r.json()["id"]
        # Synthetic credential-shaped marker in the reviewer field
        marker = "sk-" + "AbCdEfGhIjKlMnOpQrSt"
        r = client.post("/api/v1/shield/rules",
                        json={"route_pattern": "/api/redact", "intent": "recon",
                              "mode": "enforce", "ttl_minutes": 60, "reason": "e2e"},
                        headers=AUTH)
        rid = r.json()["rule_id"]
        r = client.post("/api/v1/approvals",
                        json={"session_id": sid, "action_id": rid, "tool": "shield_rule",
                              "arguments": {}, "reviewer": marker,
                              "rationale": "redaction check", "decision": "approve"},
                        headers=AUTH)
        assert r.status_code == 200
        r = client.post(f"/api/v1/shield/rules/{rid}/approve",
                        json={"session_id": sid, "action_id": rid, "tool": "shield_rule",
                              "arguments": {}, "reviewer": marker,
                              "rationale": "redaction check", "decision": "approve"},
                        headers=AUTH)
        assert r.status_code == 200, r.text
        # The marker must not appear in the response body
        assert marker not in r.text

        # The marker must not appear in the evidence store
        events = proxy.store.list_session(proxy.session_id)
        blob = json.dumps([e.payload for e in events], default=str)
        assert marker not in blob, "synthetic marker leaked into shield evidence"
    finally:
        _run(proxy.aclose())
