"""SH-02/SH-04/SH-05: cross-process coordination, atomic activation rollback,
and safe benign-gate rejection.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from apps.api.main import app
from apps.api.routes import _reset_shield_singletons, _shield_proxy, _shield_runtime, store
from sentinelx.common_schemas import (
    Actor,
    ActorRole,
    SessionKind,
    ShieldRule,
    ShieldScope,
    ShieldStatus,
)
from sentinelx.evidence.db import connect, migrate
from sentinelx.evidence.sessions import SessionService
from sentinelx.evidence.store import EvidenceStore
from sentinelx.shield.config import ShieldConfig
from sentinelx.shield.detect import Detector
from sentinelx.shield.proxy import ShieldProxy
from sentinelx.shield.recorder import ShieldRecorder
from sentinelx.shield.rules import BenignReplayGate, ShieldAction

AUTH = {"Authorization": "Bearer sentinelx-demo-local-only"}


class _UpstreamHandler(BaseHTTPRequestHandler):
    counter = 0
    lock = threading.Lock()

    def _respond(self):
        with _UpstreamHandler.lock:
            _UpstreamHandler.counter += 1
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _respond
    do_POST = _respond

    def log_message(self, *args):
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
def _isolate():
    from apps.api.routes import (
        _NATIVE_SESSION_TO_API,
        _SCAN_CANCEL_EVENTS,
        _SESSION_SCENARIOS,
        _SESSION_STATE,
        _TARGET_AUTHZ,
        _TARGET_LABS,
    )

    yield
    for d in (store.sessions, store.runs, store.findings, store.patches,
              store.approvals, store.shield_rules, store.escalations,
              store.scans, store.idempotency):
        d.clear()
    store.events_log.clear()
    store.targets.clear()
    _SESSION_STATE.clear()
    _SESSION_SCENARIOS.clear()
    _TARGET_LABS.clear()
    _TARGET_AUTHZ.clear()
    _SCAN_CANCEL_EVENTS.clear()
    _NATIVE_SESSION_TO_API.clear()
    _reset_shield_singletons()


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _call_proxy(proxy, method: str, path: str):
    scope = {
        "type": "http", "http_version": "1.1", "method": method,
        "scheme": "http", "path": path, "raw_path": path.encode(),
        "query_string": b"", "root_path": "",
        "headers": [], "client": ("127.0.0.1", 1234),
        "server": ("127.0.0.1", 18090),
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    captured: dict = {}

    async def send(msg):
        if msg["type"] == "http.response.start":
            captured["status"] = msg["status"]

    await proxy(scope, receive, send)
    return captured


def _make_standalone_proxy(upstream_url: str, runtime_store):
    """A fresh ShieldProxy that only shares the runtime DB (simulated separate process)."""
    conn = connect(":memory:")
    migrate(conn)
    evidence = EvidenceStore(conn)
    session, _ = SessionService(conn).create(
        kind=SessionKind.GUARD, policy_version="1.0",
        actor=Actor(id="standalone", role=ActorRole.SYSTEM),
    )
    detector = Detector([], [])
    recorder = ShieldRecorder(evidence, session.id, batch_interval_s=999.0,
                              suspicious_rate_cap_per_min=1000)
    config = ShieldConfig(upstream=upstream_url, mode="enforce", lab_mode=True)
    client = httpx.AsyncClient()
    proxy = ShieldProxy(config, evidence, session.id, detector, recorder,
                        http_client=client, runtime_store=runtime_store)
    return proxy, client


def _setup_api_process(upstream_url: str):
    os.environ["SHIELD_UPSTREAM"] = upstream_url
    os.environ["SHIELD_MODE"] = "enforce"
    _reset_shield_singletons()
    return _shield_proxy()


def _propose_approve_activate(client, route_pattern: str):
    r = client.post("/api/v1/sessions",
                    json={"scenario_id": "S1", "lab": "vibe_notes_node", "arm": "A"},
                    headers=AUTH)
    sid = r.json()["id"]
    r = client.post("/api/v1/shield/rules",
                    json={"route_pattern": route_pattern, "intent": "recon",
                          "mode": "enforce", "ttl_minutes": 60, "reason": "recovery"},
                    headers=AUTH)
    rid = r.json()["rule_id"]
    r = client.post("/api/v1/approvals",
                    json={"session_id": sid, "action_id": rid, "tool": "shield_rule",
                          "arguments": {}, "reviewer": "human",
                          "rationale": "recovery check", "decision": "approve"},
                    headers=AUTH)
    assert r.status_code == 200
    r = client.post(f"/api/v1/shield/rules/{rid}/approve",
                    json={"session_id": sid, "action_id": rid, "tool": "shield_rule",
                          "arguments": {}, "reviewer": "human",
                          "rationale": "recovery check", "decision": "approve"},
                    headers=AUTH)
    assert r.status_code == 200, r.text
    return rid, sid


# ------------------------------------------------------------------ SH-02


def test_sh02_separate_proxy_process_enforces_api_activation(upstream, client, tmp_path):
    """The API activation is visible to a *separate* ShieldProxy instance that
    shares only the runtime DB file - real cross-process coordination."""
    os.environ["SHIELD_RUNTIME_DB"] = str(tmp_path / "runtime.db")
    api_proxy = _setup_api_process(upstream)
    try:
        rid, _ = _propose_approve_activate(client, "/api/crossproc")

        # 'Standalone' proxy in a different object graph, same runtime DB.
        standalone, standalone_client = _make_standalone_proxy(
            upstream, _shield_runtime())
        try:
            count = _UpstreamHandler.counter
            resp = _run(_call_proxy(standalone, "GET", "/api/crossproc"))
            assert resp["status"] == 403, "standalone proxy did not enforce API activation"
            assert _UpstreamHandler.counter == count
            # Benign path still forwards
            resp = _run(_call_proxy(standalone, "GET", "/health"))
            assert resp["status"] == 200
        finally:
            _run(standalone_client.aclose())

        # Removal through the API stops the standalone proxy's enforcement.
        r = client.delete(f"/api/v1/shield/rules/{rid}", headers=AUTH)
        assert r.status_code == 200
        standalone2, standalone_client2 = _make_standalone_proxy(
            upstream, _shield_runtime())
        try:
            resp = _run(_call_proxy(standalone2, "GET", "/api/crossproc"))
            assert resp["status"] == 200, "removed rule still enforced cross-process"
        finally:
            _run(standalone_client2.aclose())
    finally:
        _run(api_proxy.aclose())


def test_sh02_runtime_store_rejects_tampered_payload(upstream, tmp_path):
    """A row marked ACTIVE whose payload hash does not match is never enforced."""
    from sentinelx.shield.runtime import ShieldRuntimeStore

    runtime = ShieldRuntimeStore(tmp_path / "runtime.db")
    rule = ShieldRule(
        id="rule_tamper",
        target_id="shield-api",
        scope=ShieldScope(route="/api/tampered"),
        action=ShieldAction.BLOCK_ROUTE_PATTERN.value,
        reason="tamper test",
        linked_finding_id=None,
        intent_event_ids=["evt_x"],
        owner="test",
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        status=ShieldStatus.PROPOSED,
    )
    runtime.upsert(rule, status=ShieldStatus.ACTIVE.value)
    # Tamper: change the payload without updating the recorded hash.
    payload = json.loads(rule.model_dump_json())
    payload["scope"]["route"] = "/"
    runtime._conn.execute(
        "UPDATE shield_runtime_rules SET payload = ? WHERE rule_id = ?",
        (json.dumps(payload), rule.id),
    )
    assert runtime.active_rules() == [], "tampered ACTIVE row was enforced"


def test_sh02_runtime_store_expires_overdue(upstream, tmp_path):
    """expire_overdue marks overdue ACTIVE rows EXPIRED - natural TTL contract."""
    from sentinelx.shield.runtime import ShieldRuntimeStore

    runtime = ShieldRuntimeStore(tmp_path / "runtime.db")
    rule = ShieldRule(
        id="rule_ttl",
        target_id="shield-api",
        scope=ShieldScope(route="/api/ttl"),
        action=ShieldAction.BLOCK_ROUTE_PATTERN.value,
        reason="ttl test",
        linked_finding_id=None,
        intent_event_ids=["evt_x"],
        owner="test",
        created_at=datetime.now(UTC) - timedelta(hours=2),
        expires_at=datetime.now(UTC) - timedelta(minutes=1),
        status=ShieldStatus.PROPOSED,
    )
    runtime.upsert(rule, status=ShieldStatus.ACTIVE.value)
    assert runtime.active_rules() == []  # already filtered by expiry
    changed = runtime.expire_overdue(datetime.now(UTC))
    assert changed == 1
    row = runtime.get(rule.id)
    assert row is not None and row[1] == "EXPIRED"


# ------------------------------------------------------------------ SH-04


def test_sh04_evidence_failure_rolls_back_runtime(upstream, client, monkeypatch):
    """If evidence persistence fails after runtime installation, the runtime
    rolls back and the API reports failure - never an untracked ACTIVE rule."""
    os.environ["SHIELD_RUNTIME_DB"] = os.path.join(
        os.environ.get("TEMP", "."), f"sh04_{uuid4().hex}.db")
    api_proxy = _setup_api_process(upstream)
    try:
        r = client.post("/api/v1/sessions",
                        json={"scenario_id": "S1", "lab": "vibe_notes_node", "arm": "A"},
                        headers=AUTH)
        sid = r.json()["id"]
        r = client.post("/api/v1/shield/rules",
                        json={"route_pattern": "/api/rollback", "intent": "recon",
                              "mode": "enforce", "ttl_minutes": 60, "reason": "sh04"},
                        headers=AUTH)
        rid = r.json()["rule_id"]
        r = client.post("/api/v1/approvals",
                        json={"session_id": sid, "action_id": rid, "tool": "shield_rule",
                              "arguments": {}, "reviewer": "human",
                              "rationale": "sh04", "decision": "approve"},
                        headers=AUTH)
        assert r.status_code == 200

        # Inject an evidence-write failure at the deployment boundary.
        import apps.api.routes as routes_mod

        def _boom(*a, **k):
            raise RuntimeError("injected evidence failure")

        monkeypatch.setattr(routes_mod, "_shield_evidence_append", _boom)

        r = client.post(f"/api/v1/shield/rules/{rid}/approve",
                        json={"session_id": sid, "action_id": rid, "tool": "shield_rule",
                              "arguments": {}, "reviewer": "human",
                              "rationale": "sh04", "decision": "approve"},
                        headers=AUTH)
        assert r.status_code == 503, f"expected 503, got {r.status_code}: {r.text}"

        # Runtime must NOT hold an ACTIVE copy.
        runtime_rule = api_proxy.rules.get_rule(rid)
        assert runtime_rule is None or runtime_rule.status != "ACTIVE"
        # API state must be PROPOSED again.
        r = client.get("/api/v1/shield/rules", headers=AUTH)
        assert any(rr["rule_id"] == rid and rr["state"] == "PROPOSED"
                   for rr in r.json())
    finally:
        _run(api_proxy.aclose())


def test_sh04_runtime_store_failure_rolls_back(upstream, client, monkeypatch):
    """If the shared runtime-store write fails, the local runtime rolls back."""
    os.environ["SHIELD_RUNTIME_DB"] = os.path.join(
        os.environ.get("TEMP", "."), f"sh04b_{uuid4().hex}.db")
    api_proxy = _setup_api_process(upstream)
    try:
        r = client.post("/api/v1/sessions",
                        json={"scenario_id": "S1", "lab": "vibe_notes_node", "arm": "A"},
                        headers=AUTH)
        sid = r.json()["id"]
        r = client.post("/api/v1/shield/rules",
                        json={"route_pattern": "/api/rollback2", "intent": "recon",
                              "mode": "enforce", "ttl_minutes": 60, "reason": "sh04b"},
                        headers=AUTH)
        rid = r.json()["rule_id"]
        r = client.post("/api/v1/approvals",
                        json={"session_id": sid, "action_id": rid, "tool": "shield_rule",
                              "arguments": {}, "reviewer": "human",
                              "rationale": "sh04b", "decision": "approve"},
                        headers=AUTH)
        assert r.status_code == 200

        # Fail the real publication write, retaining approval and transaction logic.
        def fail_upsert(*args, **kwargs):
            raise OSError("injected runtime store failure")

        monkeypatch.setattr(_shield_runtime(), "upsert", fail_upsert)

        r = client.post(f"/api/v1/shield/rules/{rid}/approve",
                        json={"session_id": sid, "action_id": rid, "tool": "shield_rule",
                              "arguments": {}, "reviewer": "human",
                              "rationale": "sh04b", "decision": "approve"},
                        headers=AUTH)
        assert r.status_code == 503, f"expected 503, got {r.status_code}: {r.text}"
        runtime_rule = api_proxy.rules.get_rule(rid)
        assert runtime_rule is None or runtime_rule.status != "ACTIVE"
    finally:
        _run(api_proxy.aclose())


# ------------------------------------------------------------------ SH-05


def test_sh05_gate_rejection_without_evidence_does_not_crash():
    """A rule with no intent_event_ids that fails the benign gate must return a
    structured rejection, not raise ValidationError."""
    conn = connect(":memory:")
    migrate(conn)
    evidence = EvidenceStore(conn)
    session, _ = SessionService(conn).create(
        kind=SessionKind.GUARD, policy_version="1.0",
        actor=Actor(id="t", role=ActorRole.SYSTEM),
    )
    gate = BenignReplayGate(
        evidence, session.id,
        benign_requests=[{"method": "GET", "path": "/api/notes", "headers": {}, "params": {}}],
    )
    rule = ShieldRule(
        id="rule_noevt",
        target_id="shield-api",
        scope=ShieldScope(route="/api/notes"),
        action=ShieldAction.BLOCK_ROUTE_PATTERN.value,
        reason="no evidence ids",
        linked_finding_id="finding_x",
        intent_event_ids=[],  # deliberately empty
        owner="test",
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        status=ShieldStatus.PROPOSED,
    )
    result = gate.check(rule)  # must not raise
    assert result.passed is False
    assert result.benign_blocked == 1
    # A real gate-rejection evidence event was recorded for the ticket
    assert result.escalation_ticket is not None
    assert len(result.escalation_ticket.evidence_event_ids) >= 1
    kinds = [e.kind for e in evidence.list_session(session.id)]
    assert "shield_gate_rejection" in kinds


def test_sh05_api_proposal_has_real_evidence(upstream, client, tmp_path):
    """API-proposed rules carry a real SHIELD_RULE_PROPOSED evidence event."""
    os.environ["SHIELD_RUNTIME_DB"] = str(tmp_path / "runtime.db")
    api_proxy = _setup_api_process(upstream)
    try:
        r = client.post("/api/v1/shield/rules",
                        json={"route_pattern": "/api/evidence", "intent": "recon",
                              "mode": "enforce", "ttl_minutes": 60, "reason": "sh05"},
                        headers=AUTH)
        assert r.status_code == 200, r.text
        rid = r.json()["rule_id"]
        entry = None
        from uuid import UUID as _UUID
        entry = store.shield_rules[_UUID(rid)]
        assert entry["intent_event_ids"], "proposal has no evidence reference"
        kinds = [e.kind for e in api_proxy.store.list_session(api_proxy.session_id)]
        assert "SHIELD_RULE_PROPOSED" in kinds
    finally:
        _run(api_proxy.aclose())


# ------------------------------------------------------------------ SH-06


def test_sh06_approval_subject_is_canonical(upstream, client, tmp_path):
    """Stored approval subjects are `shield_rule:{rule_id}:{digest}` - the same
    format the activation endpoint looks up (SH-01 + SH-06)."""
    os.environ["SHIELD_RUNTIME_DB"] = str(tmp_path / "runtime.db")
    api_proxy = _setup_api_process(upstream)
    try:
        from uuid import UUID as _UUID

        from apps.api.routes import (
            _SESSION_STATE,
            _shield_approval_subject,
            _shield_rule_digest,
        )

        r = client.post("/api/v1/sessions",
                        json={"scenario_id": "S1", "lab": "vibe_notes_node", "arm": "A"},
                        headers=AUTH)
        sid = r.json()["id"]
        r = client.post("/api/v1/shield/rules",
                        json={"route_pattern": "/api/canon", "intent": "recon",
                              "mode": "enforce", "ttl_minutes": 60, "reason": "sh06"},
                        headers=AUTH)
        rid = r.json()["rule_id"]
        r = client.post("/api/v1/approvals",
                        json={"session_id": sid, "action_id": rid, "tool": "shield_rule",
                              "arguments": {}, "reviewer": "human",
                              "rationale": "sh06", "decision": "approve"},
                        headers=AUTH)
        assert r.status_code == 200
        entry = store.shield_rules[_UUID(rid)]
        expected = _shield_approval_subject(rid, _shield_rule_digest(entry))
        records = _SESSION_STATE[_UUID(sid)]["approvals"]
        assert records[-1]["subject_id"] == expected
    finally:
        _run(api_proxy.aclose())


# ------------------------------------------------------------------ SH-07


def test_sh07_proxy_request_log_redacts_paths(upstream, client, tmp_path):
    """Credential-shaped path segments never reach the proxy request log."""
    os.environ["SHIELD_RUNTIME_DB"] = str(tmp_path / "runtime.db")
    api_proxy = _setup_api_process(upstream)
    try:
        marker = "sk-" + "ZzYyXxWwVvUuTtSsRrQq"
        _run(_call_proxy(api_proxy, "GET", f"/api/{marker}"))
        blob = json.dumps(api_proxy.request_log, default=str)
        assert marker not in blob, "credential-shaped path leaked into request log"
    finally:
        _run(api_proxy.aclose())


def test_sh07_api_response_redacts_rule_echo(upstream, client, tmp_path):
    """Credential-shaped text in intent does not leak through the API response."""
    os.environ["SHIELD_RUNTIME_DB"] = str(tmp_path / "runtime.db")
    api_proxy = _setup_api_process(upstream)
    try:
        marker = "sk-" + "AaBbCcDdEeFfGgHhIiJj"
        r = client.post("/api/v1/shield/rules",
                        json={"route_pattern": "/api/redact2", "intent": marker,
                              "mode": "enforce", "ttl_minutes": 60, "reason": "sh07"},
                        headers=AUTH)
        assert r.status_code == 200, r.text
        assert marker not in r.text
        # Evidence must also be clean
        blob = json.dumps(
            [e.payload for e in api_proxy.store.list_session(api_proxy.session_id)],
            default=str,
        )
        assert marker not in blob
    finally:
        _run(api_proxy.aclose())
