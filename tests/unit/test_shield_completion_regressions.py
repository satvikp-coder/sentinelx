"""Regression coverage for the independently reproduced recovery failures."""
from datetime import UTC, datetime
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from apps.api import routes
from apps.api.main import _rate_tokens, app
from sentinelx.common_schemas import ShieldMode
from sentinelx.shield.runtime import canonical_rule_hash

AUTH = {"Authorization": "Bearer sentinelx-demo-local-only"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD_RUNTIME_DB", str(tmp_path / "runtime.db"))
    monkeypatch.setenv("SHIELD_EVIDENCE_DB", str(tmp_path / "evidence.db"))
    routes._reset_shield_singletons()
    _rate_tokens.clear()
    for value in vars(routes.store).values():
        if isinstance(value, (dict, list)):
            value.clear()
    routes._SESSION_STATE.clear()
    routes._SESSION_SCENARIOS.clear()
    # Existing versions hardcode this path; isolate only the database location.
    original = routes.sqlite3.connect

    def connect(path, *args, **kwargs):
        from pathlib import Path
        if Path(path).name == "evidence.db" and Path(path).parent.name == "shield":
            path = tmp_path / "evidence.db"
        return original(path, *args, **kwargs)

    monkeypatch.setattr(routes.sqlite3, "connect", connect)
    with TestClient(app) as c:
        yield c
    routes._reset_shield_singletons()


def proposal(client, mode="enforce"):
    sid = client.post("/api/v1/sessions", headers=AUTH, json={
        "scenario_id": "S1", "lab": "synthetic", "arm": "A",
    }).json()["id"]
    response = client.post("/api/v1/shield/rules", headers=AUTH, json={
        "route_pattern": "/review-regression", "intent": "recon", "mode": mode,
        "ttl_minutes": 2, "reason": "Synthetic regression",
    })
    assert response.status_code == 200, response.text
    return sid, response.json()["rule_id"]


def approval(client, sid, rid, decision="approve"):
    response = client.post("/api/v1/approvals", headers=AUTH, json={
        "session_id": sid, "action_id": rid, "tool": "shield_rule", "arguments": {},
        "reviewer": "reviewer", "rationale": "Synthetic regression", "decision": decision,
    })
    assert response.status_code == 200, response.text


def activate(client, sid, rid):
    return client.post(f"/api/v1/shield/rules/{rid}/approve", headers=AUTH, json={
        "session_id": sid, "action_id": rid, "tool": "shield_rule",
        "rationale": "Synthetic regression",
    })


def test_restart_projection_discovers_durable_active_rule(client):
    sid, rid = proposal(client)
    approval(client, sid, rid)
    assert activate(client, sid, rid).status_code == 200
    routes.store.shield_rules.clear()
    response = client.get("/api/v1/shield/rules", headers=AUTH)
    assert response.status_code == 200
    assert any(r["rule_id"] == rid and r["state"] == "ACTIVE" for r in response.json())


def test_equal_timestamp_revocation_wins(client, monkeypatch):
    sid, rid = proposal(client)
    stamp = datetime.now(UTC)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return stamp

    monkeypatch.setattr(routes, "datetime", Clock)
    approval(client, sid, rid)
    approval(client, sid, rid, "revoke")
    assert activate(client, sid, rid).status_code == 400


def test_api_monitor_mode_survives_publication(client):
    sid, rid = proposal(client, "monitor")
    approval(client, sid, rid)
    assert activate(client, sid, rid).status_code == 200
    rule, _ = routes._shield_runtime().get(rid)
    assert rule.mode == ShieldMode.MONITOR


def test_runtime_hash_binds_mode(client):
    _, rid = proposal(client)
    rule = routes._shield_proxy().rules.get_rule(rid)
    assert canonical_rule_hash(rule) != canonical_rule_hash(
        rule.model_copy(update={"mode": ShieldMode.MONITOR})
    )


def test_failed_evidence_and_compensation_never_publish_active(client, monkeypatch):
    sid, rid = proposal(client)
    approval(client, sid, rid)

    def fail(*args, **kwargs):
        raise OSError("Synthetic unavailable evidence/status writer")

    monkeypatch.setattr(routes, "_shield_evidence_append", fail)
    monkeypatch.setattr(routes._shield_runtime(), "set_status", fail)
    assert activate(client, sid, rid).status_code == 503
    assert not any(r.id == rid for r in routes._shield_runtime().active_rules())


def test_request_id_not_retained_raw(client):
    proposal(client)
    proxy = routes._shield_proxy()
    marker = "sk-" + "Q" * 35
    proxy._log({"path": "/health", "request_id": marker, "method": "GET"})
    assert marker not in str(proxy.stats())


def test_authoritative_approval_sequence_is_monotonic(client):
    sid, rid = proposal(client)
    approval(client, sid, rid)
    approval(client, sid, rid, "revoke")
    # Exact DTOs remain valid; ordering metadata must not break the gateway.
    for record in routes._SESSION_STATE[UUID(sid)]["approvals"]:
        routes.ApprovalRecord.model_validate(record)


def test_activation_evidence_failure_rolls_back_same_transaction(client, monkeypatch):
    sid, rid = proposal(client)
    approval(client, sid, rid)
    runtime = routes._shield_runtime()
    original = runtime._append_event

    def fail(kind, payload):
        if kind == "SHIELD_RULE_ACTIVATED":
            raise OSError("synthetic activation evidence unavailable")
        return original(kind, payload)

    monkeypatch.setattr(runtime, "_append_event", fail)
    assert activate(client, sid, rid).status_code == 503
    assert runtime.get(rid)[1] == "PROPOSED"
    assert not runtime.active_rules()


def test_uncommitted_activation_not_visible_to_reader(client, monkeypatch, tmp_path):
    from sentinelx.shield.runtime import ShieldRuntimeStore

    sid, rid = proposal(client)
    approval(client, sid, rid)
    writer = routes._shield_runtime()
    reader = ShieldRuntimeStore(writer.path)
    original = writer._append_event
    observations = []

    def observe(kind, payload):
        if kind == "SHIELD_RULE_ACTIVATED":
            observations.append(reader.get(rid)[1])
        return original(kind, payload)

    monkeypatch.setattr(writer, "_append_event", observe)
    try:
        assert activate(client, sid, rid).status_code == 200
        assert observations == ["PROPOSED"]
        assert reader.get(rid)[1] == "ACTIVE"
        assert writer.evidence.verify_chain("shield-runtime-v2").ok
    finally:
        reader.close()


def test_durable_revocation_survives_runtime_reopen(client):
    from sentinelx.shield.runtime import ShieldRuntimeStore

    sid, rid = proposal(client)
    approval(client, sid, rid)
    approval(client, sid, rid, "revoke")
    old = routes._shield_runtime()
    routes._SHIELD_RUNTIME = ShieldRuntimeStore(old.path)
    try:
        assert activate(client, sid, rid).status_code == 400
    finally:
        old.close()


def test_gate_digest_binds_mode_and_expiry(client):
    from datetime import timedelta

    from sentinelx.shield.rules import rule_hash

    _, rid = proposal(client)
    rule = routes._shield_runtime().get(rid)[0]
    assert rule_hash(rule) != rule_hash(rule.model_copy(update={"mode": ShieldMode.MONITOR}))
    assert rule_hash(rule) != rule_hash(rule.model_copy(update={
        "expires_at": rule.expires_at + timedelta(minutes=1),
    }))


def test_sse_replay_boundary_does_not_drop_or_duplicate(monkeypatch):
    import asyncio

    from apps.api import events
    from apps.api.schemas import EventKind

    async def run():
        bus = events.EventStream()
        monkeypatch.setattr(events, "event_stream", bus)
        await bus.append(EventKind.SHIELD_RULE_ADDED, {"rule_id": "replay"})

        class Request:
            async def is_disconnected(self):
                return False

        stream = events.sse_stream_generator(Request())
        first = await anext(stream)
        await bus.append(EventKind.SHIELD_RULE_ADDED, {"rule_id": "boundary"})
        second = await asyncio.wait_for(anext(stream), 1)
        await stream.aclose()
        assert '"replay"' in first and "id: 1" in first
        assert '"boundary"' in second and "id: 2" in second
        assert not bus._subscribers

    asyncio.run(run())


def test_client_scoped_health_block_cannot_skip_benign_gate(client, monkeypatch):
    monkeypatch.setenv("SHIELD_LAB_MODE", "1")
    sid, _ = proposal(client)
    r = client.post("/api/v1/shield/rules", headers=AUTH, json={
        "route_pattern": "/health", "intent": "RECON", "mode": "enforce",
        "reason": "Synthetic regression", "client_id": "local-demo-client",
    })
    assert r.status_code == 200
    rid = r.json()["rule_id"]
    approval(client, sid, rid)
    assert activate(client, sid, rid).status_code == 400
    assert routes._shield_runtime().get(rid)[1] == "PROPOSED"


def test_corrupt_durable_row_never_falls_back_to_cached_active_rule(client):
    sid, rid = proposal(client)
    approval(client, sid, rid)
    assert activate(client, sid, rid).status_code == 200
    proxy = routes._shield_proxy()
    assert not proxy._match_rule("client", "GET", "/review-regression", {}, {}).allowed
    routes._shield_runtime()._conn.execute(
        "UPDATE shield_runtime_rules SET rule_hash='corrupt' WHERE rule_id=?", (rid,),
    )
    assert proxy._match_rule("client", "GET", "/review-regression", {}, {}).allowed


def test_process_death_during_publication_does_not_publish_half_commit(client):
    import subprocess
    import sys
    from pathlib import Path

    sid, rid = proposal(client)
    approval(client, sid, rid)
    runtime = routes._shield_runtime()
    entry = routes.store.shield_rules[UUID(rid)]
    subject = routes._shield_approval_subject(rid, routes._shield_rule_digest(entry))
    _, sequence = runtime.latest_approval(sid, subject)
    script = '''import os,sys
sys.path.insert(0,sys.argv[1])
from sentinelx.shield.runtime import ShieldRuntimeStore
from sentinelx.common_schemas import ShieldStatus
runtime=ShieldRuntimeStore(sys.argv[2])
rule=runtime.get(sys.argv[3])[0].model_copy(update={"status":ShieldStatus.ACTIVE})
original=runtime.upsert
def interrupted(*args,**kwargs):
    original(*args,**kwargs)
    os._exit(19)
runtime.upsert=interrupted
runtime.publish_activation(rule,session_id=sys.argv[4],subject=sys.argv[5],
    approval_seq=int(sys.argv[6]),gate_hash="synthetic-crash-test")
'''
    result = subprocess.run([sys.executable, "-c", script,
        str(Path(__file__).resolve().parents[2]), str(runtime.path), rid, sid, subject,
        str(sequence)], capture_output=True, timeout=15)
    assert result.returncode == 19
    assert runtime.get(rid)[1] == "PROPOSED"
    assert runtime.active_rules() == []
    assert runtime.evidence.verify_chain("shield-runtime-v2").ok


def test_public_durable_evidence_is_authenticated_and_survives_projection_loss(client):
    sid, rid = proposal(client)
    approval(client, sid, rid)
    assert activate(client, sid, rid).status_code == 200
    routes.store.shield_rules.clear()
    assert client.get("/api/v1/shield/evidence").status_code == 401
    response = client.get("/api/v1/shield/evidence", headers=AUTH)
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] and body["chain_status"] == "OK"
    assert any(e["kind"] == "SHIELD_RULE_ACTIVATED" and e["payload"]["rule_id"] == rid
               for e in body["events"])


def test_arbitrary_short_request_markers_are_not_telemetry(client):
    from sentinelx.shield.recorder import telemetry_path

    marker = "plum!door"
    assert marker not in telemetry_path("/api/" + marker + "?token=" + marker)
    proposal(client)
    proxy = routes._shield_proxy()
    proxy._log({"path": "/" + marker, "request_id": marker, "method": marker})
    assert marker not in str(proxy.stats())
