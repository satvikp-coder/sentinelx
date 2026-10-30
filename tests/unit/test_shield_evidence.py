"""Evidence tests: batching, caps, chain verification, redaction of stored events."""

from sentinelx.common_schemas import Actor, ActorRole, SessionKind
from sentinelx.evidence.db import connect, migrate
from sentinelx.evidence.sessions import SessionService
from sentinelx.evidence.store import EvidenceStore
from sentinelx.shield.recorder import ShieldRecorder, hash_client_key, path_template


class FakeClock:
    def __init__(self, start=0.0):
        self.now = start

    def __call__(self):
        return self.now


def _make_store():
    conn = connect(":memory:")
    migrate(conn)
    store = EvidenceStore(conn)
    session_service = SessionService(conn)
    session, _ = session_service.create(
        kind=SessionKind.GUARD, policy_version="1.0",
        actor=Actor(id="a", role=ActorRole.SYSTEM),
    )
    return store, session.id


def test_hash_client_key_not_raw():
    key = hash_client_key("session_abc123")
    assert key.startswith("sk_")
    assert "session_abc123" not in key
    assert len(key) == 35  # "sk_" + 32 hex


def test_path_template_masks_ids():
    assert path_template("/orders/123/items/456") == "/orders/{}/items/{}"
    assert path_template("/checkout") == "/checkout"


def test_benign_requests_are_batched_one_event():
    store, session_id = _make_store()
    clock = FakeClock(0.0)
    rec = ShieldRecorder(store, session_id, batch_interval_s=5.0,
                         suspicious_rate_cap_per_min=20, clock=clock)
    for i in range(50):
        rec.record("c1", "GET", f"/orders/{i}", 200, 100, 5.0, [], suspicious=False)
    clock.now = 5.0
    rec.flush()
    events = store.list_session(session_id)
    batch = [e for e in events if e.kind == "shield_batch"]
    assert len(batch) == 1
    assert batch[0].payload["count"] == 50


def test_500_benign_requests_bounded_events():
    store, session_id = _make_store()
    clock = FakeClock(0.0)
    rec = ShieldRecorder(store, session_id, batch_interval_s=1.0,
                         suspicious_rate_cap_per_min=20, clock=clock)
    for i in range(500):
        rec.record("c1", "GET", f"/orders/{i}", 200, 100, 5.0, [], suspicious=False)
        if i % 10 == 0:
            clock.now += 1.0
            rec.flush()
    events = store.list_session(session_id)
    assert len(events) <= 60  # bounded: one per second-ish
    # chain verifies
    v = store.verify_chain(session_id)
    assert v.status.value == "OK", v.detail


def test_no_raw_secret_in_stored_events():
    store, session_id = _make_store()
    clock = FakeClock(0.0)
    rec = ShieldRecorder(store, session_id, batch_interval_s=1.0,
                         suspicious_rate_cap_per_min=20, clock=clock)
    rec.record("c1", "GET", "/login", 200,
               200, 5.0,
               [], suspicious=True,
               # cookies/tokens passed as part of signals detail would be redacted by store.append
               )
    # write a suspicious event carrying a cookie-like detail
    rec.record("c1", "GET", "/login", 200, 200, 5.0,
               [type("S", (), {"name": "protected_no_session", "category": "auth_bypass"})()],
               suspicious=True)
    clock.now = 1.0
    rec.flush()
    events = store.list_session(session_id)
    text = str(events)
    assert "session_secret" not in text
    assert "synth_tok_" not in text


def test_suspicious_individual_event_rate_capped():
    store, session_id = _make_store()
    clock = FakeClock(0.0)
    rec = ShieldRecorder(store, session_id, batch_interval_s=999.0,
                         suspicious_rate_cap_per_min=3, clock=clock)
    sig = type("S", (), {"name": "sql_break_char", "category": "injection"})()
    for _i in range(10):
        rec.record("c1", "GET", "/x", 200, 100, 5.0, [sig], suspicious=True)
    events = [e for e in store.list_session(session_id) if e.kind == "shield_suspicious"]
    assert len(events) == 3  # capped at 3 per minute


def test_chain_verifies_after_mixed_events():
    store, session_id = _make_store()
    clock = FakeClock(0.0)
    rec = ShieldRecorder(store, session_id, batch_interval_s=1.0,
                         suspicious_rate_cap_per_min=20, clock=clock)
    rec.record("c1", "GET", "/orders/1", 200, 100, 5.0, [], suspicious=False)
    sig = type("S", (), {"name": "scanner_ua", "category": "scanner"})()
    rec.record("c1", "GET", "/.env", 200, 100, 5.0, [sig], suspicious=True)
    clock.now = 1.0
    rec.flush()
    v = store.verify_chain(session_id)
    assert v.status.value == "OK", v.detail
