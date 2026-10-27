import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentinelx.common_schemas import (
    AttackIntent,
    EvidenceState,
    IncidentFinding,
    SessionKind,
    SessionRecord,
    SessionState,
)
from sentinelx.evidence.db import connect, migrate
from sentinelx.evidence.records import RecordStore
from sentinelx.evidence.refs import UnknownEventReference, assert_citations_exist
from sentinelx.evidence.store import GENESIS_HASH, ChainStatus, EvidenceStore


@pytest.fixture()
def conn(tmp_path: Path) -> sqlite3.Connection:
    c = connect(tmp_path / "e.db")
    migrate(c)
    return c


def make_session(conn: sqlite3.Connection, sid: str) -> None:
    RecordStore(conn).insert(
        SessionRecord(
            id=sid, kind=SessionKind.SCAN, state=SessionState.CREATED,
            created_at=datetime.now(UTC), policy_version="p1",
        )
    )


@pytest.fixture()
def store(conn: sqlite3.Connection) -> EvidenceStore:
    make_session(conn, "s1")
    return EvidenceStore(conn)


def fill(store: EvidenceStore, sid: str = "s1", n: int = 5):
    return [
        store.append(sid, "obs", EvidenceState.OBSERVED, "test", {"i": i}) for i in range(1, n + 1)
    ]


def test_append_builds_chain_and_verifies(store: EvidenceStore) -> None:
    events = fill(store)
    assert [e.seq for e in events] == [1, 2, 3, 4, 5]
    assert events[0].previous_hash == GENESIS_HASH
    for a, b in zip(events, events[1:], strict=False):
        assert b.previous_hash == a.event_hash
    res = store.verify_chain("s1")
    assert res.ok and res.status is ChainStatus.OK
    assert res.first_broken_event_id is None and res.events_checked == 5


def test_get_and_list(store: EvidenceStore) -> None:
    events = fill(store, n=3)
    assert store.get(events[1].id) == events[1]
    assert store.get("nope") is None
    assert store.list_session("s1") == events


def test_empty_session_verifies(store: EvidenceStore) -> None:
    assert store.verify_chain("s1").ok


def test_no_update_or_delete_api() -> None:
    public = {n for n in dir(EvidenceStore) if not n.startswith("_")}
    assert not any(n.startswith(("update", "delete", "remove", "edit", "set")) for n in public)


def test_hash_is_reimplementable(store: EvidenceStore) -> None:
    import hashlib

    ev = fill(store, n=1)[0]
    doc = {
        "schema_version": ev.schema_version, "id": ev.id, "session_id": ev.session_id,
        "seq": ev.seq, "kind": ev.kind,
        "timestamp_utc": ev.timestamp_utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "parent_event_id": ev.parent_event_id, "state": ev.state.value, "source": ev.source,
        "payload": ev.payload, "previous_hash": ev.previous_hash,
    }
    text = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert hashlib.sha256(text.encode("utf-8") + GENESIS_HASH.encode("ascii")).hexdigest() == (
        ev.event_hash
    )


def test_modified_event_detected_and_located(store: EvidenceStore, conn) -> None:
    events = fill(store)
    conn.execute("UPDATE events SET payload = ? WHERE id = ?", ('{"i": 999}', events[2].id))
    res = store.verify_chain("s1")
    assert not res.ok and res.status is ChainStatus.MODIFIED
    assert res.first_broken_event_id == events[2].id and res.first_broken_seq == 3


def test_modified_state_and_hash_rewrite_detected(store: EvidenceStore, conn) -> None:
    events = fill(store)
    conn.execute("UPDATE events SET state = 'VERIFIED' WHERE id = ?", (events[1].id,))
    res = store.verify_chain("s1")
    assert res.status is ChainStatus.MODIFIED and res.first_broken_event_id == events[1].id


def test_attacker_who_rehashes_one_event_is_caught_at_the_link(
    store: EvidenceStore, conn
) -> None:
    from sentinelx.evidence.store import compute_event_hash

    events = fill(store)
    forged = events[2].model_copy(update={"payload": {"i": 777}})
    new_hash = compute_event_hash(forged)
    conn.execute(
        "UPDATE events SET payload = ?, event_hash = ? WHERE id = ?",
        (json.dumps({"i": 777}), new_hash, events[2].id),
    )
    res = store.verify_chain("s1")
    assert not res.ok and res.first_broken_event_id == events[2].id


def test_deleted_middle_row_detected_as_missing(store: EvidenceStore, conn) -> None:
    events = fill(store)
    conn.execute("DELETE FROM events WHERE id = ?", (events[2].id,))
    res = store.verify_chain("s1")
    assert res.status is ChainStatus.MISSING
    assert res.first_broken_event_id == events[3].id  # first event after the gap


def test_deleted_first_row_detected(store: EvidenceStore, conn) -> None:
    events = fill(store)
    conn.execute("DELETE FROM events WHERE id = ?", (events[0].id,))
    assert store.verify_chain("s1").status is ChainStatus.MISSING


def test_truncated_tail_needs_external_anchor(store: EvidenceStore, conn) -> None:
    events = fill(store)
    conn.execute("DELETE FROM events WHERE id = ?", (events[4].id,))
    assert store.verify_chain("s1").ok  # known limitation, documented
    res = store.verify_chain("s1", expected_last_hash=events[4].event_hash)
    assert res.status is ChainStatus.MISSING


def test_reordered_rows_detected(store: EvidenceStore, conn) -> None:
    events = fill(store)
    conn.execute("UPDATE events SET seq = 99 WHERE id = ?", (events[1].id,))
    conn.execute("UPDATE events SET seq = 2 WHERE id = ?", (events[2].id,))
    conn.execute("UPDATE events SET seq = 3 WHERE id = ?", (events[1].id,))
    res = store.verify_chain("s1")
    assert res.status is ChainStatus.REORDERED
    assert res.first_broken_event_id in {events[1].id, events[2].id}


def test_sessions_have_independent_chains(store: EvidenceStore, conn) -> None:
    make_session(conn, "s2")
    a = fill(store, "s1", 3)
    b = fill(store, "s2", 3)
    assert a[0].previous_hash == b[0].previous_hash == GENESIS_HASH
    assert a[0].event_hash != b[0].event_hash
    conn.execute("UPDATE events SET payload = '{\"i\": 5}' WHERE id = ?", (a[1].id,))
    assert not store.verify_chain("s1").ok
    assert store.verify_chain("s2").ok


def test_append_redacts_secrets(store: EvidenceStore) -> None:
    ev = store.append(
        "s1", "http", EvidenceState.OBSERVED, "t",
        {"headers": {"Authorization": "Bearer abcdefgh12345678"}, "note": "ok"},
    )
    assert "abcdefgh12345678" not in json.dumps(ev.payload)
    assert ev.payload["note"] == "ok"
    assert store.verify_chain("s1").ok


def test_append_requires_existing_session(store: EvidenceStore) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        store.append("ghost", "k", EvidenceState.OBSERVED, "t", {})


def test_resolve_refs_catches_fabricated_ids(store: EvidenceStore, conn) -> None:
    make_session(conn, "s2")
    real = fill(store, "s1", 2)
    other = fill(store, "s2", 1)
    ids = [real[0].id, "evt_fabricated", other[0].id]
    assert store.resolve_refs(ids, "s1") == ["evt_fabricated", other[0].id]
    assert store.resolve_refs([real[0].id, real[1].id], "s1") == []


def test_parent_event_must_exist(store: EvidenceStore) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        store.append("s1", "k", EvidenceState.OBSERVED, "t", {}, parent_event_id="evt_nope")


def test_citation_helper_rejects_nonexistent_events(store: EvidenceStore) -> None:
    real = fill(store, n=2)
    ok_finding = IncidentFinding(
        incident_id="i", finding="f", evidence_event_ids=[real[0].id], confidence=0.5,
        observed=[], inferred=[], recommended_mitigations=[],
    )
    assert_citations_exist(store, "s1", ok_finding)
    bad_intent = AttackIntent(
        id="a", session_ref="s1", intent="RECON", summary="s",
        cited_event_ids=[real[0].id, "evt_made_up"], confidence=0.2,
    )
    with pytest.raises(UnknownEventReference) as exc:
        assert_citations_exist(store, "s1", bad_intent)
    assert exc.value.missing == ["evt_made_up"]
