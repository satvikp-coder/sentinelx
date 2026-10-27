import sqlite3
from itertools import product
from pathlib import Path

import pytest

from sentinelx.common_schemas import Actor, ActorRole, SessionKind, SessionState
from sentinelx.evidence.db import connect, migrate
from sentinelx.evidence.sessions import (
    LEGAL_TRANSITIONS,
    IllegalTransition,
    PermissionDenied,
    SessionNotFound,
    SessionService,
)

S = SessionState
OP = Actor(id="op", role=ActorRole.OPERATOR)
SYS = Actor(id="sys", role=ActorRole.SYSTEM)
AGENT = Actor(id="agent", role=ActorRole.AGENT)

# A legal path from CREATED to each state, used to reach states honestly.
PATHS: dict[SessionState, list[SessionState]] = {
    S.CREATED: [],
    S.READY: [S.READY],
    S.RUNNING: [S.READY, S.RUNNING],
    S.PAUSED: [S.READY, S.RUNNING, S.PAUSED],
    S.COMPLETED: [S.READY, S.RUNNING, S.COMPLETED],
    S.FAILED: [S.READY, S.RUNNING, S.FAILED],
    S.CANCELLED: [S.CANCELLED],
    S.ANALYZED: [S.READY, S.RUNNING, S.COMPLETED, S.ANALYZED],
    S.EXPORTED: [S.READY, S.RUNNING, S.COMPLETED, S.ANALYZED, S.EXPORTED],
}


@pytest.fixture()
def conn(tmp_path: Path) -> sqlite3.Connection:
    c = connect(tmp_path / "s.db")
    migrate(c)
    return c


@pytest.fixture()
def svc(conn: sqlite3.Connection) -> SessionService:
    return SessionService(conn)


def session_in(svc: SessionService, state: SessionState, key: str | None = None) -> str:
    s, _ = svc.create(SessionKind.AGENT_RUN, "p1", SYS, idempotency_key=key)
    for step in PATHS[state]:
        svc.transition(s.id, step, OP)
    assert svc.get(s.id).state is state
    return s.id


def test_table_matches_spec() -> None:
    assert LEGAL_TRANSITIONS[S.RUNNING] == {S.PAUSED, S.COMPLETED, S.FAILED, S.CANCELLED}
    assert LEGAL_TRANSITIONS[S.CANCELLED] == set()
    assert S.RUNNING in LEGAL_TRANSITIONS[S.PAUSED]


@pytest.mark.parametrize(
    ("src", "dst"),
    [(a, b) for a, targets in LEGAL_TRANSITIONS.items() for b in sorted(targets)],
)
def test_every_legal_transition_works(svc: SessionService, src, dst) -> None:
    sid = session_in(svc, src)
    assert svc.transition(sid, dst, OP).state is dst


ILLEGAL = [
    (a, b) for a, b in product(SessionState, SessionState)
    if a != b and b not in LEGAL_TRANSITIONS[a]
]


@pytest.mark.parametrize(("src", "dst"), ILLEGAL)
def test_every_illegal_transition_raises(svc: SessionService, src, dst) -> None:
    sid = session_in(svc, src)
    with pytest.raises(IllegalTransition) as exc:
        svc.transition(sid, dst, OP)
    assert exc.value.from_state is src and exc.value.to_state is dst
    assert svc.get(sid).state is src


def test_repeating_a_transition_is_a_noop(svc: SessionService, conn) -> None:
    sid = session_in(svc, S.READY)
    svc.transition(sid, S.RUNNING, OP)
    audits = conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
    events = len(svc.evidence.list_session(sid))
    again = svc.transition(sid, S.RUNNING, OP)
    assert again.state is S.RUNNING
    assert conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0] == audits
    assert len(svc.evidence.list_session(sid)) == events


def test_cancelled_is_terminal(svc: SessionService) -> None:
    sid = session_in(svc, S.CANCELLED)
    for dst in SessionState:
        if dst is S.CANCELLED:
            continue
        with pytest.raises(IllegalTransition):
            svc.transition(sid, dst, OP)
    assert svc.transition(sid, S.CANCELLED, OP).state is S.CANCELLED  # idempotent


def test_resume_requires_authorized_operator(svc: SessionService) -> None:
    sid = session_in(svc, S.PAUSED)
    for actor in (AGENT, SYS):
        with pytest.raises(PermissionDenied):
            svc.transition(sid, S.RUNNING, actor)
    assert svc.get(sid).state is S.PAUSED
    assert svc.transition(sid, S.RUNNING, OP).state is S.RUNNING


def test_agent_may_only_request_pause(svc: SessionService) -> None:
    sid = session_in(svc, S.READY)
    with pytest.raises(PermissionDenied):
        svc.transition(sid, S.RUNNING, AGENT)
    svc.transition(sid, S.RUNNING, SYS)
    with pytest.raises(PermissionDenied):
        svc.transition(sid, S.COMPLETED, AGENT)
    with pytest.raises(PermissionDenied):
        svc.transition(sid, S.CANCELLED, AGENT)
    assert svc.transition(sid, S.PAUSED, AGENT).state is S.PAUSED


def test_transition_writes_audit_and_evidence_and_chain_verifies(svc: SessionService, conn) -> None:
    sid = session_in(svc, S.RUNNING)
    rows = conn.execute("SELECT * FROM audit WHERE session_id = ? ORDER BY id", (sid,)).fetchall()
    assert [(r["from_state"], r["to_state"]) for r in rows] == [
        (None, "CREATED"), ("CREATED", "READY"), ("READY", "RUNNING"),
    ]
    assert rows[-1]["actor_id"] == "op" and rows[-1]["actor_role"] == "OPERATOR"
    kinds = [e.kind for e in svc.evidence.list_session(sid)]
    assert kinds == ["session.created", "session.transition", "session.transition"]
    assert svc.evidence.verify_chain(sid).ok


def test_timestamps_set_on_run_and_end(svc: SessionService) -> None:
    sid = session_in(svc, S.RUNNING)
    assert svc.get(sid).started_at is not None and svc.get(sid).ended_at is None
    done = svc.transition(sid, S.COMPLETED, SYS)
    assert done.ended_at is not None


def test_unknown_session(svc: SessionService) -> None:
    with pytest.raises(SessionNotFound):
        svc.transition("ghost", S.READY, OP)


def test_failed_transition_leaves_no_partial_writes(svc: SessionService, conn) -> None:
    sid = session_in(svc, S.CREATED)
    before = conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
    with pytest.raises(IllegalTransition):
        svc.transition(sid, S.COMPLETED, OP)
    assert conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0] == before


def test_idempotent_session_creation(svc: SessionService, conn) -> None:
    a, created_a = svc.create(SessionKind.SCAN, "p1", SYS, idempotency_key="k-1")
    b, created_b = svc.create(SessionKind.SCAN, "p1", SYS, idempotency_key="k-1")
    assert created_a and not created_b and a.id == b.id
    assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1
    assert len(svc.evidence.list_session(a.id)) == 1
    c, created_c = svc.create(SessionKind.SCAN, "p1", SYS, idempotency_key="k-2")
    assert created_c and c.id != a.id
    d, created_d = svc.create(SessionKind.SCAN, "p1", SYS)
    e, created_e = svc.create(SessionKind.SCAN, "p1", SYS)
    assert created_d and created_e and d.id != e.id  # no key = no dedup
