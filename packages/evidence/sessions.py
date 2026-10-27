"""Session lifecycle: creation (idempotent) and the permission-checked state machine.

    CREATED -> READY -> RUNNING -> { PAUSED, COMPLETED, FAILED, CANCELLED }
    PAUSED -> RUNNING (explicit authorized resume) | CANCELLED
    COMPLETED | FAILED -> ANALYZED -> EXPORTED
    CANCELLED is terminal. CREATED/READY may also go to CANCELLED.

A BLOCKED action is an evidence EVENT, never a session state. Every real transition writes one
audit row and one evidence event in the same transaction as the state change. Repeating a
transition (target == current state) is a no-op that writes nothing.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime

from sentinelx.common_schemas import (
    Actor,
    ActorRole,
    Arm,
    AuditRecord,
    EvidenceState,
    SessionKind,
    SessionRecord,
    SessionState,
    format_utc,
)

from .db import transaction
from .records import RecordStore, row_to_session
from .store import EvidenceStore

S = SessionState

LEGAL_TRANSITIONS: dict[SessionState, set[SessionState]] = {
    S.CREATED: {S.READY, S.CANCELLED},
    S.READY: {S.RUNNING, S.CANCELLED},
    S.RUNNING: {S.PAUSED, S.COMPLETED, S.FAILED, S.CANCELLED},
    S.PAUSED: {S.RUNNING, S.CANCELLED},
    S.COMPLETED: {S.ANALYZED},
    S.FAILED: {S.ANALYZED},
    S.CANCELLED: set(),
    S.ANALYZED: {S.EXPORTED},
    S.EXPORTED: set(),
}
_ENDING = {S.COMPLETED, S.FAILED, S.CANCELLED}


class SessionError(Exception):
    """Base class for session lifecycle errors."""


class SessionNotFound(SessionError):
    pass


class IllegalTransition(SessionError):
    def __init__(self, from_state: SessionState, to_state: SessionState) -> None:
        self.from_state, self.to_state = from_state, to_state
        super().__init__(f"illegal session transition {from_state.value} -> {to_state.value}")


class PermissionDenied(SessionError):
    def __init__(self, actor: Actor, from_state: SessionState, to_state: SessionState) -> None:
        self.actor = actor
        super().__init__(
            f"actor {actor.id} ({actor.role.value}) may not move {from_state.value} -> "
            f"{to_state.value}"
        )


def _permitted(actor: Actor, src: SessionState, dst: SessionState) -> bool:
    role = actor.role
    if role is ActorRole.AGENT:  # model-driven code may only request a pause
        return (src, dst) == (S.RUNNING, S.PAUSED)
    if (src, dst) == (S.PAUSED, S.RUNNING):  # resume: a human decision
        return role is ActorRole.OPERATOR
    return role in (ActorRole.OPERATOR, ActorRole.SYSTEM)


def _stamp(dt: datetime | None = None) -> str:
    return format_utc(dt or datetime.now(UTC))


class SessionService:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self.records = RecordStore(conn)
        self.evidence = EvidenceStore(conn)

    def get(self, session_id: str) -> SessionRecord:
        row = self.conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        if row is None:
            raise SessionNotFound(session_id)
        return row_to_session(row)

    def create(
        self,
        kind: SessionKind,
        policy_version: str,
        actor: Actor,
        *,
        scenario_id: str | None = None,
        target_id: str | None = None,
        arm: Arm | None = None,
        model: str | None = None,
        provider: str | None = None,
        fixture_version: str | None = None,
        idempotency_key: str | None = None,
        session_id: str | None = None,
    ) -> tuple[SessionRecord, bool]:
        """Create a session, or return the existing one for the same idempotency_key.

        Returns (session, created). ``created`` is False when an existing session was returned.
        """
        with transaction(self.conn):
            if idempotency_key is not None:
                row = self.conn.execute(
                    "SELECT * FROM sessions WHERE idempotency_key = ?", (idempotency_key,)
                ).fetchone()
                if row is not None:
                    return row_to_session(row), False
            session = SessionRecord(
                id=session_id or f"ses_{uuid.uuid4().hex}",
                kind=kind,
                scenario_id=scenario_id,
                target_id=target_id,
                arm=arm,
                state=S.CREATED,
                model=model,
                provider=provider,
                created_at=datetime.now(UTC),
                policy_version=policy_version,
                fixture_version=fixture_version,
                idempotency_key=idempotency_key,
            )
            self.records.insert(session)
            self._record(session.id, actor, "session.created", None, S.CREATED)
        return session, True

    def transition(self, session_id: str, to_state: SessionState, actor: Actor) -> SessionRecord:
        with transaction(self.conn):
            current = self.get(session_id)
            if current.state is to_state:
                return current  # idempotent no-op
            if to_state not in LEGAL_TRANSITIONS[current.state]:
                raise IllegalTransition(current.state, to_state)
            if not _permitted(actor, current.state, to_state):
                raise PermissionDenied(actor, current.state, to_state)
            now = _stamp()
            sets, args = ["state = ?"], [to_state.value]
            if to_state is S.RUNNING and current.started_at is None:
                sets.append("started_at = ?")
                args.append(now)
            if to_state in _ENDING:
                sets.append("ended_at = ?")
                args.append(now)
            self.conn.execute(
                f"UPDATE sessions SET {', '.join(sets)} WHERE id = ?",  # noqa: S608 (static)
                [*args, session_id],
            )
            self._record(session_id, actor, "session.transition", current.state, to_state)
        return self.get(session_id)

    def _record(
        self,
        session_id: str,
        actor: Actor,
        action: str,
        from_state: SessionState | None,
        to_state: SessionState,
    ) -> None:
        now = datetime.now(UTC)
        self.records.insert(
            AuditRecord(
                session_id=session_id,
                actor_id=actor.id,
                actor_role=actor.role,
                action=action,
                from_state=from_state,
                to_state=to_state,
                timestamp=now,
            )
        )
        self.evidence.append(
            session_id,
            action,
            EvidenceState.OBSERVED,
            "session_state_machine",
            {
                "from_state": from_state.value if from_state else None,
                "to_state": to_state.value,
                "actor_id": actor.id,
                "actor_role": actor.role.value,
            },
            timestamp=now,
        )
