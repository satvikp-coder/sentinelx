"""Demo: create a session, append 5 events, verify, tamper with one row, verify again."""

import tempfile
from pathlib import Path

from sentinelx.common_schemas import Actor, ActorRole, EvidenceState, SessionKind
from sentinelx.evidence.db import connect, migrate
from sentinelx.evidence.sessions import SessionService


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        conn = connect(Path(tmp) / "demo.db")
        try:
            migrate(conn)
            svc = SessionService(conn)
            actor = Actor(id="demo", role=ActorRole.SYSTEM)
            session, _ = svc.create(SessionKind.SCAN, "demo-policy", actor)
            for i in range(1, 6):
                svc.evidence.append(
                    session.id, "demo.event", EvidenceState.OBSERVED, "demo", {"n": i}
                )
            events = svc.evidence.list_session(session.id)
            print(f"session {session.id}: {len(events)} events (session.created + 5 appended)")
            print("verify (clean)   :", svc.evidence.verify_chain(session.id))
            target = events[3]
            conn.execute("UPDATE events SET payload = ? WHERE id = ?", ('{"n": 999}', target.id))
            print(f"tampered row     : seq {target.seq}, id {target.id}")
            result = svc.evidence.verify_chain(session.id)
            print("verify (tampered):", result)
            assert result.first_broken_event_id == target.id
        finally:
            conn.close()


if __name__ == "__main__":
    main()
