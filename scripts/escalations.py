"""List, acknowledge, or resolve EscalationTickets.

Usage:
  python scripts/escalations.py list [--db ...]
  python scripts/escalations.py ack <ticket_id> [--db ...]
  python scripts/escalations.py resolve <ticket_id> --reviewer NAME --decision approve|reject
      --rationale "..." [--db ...]
"""

import argparse
import json
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinelx.common_schemas import ApprovalDecision, ApprovalRecord, EscalationStatus  # noqa: E402
from sentinelx.evidence.db import connect, migrate  # noqa: E402
from sentinelx.evidence.records import RecordStore  # noqa: E402

DEFAULT_DB = ROOT / "evaluations" / "fix_runs" / "fix.sqlite"


def _load(conn, ticket_id: str) -> dict:
    row = conn.execute("SELECT body FROM escalations WHERE id = ?", (ticket_id,)).fetchone()
    if row is None:
        raise ValueError(f"no such escalation ticket: {ticket_id!r}")
    return json.loads(row["body"])


def _set_status(conn, ticket_id: str, status: EscalationStatus) -> None:
    body = _load(conn, ticket_id)
    body["status"] = status.value
    conn.execute("UPDATE escalations SET body = ? WHERE id = ?",
                (json.dumps(body, sort_keys=True), ticket_id))
    conn.commit()


def _list(conn) -> None:
    rows = conn.execute("SELECT id, body FROM escalations ORDER BY id").fetchall()
    if not rows:
        print("no escalation tickets")
        return
    for row in rows:
        body = json.loads(row["body"])
        print(f"{row['id']}  [{body['status']}]  finding={body['finding_id']}")
        print(f"    {body['explanation']}")
        for i, opt in enumerate(body["options"], 1):
            print(f"      {i}. {opt}")


def _ack(conn, ticket_id: str) -> None:
    _set_status(conn, ticket_id, EscalationStatus.ACKNOWLEDGED)
    print(f"{ticket_id} -> ACKNOWLEDGED")


def _resolve(conn, ticket_id: str, reviewer: str, decision: str, rationale: str) -> None:
    _load(conn, ticket_id)  # raises a clear error if the ticket does not exist
    RecordStore(conn).insert(ApprovalRecord(
        id=f"appr_{uuid.uuid4().hex[:12]}", subject_type="escalation", subject_id=ticket_id,
        reviewer=reviewer, decision=ApprovalDecision(decision), rationale=rationale,
        timestamp=datetime.now(UTC)))
    _set_status(conn, ticket_id, EscalationStatus.RESOLVED)
    print(f"{ticket_id} -> RESOLVED ({decision} by {reviewer})")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("action", choices=["list", "ack", "resolve"])
    ap.add_argument("ticket_id", nargs="?")
    ap.add_argument("--reviewer")
    ap.add_argument("--decision", choices=["approve", "reject"])
    ap.add_argument("--rationale", default="")
    ap.add_argument("--db", default=str(DEFAULT_DB))
    args = ap.parse_args()

    conn = connect(Path(args.db))
    migrate(conn)
    if args.action == "list":
        _list(conn)
    elif args.action == "ack":
        if not args.ticket_id:
            ap.error("ack needs a ticket_id")
        _ack(conn, args.ticket_id)
    else:
        if not (args.ticket_id and args.reviewer and args.decision):
            ap.error("resolve needs ticket_id, --reviewer and --decision")
        _resolve(conn, args.ticket_id, args.reviewer, args.decision, args.rationale)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
