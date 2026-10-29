"""List, acknowledge, or resolve EscalationTickets.

Usage:
  python scripts/escalations.py list [--db ...]
  python scripts/escalations.py ack <ticket_id> [--db ...]
  python scripts/escalations.py resolve <ticket_id> --reviewer NAME --decision approve|reject
      --rationale "..." [--db ...]
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinelx.common_schemas import ApprovalDecision, ApprovalRecord, EscalationStatus  # noqa: E402
from sentinelx.evidence.db import connect, migrate  # noqa: E402
from sentinelx.evidence.records import RecordStore  # noqa: E402

DEFAULT_DB = ROOT / "evaluations" / "fix_runs" / "fix.sqlite"


def _list(conn) -> None:
    rows = conn.execute("SELECT id, status, body FROM escalations ORDER BY id").fetchall()
    if not rows:
        print("no escalation tickets")
        return
    for row in rows:
        import json

        body = json.loads(row["body"])
        print(f"{row['id']}  [{row['status']}]  finding={body['finding_id']}")
        print(f"    {body['explanation']}")
        for i, opt in enumerate(body["options"], 1):
            print(f"      {i}. {opt}")


def _ack(conn, ticket_id: str) -> None:
    conn.execute("UPDATE escalations SET status = ? WHERE id = ?",
                (EscalationStatus.ACKNOWLEDGED.value, ticket_id))
    conn.commit()
    print(f"{ticket_id} -> ACKNOWLEDGED")


def _resolve(conn, ticket_id: str, reviewer: str, decision: str, rationale: str) -> None:
    import uuid
    from datetime import UTC, datetime

    RecordStore(conn).insert(ApprovalRecord(
        id=f"appr_{uuid.uuid4().hex[:12]}", subject_type="escalation", subject_id=ticket_id,
        reviewer=reviewer, decision=ApprovalDecision(decision), rationale=rationale,
        timestamp=datetime.now(UTC)))
    conn.execute("UPDATE escalations SET status = ? WHERE id = ?",
                (EscalationStatus.RESOLVED.value, ticket_id))
    conn.commit()
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
