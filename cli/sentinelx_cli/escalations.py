#!/usr/bin/env python3
"""sentinelx escalations - Manage escalation tickets."""

from __future__ import annotations

import sys

from sentinelx.common_schemas import (
    Actor,
    ActorRole,
    EscalationStatus,
)
from sentinelx.evidence.db import connect, migrate
from sentinelx.evidence.sessions import SessionService
from sentinelx.evidence.store import EvidenceStore


def escalations_cmd(args, subcmd: str) -> int:
    if subcmd == "list":
        return _list(args)
    elif subcmd == "ack":
        return _ack(args)
    elif subcmd == "resolve":
        return _resolve(args)
    else:
        print(f"Unknown escalations command: {args.esc_cmd}", file=sys.stderr)
        return 1


def _get_session_and_store(db_path: str):
    conn = connect(db_path)
    migrate(conn)
    store = EvidenceStore(conn)
    session_svc = SessionService(conn)
    session, _ = session_svc.create(
        kind="GUARD", policy_version="1.0",
        actor=Actor(id="cli", role=ActorRole.SYSTEM),
    )
    return session_svc, store, session.id


def _list(args) -> int:
    _, store, session_id = _get_session_and_store(args.db)
    events = store.list_session(session_id)
    tickets = [e for e in events if e.kind == "escalation_ticket"]
    if not tickets:
        print("No escalation tickets")
        return 0
    for e in tickets:
        print(f"{e.id}  {e.payload.get('status', 'UNKNOWN')}  {e.payload.get('finding_id', 'N/A')}  {e.timestamp_utc.isoformat()}")
    return 0


def _ack(args) -> int:

    _, store, session_id = _get_session_and_store(args.db)
    # Find ticket
    events = store.list_session(session_id)
    ticket = None
    for e in events:
        if e.kind == "escalation_ticket" and e.id == args.ticket_id:
            ticket = e
            break
    if not ticket:
        print(f"Ticket not found: {args.ticket_id}", file=sys.stderr)
        return 1
    if ticket.payload.get("status") != "OPEN":
        print(f"Ticket already acknowledged: {args.ticket_id}")
        return 1
    # Update ticket
    new_payload = dict(ticket.payload)
    new_payload["status"] = EscalationStatus.ACKNOWLEDGED.value
    new_payload["acknowledged_by"] = "cli"
    updated = ticket.model_copy(update={"payload": new_payload, "status": EscalationStatus.ACKNOWLEDGED})
    store.append(
        session_id, "escalation_ticket", EscalationStatus.ACKNOWLEDGED, "sentinelx.cli",
        new_payload, parent_event_id=ticket.id
    )
    print(f"Acknowledged ticket {args.ticket_id}")
    return 0


def _resolve(args) -> int:

    _, store, session_id = _get_session_and_store(args.db)
    events = store.list_session(session_id)
    ticket = None
    for e in events:
        if e.kind == "escalation_ticket" and e.id == args.ticket_id:
            ticket = e
            break
    if not ticket:
        print(f"Ticket not found: {args.ticket_id}", file=sys.stderr)
        return 1
    if ticket.payload.get("status") == "RESOLVED":
        print(f"Ticket already resolved: {args.ticket_id}")
        return 1
    new_payload = dict(ticket.payload)
    new_payload["status"] = EscalationStatus.RESOLVED.value
    new_payload["resolved_by"] = args.reviewer
    new_payload["resolution"] = args.decision
    new_payload["rationale"] = args.rationale
    updated = ticket.model_copy(update={"payload": new_payload, "status": EscalationStatus.RESOLVED})
    store.append(
        session_id, "escalation_ticket", EscalationStatus.RESOLVED, "sentinelx.cli",
        new_payload, parent_event_id=ticket.id
    )
    print(f"Resolved ticket {args.ticket_id} as {args.decision}")
    return 0
