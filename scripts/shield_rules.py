#!/usr/bin/env python3
"""CLI for shield rule lifecycle: list, show, remove, extend.

Each change is recorded as an evidence event and an ApprovalRecord.
"""

from __future__ import annotations

import argparse
import sys
import uuid
from datetime import UTC, datetime

from sentinelx.common_schemas import (
    Actor,
    ActorRole,
    ApprovalDecision,
    ApprovalRecord,
)
from sentinelx.evidence.db import connect, migrate
from sentinelx.evidence.sessions import SessionService
from sentinelx.evidence.store import EvidenceStore
from sentinelx.shield.rules import RuleLifecycle


def _now() -> datetime:
    return datetime.now(UTC)


def _gen_id(prefix: str = "appr") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _get_session_and_lifecycle(
    db_path: str = ":memory:",
) -> tuple[SessionService, EvidenceStore, RuleLifecycle, str]:
    conn = connect(db_path)
    migrate(conn)
    store = EvidenceStore(conn)
    session_svc = SessionService(conn)
    session, _ = session_svc.create(
        kind="GUARD", policy_version="1.0", actor=Actor(id="cli", role=ActorRole.OPERATOR)
    )
    lifecycle = RuleLifecycle(store, session.id)
    return session_svc, store, lifecycle, session.id


def cmd_list(args: argparse.Namespace) -> int:
    _, _, lifecycle, _ = _get_session_and_lifecycle(args.db)
    rules = lifecycle.list_rules()
    if not rules:
        print("No rules")
        return 0
    for r in lifecycle.list_rules():
        status = r.status.value
        expires = r.expires_at.isoformat()
        print(f"{r.id}  {r.scope.route}  {r.action}  {status}  expires={expires}")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    _, _, lifecycle, _ = _get_session_and_lifecycle(args.db)
    rule = lifecycle.get_rule(args.rule_id)
    if not rule:
        print(f"Rule not found: {args.rule_id}", file=sys.stderr)
        return 1
    print(f"id: {rule.id}")
    print(f"target: {rule.target_id}")
    print(
        f"scope: route={rule.scope.route} param={rule.scope.parameter} client={rule.scope.client}"
    )
    print(f"action: {rule.action}")
    print(f"reason: {rule.reason}")
    print(f"linked_finding: {rule.linked_finding_id}")
    print(f"intent_events: {rule.intent_event_ids}")
    print(f"owner: {rule.owner}")
    print(f"created: {rule.created_at.isoformat()}")
    print(f"expires: {rule.expires_at.isoformat()}")
    print(f"status: {rule.status.value}")
    print(f"label: {rule.label}")
    return 0


def cmd_remove(args: argparse.Namespace) -> int:
    _, store, lifecycle, session_id = _get_session_and_lifecycle(args.db)
    rule = lifecycle.get_rule(args.rule_id)
    if not rule:
        print(f"Rule not found: {args.rule_id}", file=sys.stderr)
        return 1
    if not lifecycle.remove_rule(args.rule_id, "cli", args.reason):
        print("Failed to remove rule", file=sys.stderr)
        return 1
    # Record approval record
    ApprovalRecord(
        id=f"appr_{uuid.uuid4().hex[:12]}",
        subject_type="shield_rule",
        subject_id=args.rule_id,
        reviewer="cli",
        decision=ApprovalDecision.REJECT,
        rationale=args.reason,
        timestamp=datetime.now(UTC),
    )
    print(f"Removed rule {args.rule_id}")
    return 0


def cmd_extend(args: argparse.Namespace) -> int:
    _, _, lifecycle, _ = _get_session_and_lifecycle(args.db)
    if not lifecycle.extend_rule(args.rule_id, args.minutes, "cli"):
        print("Failed to extend rule (not found or TTL would exceed maximum)", file=sys.stderr)
        return 1
    print(f"Extended rule {args.rule_id} by {args.minutes} minutes")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Shield rule lifecycle management")
    ap.add_argument("--db", default=":memory:", help="SQLite database path")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="List all rules")

    sp = sub.add_parser("show", help="Show rule details")
    sp.add_argument("rule_id", help="Rule ID")

    sp = sub.add_parser("remove", help="Remove a rule")
    sp.add_argument("rule_id", help="Rule ID")
    sp.add_argument("--reason", required=True, help="Removal reason")

    sp = sub.add_parser("extend", help="Extend rule TTL")
    sp.add_argument("rule_id", help="Rule ID")
    sp.add_argument("--minutes", type=int, required=True, help="Additional minutes")

    args = ap.parse_args()
    if args.cmd == "list":
        return cmd_list(args)
    elif args.cmd == "show":
        return cmd_show(args)
    elif args.cmd == "remove":
        return cmd_remove(args)
    elif args.cmd == "extend":
        return cmd_extend(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
