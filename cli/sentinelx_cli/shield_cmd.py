#!/usr/bin/env python3
"""sentinelx shield - Manage shield rules."""

from __future__ import annotations

import sys

from sentinelx.shield.rules import RuleLifecycle


def shield_cmd(args, subcmd: str) -> int:
    if subcmd == "list":
        return _shield_list(args)
    elif subcmd == "show":
        return _shield_show(args)
    elif subcmd == "remove":
        return _shield_remove(args)
    elif subcmd == "extend":
        return _shield_extend(args)
    elif subcmd == "approve":
        return _shield_approve(args)
    else:
        print(f"Unknown shield command: {args.shield_cmd}", file=sys.stderr)
        return 1


def _shield_list(args) -> int:
    db_path = args.db
    from sentinelx.common_schemas import Actor, ActorRole
    from sentinelx.evidence.db import connect, migrate
    from sentinelx.evidence.sessions import SessionService
    from sentinelx.evidence.store import EvidenceStore

    conn = connect(args.db)
    migrate(conn)

    conn = connect(args.db)
    from sentinelx.evidence.db import migrate
    migrate(conn)
    store = EvidenceStore(conn)
    session_svc = SessionService(conn)
    session, _ = session_svc.create(
        kind="GUARD", policy_version="1.0",
        actor=Actor(id="cli", role=ActorRole.SYSTEM)
    )
    lifecycle = RuleLifecycle(store, session.id)
    rules = lifecycle.list_rules()
    if not rules:
        print("No rules")
        return 0
    for r in rules:
        print(f"{r.id}  {r.scope.route}  {r.action}  {r.status.value}  expires={r.expires_at.isoformat()}")
    return 0


def _shield_show(args) -> int:
    from sentinelx.common_schemas import Actor, ActorRole
    from sentinelx.evidence.db import connect, migrate
    from sentinelx.evidence.sessions import SessionService
    from sentinelx.evidence.store import EvidenceStore
    from sentinelx.shield.rules import RuleLifecycle

    conn = connect(args.db)
    migrate(conn)
    store = EvidenceStore(conn)
    session_svc = SessionService(conn)
    session, _ = session_svc.create(
        kind="GUARD", policy_version="1.0",
        actor=Actor(id="cli", role=ActorRole.SYSTEM)
    )
    lifecycle = RuleLifecycle(store, session.id)
    rule = lifecycle.get_rule(args.rule_id)
    if not rule:
        print(f"Rule not found: {args.rule_id}", file=sys.stderr)
        return 1
    print(f"id: {rule.id}")
    print(f"target: {rule.target_id}")
    print(f"scope: route={rule.scope.route} param={rule.scope.parameter} client={rule.scope.client}")
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


def _shield_remove(args) -> int:
    from sentinelx.common_schemas import Actor, ActorRole
    from sentinelx.evidence.db import connect, migrate
    from sentinelx.evidence.sessions import SessionService
    from sentinelx.evidence.store import EvidenceStore
    from sentinelx.shield.rules import RuleLifecycle

    conn = connect(args.db)
    migrate(conn)
    store = EvidenceStore(conn)
    session_svc = SessionService(conn)
    session, _ = session_svc.create(
        kind="GUARD", policy_version="1.0",
        actor=Actor(id="cli", role=ActorRole.SYSTEM)
    )
    lifecycle = RuleLifecycle(store, session.id)
    if not lifecycle.remove_rule(args.rule_id, "cli", "removed via CLI"):
        print(f"Failed to remove rule: {args.rule_id}", file=sys.stderr)
        return 1
    print(f"Removed rule {args.rule_id}")
    return 0


def _shield_extend(args) -> int:
    from sentinelx.common_schemas import Actor, ActorRole
    from sentinelx.evidence.db import connect, migrate
    from sentinelx.evidence.sessions import SessionService
    from sentinelx.evidence.store import EvidenceStore
    from sentinelx.shield.rules import RuleLifecycle

    conn = connect(args.db)
    migrate(conn)
    store = EvidenceStore(conn)
    session_svc = SessionService(conn)
    session, _ = session_svc.create(
        kind="GUARD", policy_version="1.0",
        actor=Actor(id="cli", role=ActorRole.SYSTEM)
    )
    lifecycle = RuleLifecycle(store, session.id)
    if not lifecycle.extend_rule(args.rule_id, args.minutes, "cli"):
        print("Failed to extend rule (not found or TTL would exceed maximum)", file=sys.stderr)
        return 1
    print(f"Extended rule {args.rule_id} by {args.minutes} minutes")
    return 0


def _shield_approve(args) -> int:
    from sentinelx.common_schemas import Actor, ActorRole
    from sentinelx.evidence.db import connect, migrate
    from sentinelx.evidence.sessions import SessionService
    from sentinelx.evidence.store import EvidenceStore
    from sentinelx.shield.rules import RuleLifecycle

    conn = connect(args.db)
    migrate(conn)
    store = EvidenceStore(conn)
    session_svc = SessionService(conn)
    session, _ = session_svc.create(
        kind="GUARD", policy_version="1.0",
        actor=Actor(id="cli", role=ActorRole.SYSTEM)
    )
    lifecycle = RuleLifecycle(store, session.id)
    rule = lifecycle.get_rule(args.rule_id)
    if not rule or rule.status.value != "PROPOSED":
        print(f"Rule not found or not in PROPOSED state: {args.rule_id}", file=sys.stderr)
        return 1
    if not lifecycle.activate_rule(args.rule_id):
        print("Failed to approve rule", file=sys.stderr)
        return 1
    print(f"Approved and activated rule {args.rule_id}")
    return 0
