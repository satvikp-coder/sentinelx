"""Tests for shield rules: compiler, safety gate, rule evaluation, lifecycle."""

from datetime import UTC, datetime, timedelta

from sentinelx.common_schemas import (
    Actor,
    ActorRole,
    EscalationStatus,
    EvidenceState,
    SessionKind,
    ShieldRule,
    ShieldScope,
    ShieldStatus,
)
from sentinelx.evidence.db import connect, migrate
from sentinelx.evidence.sessions import SessionService
from sentinelx.evidence.store import EvidenceStore
from sentinelx.shield.rules import (
    BenignReplayGate,
    RuleCompiler,
    RuleLifecycle,
    ShieldAction,
    evaluate_rule,
    evaluate_rules,
    retire_rules_for_finding,
)


def _setup() -> tuple[SessionService, EvidenceStore, RuleLifecycle, str]:
    conn = connect(":memory:")
    migrate(conn)
    store = EvidenceStore(conn)
    session_svc = SessionService(conn)
    session, _ = session_svc.create(
        kind=SessionKind.GUARD,
        policy_version="1.0",
        actor=Actor(id="test", role=ActorRole.SYSTEM),
    )
    lifecycle = RuleLifecycle(store, session.id)
    return session_svc, store, lifecycle, session.id


def test_compiler_rejects_overly_broad_rules():
    _, store, _, session_id = _setup()
    compiler = RuleCompiler(store, session_id)

    # Route "/" with no param or client
    res = compiler.compile(
        intent_id="i1", suggested_action=ShieldAction.BLOCK_ROUTE_PATTERN,
        scope=ShieldScope(route="/"), reason="r", owner="o"
    )
    assert res.rejected

    # Wildcard route (should be rejected by compiler)
    res = compiler.compile(
        intent_id="i1", suggested_action=ShieldAction.BLOCK_ROUTE_PATTERN,
        scope=ShieldScope(route="*"), reason="r", owner="o"
    )
    assert res.rejected

    # Route "/" with no param or client
    res = compiler.compile(
        intent_id="i1", suggested_action=ShieldAction.BLOCK_ROUTE_PATTERN,
        scope=ShieldScope(route="/"), reason="r", owner="o"
    )
    assert res.rejected

    # TTL above maximum
    res = compiler.compile(
        intent_id="i1", suggested_action=ShieldAction.BLOCK_ROUTE_PATTERN,
        scope=ShieldScope(route="/api/notes"), reason="r", owner="o",
        ttl_minutes=2000
    )
    assert res.rejected

    # Missing owner
    res = compiler.compile(
        intent_id="i1", suggested_action=ShieldAction.BLOCK_ROUTE_PATTERN,
        scope=ShieldScope(route="/api/notes"), reason="r", owner=""
    )
    assert res.rejected

    # Missing reason
    res = compiler.compile(
        intent_id="i1", suggested_action=ShieldAction.BLOCK_ROUTE_PATTERN,
        scope=ShieldScope(route="/api/notes"), reason="", owner="o"
    )
    assert res.rejected

    # Action not in catalog
    res = compiler.compile(
        intent_id="i1", suggested_action="INVALID_ACTION",
        scope=ShieldScope(route="/api/notes"), reason="r", owner="o"
    )
    assert res.rejected

# Valid rule accepted
    # First create an event to cite
    evt = store.append(session_id, "test", EvidenceState.OBSERVED, "test", {"test": "data"})
    res = compiler.compile(
        intent_id="i1", suggested_action=ShieldAction.BLOCK_ROUTE_PATTERN,
        scope=ShieldScope(route="/api/notes"), reason="r", owner="o",
        intent_event_ids=[evt.id]
    )
    assert not res.rejected
    assert res.rule is not None
    assert res.rule.status == ShieldStatus.PROPOSED


def test_compiler_validates_intent_event_ids():
    _, store, _, session_id = _setup()
    compiler = RuleCompiler(store, session_id)

    # Non-existent intent event ids
    res = compiler.compile(
        intent_id="i1", suggested_action=ShieldAction.BLOCK_ROUTE_PATTERN,
        scope=ShieldScope(route="/api/notes"), reason="r", owner="o",
        intent_event_ids=["evt_nonexistent"]
    )
    assert res.rejected
    assert "not found" in (res.reason or "")


def test_gate_passes_benign_traffic():
    _, store, _, session_id = _setup()
    gate = BenignReplayGate(store, session_id, benign_requests=[
        {"method": "GET", "path": "/other", "params": {}, "headers": {}},
        {"method": "POST", "path": "/other", "params": {}, "headers": {}},
    ])

    rule = ShieldRule(
        id="r1", target_id=session_id, scope=ShieldScope(route="/api/notes", parameter=None, client=None),
        action=ShieldAction.BLOCK_ROUTE_PATTERN.value, reason="test", linked_finding_id=None,
        intent_event_ids=["evt1"], owner="test", created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1), status="ACTIVE"
    )
    result = gate.check(rule)
    assert result.passed
    assert result.benign_blocked == 0


def test_gate_rejects_harmful_rule():
    _, store, _, session_id = _setup()
    gate = BenignReplayGate(store, session_id, benign_requests=[
        {"method": "GET", "path": "/api/notes", "params": {}, "headers": {}},
    ])

    rule = ShieldRule(
        id="r1", target_id=session_id, scope=ShieldScope(route="/api/notes", parameter=None, client=None),
        action=ShieldAction.BLOCK_ROUTE_PATTERN.value, reason="test", linked_finding_id=None,
        intent_event_ids=["evt1"], owner="test", created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1), status="ACTIVE"
    )
    result = gate.check(rule)
    assert not result.passed
    assert result.benign_blocked == 1
    assert result.escalation_ticket is not None
    assert result.escalation_ticket.status == EscalationStatus.OPEN


def test_rule_evaluation():
    rule = ShieldRule(
        id="r1", target_id="s1", scope=ShieldScope(route="/api/notes", parameter=None, client=None),
        action=ShieldAction.BLOCK_ROUTE_PATTERN.value, reason="test", linked_finding_id=None,
        intent_event_ids=["evt1"], owner="test", created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1), status="ACTIVE"
    )

    # Matching request
    req = {"method": "GET", "path": "/api/notes", "params": {}, "headers": {}}
    decision = evaluate_rule(rule, req)
    assert not decision.allowed
    assert decision.action == ShieldAction.BLOCK_ROUTE_PATTERN
    assert decision.rule_id == "r1"

    # Non-matching request
    req = {"method": "GET", "path": "/other", "params": {}, "headers": {}}
    decision = evaluate_rule(rule, req)
    assert decision.allowed

    # Expired rule - create with valid expiry then manually expire
    rule2 = ShieldRule(
        id="r2", target_id="s1", scope=ShieldScope(route="/api/notes"),
        action=ShieldAction.BLOCK_ROUTE_PATTERN.value, reason="test", linked_finding_id=None,
        intent_event_ids=["evt1"], owner="test", created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1), status="ACTIVE"
    )
    # Manually expire it
    rule2 = rule2.model_copy(update={"expires_at": datetime.now(UTC) - timedelta(hours=1)})
    decision = evaluate_rule(rule2, {"method": "GET", "path": "/api/notes", "params": {}, "headers": {}})
    assert decision.allowed


def test_rule_evaluation_priority():
    rule1 = ShieldRule(
        id="r1", target_id="s1", scope=ShieldScope(route="/api/notes"),
        action=ShieldAction.BLOCK_ROUTE_PATTERN.value, reason="test", linked_finding_id=None,
        intent_event_ids=["evt1"], owner="test", created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1), status="ACTIVE"
    )
    rule2 = ShieldRule(
        id="r2", target_id="s1", scope=ShieldScope(route="/api/notes"),
        action=ShieldAction.REQUIRE_AUTH_ON_ROUTE.value, reason="test", linked_finding_id=None,
        intent_event_ids=["evt1"], owner="test", created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1), status="ACTIVE"
    )

    req = {"method": "GET", "path": "/api/notes", "params": {}, "headers": {}}
    decision = evaluate_rules([rule1, rule2], req)
    assert not decision.allowed
    assert decision.action == ShieldAction.BLOCK_ROUTE_PATTERN
    assert decision.rule_id == "r1"


def test_lifecycle_ttl_expiry():
    _, store, lifecycle, _ = _setup()
    rule = ShieldRule(
        id="r1", target_id="s1", scope=ShieldScope(route="/api/notes"),
        action="BLOCK_ROUTE_PATTERN", reason="test", linked_finding_id=None,
        intent_event_ids=["evt1"], owner="test", created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1), status="ACTIVE"
    )
    # Manually expire
    rule = rule.model_copy(update={"expires_at": datetime.now(UTC) - timedelta(minutes=1)})
    lifecycle.add_rule(rule)
    expired = lifecycle.expire_rules()
    assert expired == 1
    assert lifecycle.get_rule("r1").status == "EXPIRED"


def test_lifecycle_manual_removal():
    _, _, lifecycle, _ = _setup()
    rule = ShieldRule(
        id="r1", target_id="s1", scope=ShieldScope(route="/api/notes"),
        action="BLOCK_ROUTE_PATTERN", reason="test", linked_finding_id=None,
        intent_event_ids=["evt1"], owner="test", created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1), status="ACTIVE"
    )
    lifecycle.add_rule(rule)
    assert lifecycle.remove_rule("r1", "cli", "test reason")
    assert lifecycle.get_rule("r1").status == "REMOVED"
    assert not lifecycle.remove_rule("nonexistent", "cli", "reason")


def test_lifecycle_extend():
    _, _, lifecycle, _ = _setup()
    rule = ShieldRule(
        id="r1", target_id="s1", scope=ShieldScope(route="/api/notes"),
        action="BLOCK_ROUTE_PATTERN", reason="test", linked_finding_id=None,
        intent_event_ids=["evt1"], owner="test", created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=30), status="ACTIVE"
    )
    lifecycle.add_rule(rule)
    assert lifecycle.extend_rule("r1", 60, "cli")
    assert lifecycle.get_rule("r1").expires_at > datetime.now(UTC) + timedelta(minutes=60)


def test_retire_rules_for_finding():
    _, store, lifecycle, session_id = _setup()

    rule1 = ShieldRule(
        id="r1", target_id=session_id, scope=ShieldScope(route="/api/notes"),
        action="BLOCK_ROUTE_PATTERN", reason="test", linked_finding_id="finding1",
        intent_event_ids=["evt1"], owner="test", created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1), status="ACTIVE"
    )
    rule2 = ShieldRule(
        id="r2", target_id=session_id, scope=ShieldScope(route="/api/other"),
        action="BLOCK_ROUTE_PATTERN", reason="test", linked_finding_id="finding1",
        intent_event_ids=["evt1"], owner="test", created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1), status="ACTIVE"
    )
    lifecycle.add_rule(rule1)
    lifecycle.add_rule(rule2)

    count = retire_rules_for_finding("finding1", lifecycle, store, session_id)
    assert count == 2
    assert lifecycle.get_rule("r1").status == "REMOVED"
    assert lifecycle.get_rule("r2").status == "REMOVED"
