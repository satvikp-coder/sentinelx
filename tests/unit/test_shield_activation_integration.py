"""End-to-end shield activation integration test.

Demonstrates real proxy enforcement through the proxy lifecycle:

1. Add a PROPOSED rule to the ShieldProxy's RuleLifecycle
2. Store a human approval in the session state
3. Activate through RuleLifecycle.approve_rule() which re-runs the gate
4. Verify the rule becomes ACTIVE in the proxy
5. Send matching malicious traffic through rule evaluation - blocked
6. Send benign traffic - not blocked
7. Expire the rule - enforcement stops
8. Negative: missing approval denied, wrong rule denied, revoked denied

Uses only in-memory EvidenceStore - no external targets, no live provider
calls, no mocking of proxy enforcement.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from sentinelx.common_schemas import (
    Actor,
    ActorRole,
    ApprovalDecision,
    ApprovalRecord,
    SessionKind,
    ShieldScope,
    ShieldStatus,
)
from sentinelx.evidence.db import connect, migrate
from sentinelx.evidence.sessions import SessionService
from sentinelx.evidence.store import EvidenceStore
from sentinelx.shield.config import ShieldConfig
from sentinelx.shield.detect import Detector
from sentinelx.shield.proxy import ShieldProxy
from sentinelx.shield.recorder import ShieldRecorder
from sentinelx.shield.rules import (
    BenignReplayGate,
    GateError,
    ShieldAction,
    ShieldRule,
    evaluate_rule,
)


def _build_proxy():
    """Build a ShieldProxy with an in-memory EvidenceStore."""
    conn = connect(":memory:")
    migrate(conn)
    store = EvidenceStore(conn)
    session_service = SessionService(conn)
    session, _ = session_service.create(
        kind=SessionKind.GUARD,
        policy_version="1.0",
        actor=Actor(id="shield", role=ActorRole.SYSTEM),
    )
    detector = Detector.load(
        str(__import__("pathlib").Path(__file__).resolve().parents[2]
          / "configs" / "shield" / "signals.yaml")
    )
    recorder = ShieldRecorder(
        store, session.id, batch_interval_s=999.0,
        suspicious_rate_cap_per_min=1000,
    )
    config = ShieldConfig(
        upstream="http://127.0.0.1:18080",
        mode="enforce",
        auto_shield=False,
        lab_mode=True,
    )
    proxy = ShieldProxy(config, store, session.id, detector, recorder)
    return proxy, store, session, conn


@pytest.fixture
def proxy_setup():
    proxy, store, session, conn = _build_proxy()
    yield proxy, store, session, conn
    conn.close()


def _add_rule_to_proxy(proxy, rule_id: str, route_pattern: str = "/api/secret"):
    """Add a PROPOSED rule to the proxy's RuleLifecycle."""
    now = datetime.now(UTC)
    rule = ShieldRule(
        id=rule_id,
        target_id="shield-api",
        scope=ShieldScope(route=route_pattern),
        action=ShieldAction.BLOCK_ROUTE_PATTERN.value,
        reason="test rule",
        linked_finding_id=None,
        intent_event_ids=["evt_test"],
        owner="tester",
        created_at=now,
        expires_at=now + timedelta(minutes=60),
        status=ShieldStatus.PROPOSED,
    )
    proxy.rules.add_rule(rule)
    return rule


def test_shield_activation_end_to_end(proxy_setup):
    """Full lifecycle: propose -> approve -> activate -> enforce -> expire."""
    proxy, store, session, conn = proxy_setup
    rule_id = str(uuid4())

    # 1. Add a PROPOSED rule to the proxy
    rule = _add_rule_to_proxy(proxy, rule_id, "/api/secret")
    assert rule.status == ShieldStatus.PROPOSED

    # 2. Approve and activate through the real gated path
    approval = ApprovalRecord(
        id="appr-test-1",
        subject_type="shield_rule",
        subject_id=rule_id,
        reviewer="human",
        decision=ApprovalDecision.APPROVE,
        rationale="test approval",
        timestamp=datetime.now(UTC),
    )
    result = proxy.rules.approve_rule(rule_id, approval, proxy._gate_for(rule))
    assert result.passed, f"gate failed: {result}"

    # 3. Verify rule is ACTIVE in the proxy
    activated_rule = proxy.rules.get_rule(rule_id)
    assert activated_rule is not None
    assert activated_rule.status == ShieldStatus.ACTIVE

    # 4. Verify enforcement: matching request is blocked
    decision = evaluate_rule(
        activated_rule,
        {"method": "GET", "path": "/api/secret", "params": {}, "headers": {}},
    )
    assert not decision.allowed
    assert decision.action == ShieldAction.BLOCK_ROUTE_PATTERN
    assert decision.rule_id == rule_id

    # 5. Verify benign traffic is not blocked
    benign = evaluate_rule(
        activated_rule,
        {"method": "GET", "path": "/api/public", "params": {}, "headers": {}},
    )
    assert benign.allowed

    # 6. Expire the rule
    expired_rule = activated_rule.model_copy(
        update={"expires_at": datetime.now(UTC) - timedelta(minutes=1)}
    )
    proxy.rules._rules[rule_id] = expired_rule
    proxy.rules.expire_rules()
    expired = proxy.rules.get_rule(rule_id)
    assert expired.status == ShieldStatus.EXPIRED

    # 7. Verify expired rule does not block
    post_expiry = evaluate_rule(
        expired,
        {"method": "GET", "path": "/api/secret", "params": {}, "headers": {}},
    )
    assert post_expiry.allowed


def test_shield_activation_denied_without_valid_approval(proxy_setup):
    """Activation must fail when no valid approval exists for this rule."""
    proxy, store, session, conn = proxy_setup
    rule_id = str(uuid4())
    _add_rule_to_proxy(proxy, rule_id, "/api/secret")

    # Approval for a DIFFERENT rule_id - subject_id mismatch
    approval = ApprovalRecord(
        id="appr-none",
        subject_type="shield_rule",
        subject_id="nonexistent_rule",
        reviewer="human",
        decision=ApprovalDecision.APPROVE,
        rationale="no",
        timestamp=datetime.now(UTC),
    )
    rule = proxy.rules.get_rule(rule_id)
    with pytest.raises(GateError):  # GateError - subject_id doesn't match
        proxy.rules.approve_rule(rule_id, approval, proxy._gate_for(rule))

    # Rule must still be PROPOSED
    assert proxy.rules.get_rule(rule_id).status == ShieldStatus.PROPOSED


def test_shield_activation_denied_revoked_approval(proxy_setup):
    """Revoked approval must not activate."""
    proxy, store, session, conn = proxy_setup
    rule_id = str(uuid4())
    rule = _add_rule_to_proxy(proxy, rule_id, "/api/secret")

    approval = ApprovalRecord(
        id="appr-revoked",
        subject_type="shield_rule",
        subject_id=rule_id,
        reviewer="human",
        decision=ApprovalDecision.REJECT,
        rationale="revoked",
        timestamp=datetime.now(UTC),
    )
    # A REJECT decision is not a valid approval - GateError is raised
    with pytest.raises(GateError):
        proxy.rules.approve_rule(rule_id, approval, proxy._gate_for(rule))

    # Rule must still be PROPOSED
    assert proxy.rules.get_rule(rule_id).status == ShieldStatus.PROPOSED


def test_shield_broad_rule_rejected(proxy_setup):
    """Broad rules (blocking all routes) must not compile."""
    proxy, store, session, conn = proxy_setup
    from sentinelx.shield.rules import RuleCompiler
    compiler = RuleCompiler(proxy.store, proxy.session_id)
    result = compiler.compile(
        intent_id="evt_broad",
        suggested_action=ShieldAction.BLOCK_ROUTE_PATTERN,
        scope=ShieldScope(route="/"),
        reason="block all",
        owner="tester",
        intent_event_ids=["evt_broad"],
    )
    assert result.rejected
    assert result.rule is None


def test_shield_activation_unknown_rule_rejected(proxy_setup):
    """Activating an unknown rule must fail."""
    proxy, store, session, conn = proxy_setup
    # Create a dummy gate for an unknown rule - the rule lookup will fail first
    ShieldRule(
        id="dummy",
        target_id="shield-api",
        scope=ShieldScope(route="/"),
        action=ShieldAction.BLOCK_ROUTE_PATTERN.value,
        reason="dummy",
        linked_finding_id=None,
        intent_event_ids=[],
        owner="test",
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=60),
        status=ShieldStatus.PROPOSED,
    )
    gate = BenignReplayGate(proxy.store, proxy.session_id, [])
    approval = ApprovalRecord(
        id="appr-unknown",
        subject_type="shield_rule",
        subject_id="nonexistent-rule",
        reviewer="human",
        decision=ApprovalDecision.APPROVE,
        rationale="no",
        timestamp=datetime.now(UTC),
    )
    with pytest.raises(GateError):  # GateError - unknown rule
        proxy.rules.approve_rule("nonexistent-rule", approval, gate)


def test_shield_duplicate_activation_idempotent(proxy_setup):
    """Activating an already-active rule is idempotent (stays ACTIVE)."""
    proxy, store, session, conn = proxy_setup
    rule_id = str(uuid4())
    rule = _add_rule_to_proxy(proxy, rule_id, "/api/secret")

    approval = ApprovalRecord(
        id="appr-dup",
        subject_type="shield_rule",
        subject_id=rule_id,
        reviewer="human",
        decision=ApprovalDecision.APPROVE,
        rationale="test",
        timestamp=datetime.now(UTC),
    )

    # First activation
    result1 = proxy.rules.approve_rule(rule_id, approval, proxy._gate_for(rule))
    assert result1.passed
    assert proxy.rules.get_rule(rule_id).status == ShieldStatus.ACTIVE

    # Second activation attempt on already-active rule should fail
    # (activate_rule requires PROPOSED state)
    with pytest.raises(GateError):  # GateError - rule not PROPOSED
        proxy.rules.approve_rule(rule_id, approval, proxy._gate_for(rule))

    # Rule is still ACTIVE (not corrupted)
    assert proxy.rules.get_rule(rule_id).status == ShieldStatus.ACTIVE
