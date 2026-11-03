"""Task 22: Shield intent accuracy and injection protection tests.

Covers:
- Fixed labeled intent dataset + confusion matrix for aggregate_intent
- Benign search traffic is not classified as an attack intent
- Injection attempts (SQL, NoSQL, command, directory traversal) -> INJECTION_PROBE
- Admin probing -> ADMIN_PROBE
- Sequential object access -> DATA_ENUMERATION
- Rate limiting / failed logins -> CREDENTIAL_GUESSING; high_404_rate -> RECON (low conf)
- Evidence citation validation (build_intent drops unknown cited ids, state INFERRED)
- Rule compiler rejects overly broad rules, accepts narrow ones
- Rule TTL expiry and manual removal
- Human approval re-runs the benign-replay gate
- Fail-open behavior and kill switch
- Intent labels remain INFERRED (never OBSERVED)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sentinelx.common_schemas import (
    Actor,
    ActorRole,
    ApprovalDecision,
    ApprovalRecord,
    EvidenceState,
    IntentLabel,
    SessionKind,
    ShieldScope,
)
from sentinelx.evidence.db import connect, migrate
from sentinelx.evidence.sessions import SessionService
from sentinelx.evidence.store import EvidenceStore
from sentinelx.shield.config import ShieldConfig
from sentinelx.shield.detect import Detector
from sentinelx.shield.intent import (
    DEFAULT_CONFIDENCE,
    DEFAULT_INTENT,
    INTENT_LABELS,
    SIGNAL_TO_INTENT,
    IntentVerdict,
    aggregate_intent,
    build_intent,
)
from sentinelx.shield.proxy import ShieldProxy
from sentinelx.shield.recorder import ShieldRecorder
from sentinelx.shield.rules import (
    BenignReplayGate,
    RuleCompiler,
    RuleLifecycle,
    ShieldAction,
    ShieldStatus,
    evaluate_rule,
    evaluate_rules,
)

# ------------------------------------------------------------------ fixed labeled dataset
# Each entry: (signal_names, expected_intent_value, min_confidence)
INTENT_DATASET = [
    # Injection probes
    (["sql_break_char"], "INJECTION_PROBE", 0.85),
    (["markup_reflected"], "INJECTION_PROBE", 0.8),
    (["nosqli_probe"], "INJECTION_PROBE", 0.8),
    (["command_injection"], "INJECTION_PROBE", 0.85),
    (["directory_traversal"], "INJECTION_PROBE", 0.8),
    (["sql_break_char", "markup_reflected"], "INJECTION_PROBE", 0.8),
    # Recon
    (["sensitive_path_env"], "RECON", 0.7),
    (["sensitive_path_git"], "RECON", 0.7),
    (["backup_extension"], "RECON", 0.6),
    (["debug_route"], "RECON", 0.6),
    (["scanner_ua"], "RECON", 0.65),
    (["directory_listing"], "RECON", 0.7),
    # high_404_rate is low-confidence recon (not a high-confidence attack)
    (["high_404_rate"], "RECON", 0.55),
    # Credential guessing (distinguished failed-login behavior)
    (["repeated_failed_logins"], "CREDENTIAL_GUESSING", 0.8),
    (["rapid_failed_logins"], "CREDENTIAL_GUESSING", 0.9),
    (["nonexistent_user_probe"], "CREDENTIAL_GUESSING", 0.7),
    (["protected_no_session"], "CREDENTIAL_GUESSING", 0.6),
    # Data enumeration
    (["object_id_enumeration"], "DATA_ENUMERATION", 0.75),
    # Admin probing
    (["admin_probe"], "ADMIN_PROBE", 0.8),
    (["sensitive_admin_path"], "ADMIN_PROBE", 0.85),
    # Exfiltration
    (["data_transfer_large"], "EXFIL_ATTEMPT", 0.75),
    # Mixed signals: aggregation picks highest-confidence intent
    (["sql_break_char", "sensitive_path_env", "object_id_enumeration"], "INJECTION_PROBE", 0.85),
    (["repeated_failed_logins", "rapid_failed_logins"], "CREDENTIAL_GUESSING", 0.9),
    # Unknown signal -> default recon
    (["no_such_signal"], "RECON", DEFAULT_CONFIDENCE),
    ([] , "RECON", DEFAULT_CONFIDENCE),
]


def test_confusion_matrix_fixed_dataset():
    """Every labeled signal set maps to the expected intent at >= min confidence."""
    for signals, expected_intent, min_conf in INTENT_DATASET:
        intent, confidence, _scores = aggregate_intent(signals)
        assert intent.value == expected_intent, (
            f"signals={signals}: expected {expected_intent}, got {intent.value}"
        )
        assert confidence >= min_conf, (
            f"signals={signals}: expected confidence >= {min_conf}, got {confidence}"
        )


def test_intent_labels_never_observed():
    """Intent labels are always INFERRED; aggregate_intent never returns OBSERVED."""
    for signals, _expected_intent, _min_conf in INTENT_DATASET:
        intent, confidence, _scores = aggregate_intent(signals)
        assert intent in INTENT_LABELS
        # build_intent always sets state=INFERRED
        verdict = IntentVerdict(
            intent=intent.value, summary="test", confidence=confidence,
            cited_event_ids=["evt_1"], model_used=False, note=None,
        )
        ai = build_intent("s1", ["evt_1"], verdict)
        assert ai.state == EvidenceState.INFERRED
        assert ai.state.value != "OBSERVED"


def test_benign_search_traffic_not_attack():
    """Benign search/browse traffic must not be classified as an attack intent."""
    benign_signals = [
        [],  # no signals
        ["scanner_ua"],  # low-confidence recon only
        ["high_404_rate"],  # low-confidence recon only
    ]
    for signals in benign_signals:
        intent, confidence, _scores = aggregate_intent(signals)
        # Benign traffic must never be classified as a high-severity attack class
        assert intent not in (
            IntentLabel.INJECTION_PROBE,
            IntentLabel.EXFIL_ATTEMPT,
            IntentLabel.ADMIN_PROBE,
        ), f"benign signals {signals} classified as {intent.value}"
        # Confidence for benign recon must stay low
        assert confidence <= 0.7, f"benign signals {signals} got high confidence {confidence}"


def test_injection_attempts_classified():
    """Injection attempts (SQL, NoSQL, command, traversal) -> INJECTION_PROBE."""
    injection_signal_sets = [
        ["sql_break_char"],
        ["markup_reflected"],
        ["nosqli_probe"],
        ["command_injection"],
        ["directory_traversal"],
        ["sql_break_char", "nosqli_probe", "command_injection"],
    ]
    for signals in injection_signal_sets:
        intent, confidence, _scores = aggregate_intent(signals)
        assert intent == IntentLabel.INJECTION_PROBE, signals
        assert confidence >= 0.8, f"signals={signals}: confidence {confidence} < 0.8"


def test_admin_probing_classified():
    """Admin probing -> ADMIN_PROBE."""
    admin_signals = [
        ["admin_probe"],
        ["sensitive_admin_path"],
        ["admin_probe", "sensitive_admin_path"],
    ]
    for signals in admin_signals:
        intent, confidence, _scores = aggregate_intent(signals)
        assert intent == IntentLabel.ADMIN_PROBE, signals
        assert confidence >= 0.8


def test_sequential_object_access_classified():
    """Sequential object access -> DATA_ENUMERATION."""
    intent, confidence, _scores = aggregate_intent(["object_id_enumeration"])
    assert intent == IntentLabel.DATA_ENUMERATION
    assert confidence >= 0.75


def test_rate_limiting_not_misattributed():
    """Rate limiting / failed logins -> CREDENTIAL_GUESSING; high_404_rate -> RECON (low conf)."""
    # rapid failed logins (>=10) -> higher confidence than repeated (>=5)
    intent, confidence, _scores = aggregate_intent(["rapid_failed_logins"])
    assert intent == IntentLabel.CREDENTIAL_GUESSING
    assert confidence >= 0.9

    intent, confidence, _scores = aggregate_intent(["repeated_failed_logins"])
    assert intent == IntentLabel.CREDENTIAL_GUESSING
    assert confidence >= 0.8

    # high_404_rate is low-confidence recon, not an attack class
    intent, confidence, _scores = aggregate_intent(["high_404_rate"])
    assert intent == IntentLabel.RECON
    assert confidence < 0.7  # low confidence, not a high-severity attack


def test_evidence_citation_validation():
    """build_intent drops unknown cited ids and always sets INFERRED state."""
    conn = connect(":memory:")
    migrate(conn)
    store = EvidenceStore(conn)
    session_service = SessionService(conn)
    session, _ = session_service.create(
        kind=SessionKind.GUARD, policy_version="1.0",
        actor=Actor(id="shield", role=ActorRole.SYSTEM),
    )
    real = store.append(session.id, "shield_suspicious", EvidenceState.OBSERVED,
                        "sentinelx.shield", {"method": "GET", "path": "/x"})

    verdict = IntentVerdict(
        intent="INJECTION_PROBE", summary="sqli probe", confidence=0.85,
        cited_event_ids=[real.id, "evt_nonexistent"], model_used=False, note=None,
    )
    intent = build_intent(session.id, [real.id, "evt_nonexistent"], verdict, store=store)
    assert intent.state == EvidenceState.INFERRED
    assert real.id in intent.cited_event_ids
    assert "evt_nonexistent" not in intent.cited_event_ids


def test_intent_state_inferred_not_observed():
    """build_intent always produces INFERRED state; never OBSERVED."""
    conn = connect(":memory:")
    migrate(conn)
    store = EvidenceStore(conn)
    session_service = SessionService(conn)
    session, _ = session_service.create(
        kind=SessionKind.GUARD, policy_version="1.0",
        actor=Actor(id="shield", role=ActorRole.SYSTEM),
    )
    real = store.append(session.id, "shield_suspicious", EvidenceState.OBSERVED,
                        "sentinelx.shield", {"method": "GET", "path": "/x"})

    verdict = IntentVerdict(
        intent="RECON", summary="recon", confidence=0.7,
        cited_event_ids=[real.id], model_used=False, note=None,
    )
    ai = build_intent(session.id, [real.id], verdict, store=store)
    assert ai.state == EvidenceState.INFERRED
    assert ai.state.value != "OBSERVED"


# ------------------------------------------------------------------ rule compiler tests

def _make_store_session():
    conn = connect(":memory:")
    migrate(conn)
    store = EvidenceStore(conn)
    session_service = SessionService(conn)
    session, _ = session_service.create(
        kind=SessionKind.GUARD, policy_version="1.0",
        actor=Actor(id="shield", role=ActorRole.SYSTEM),
    )
    return store, session


def _make_scope(route="/api/notes/*", parameter=None, client=None):
    return ShieldScope(route=route, parameter=parameter, client=client)


def test_rule_compiler_accepts_narrow_rule():
    """A narrowly scoped rule (specific route + parameter + intent events) compiles."""
    store, session = _make_store_session()
    real = store.append(session.id, "shield_intent", EvidenceState.INFERRED,
                        "sentinelx.shield", {"intent": "INJECTION_PROBE"})
    compiler = RuleCompiler(store, session.id)
    result = compiler.compile(
        intent_id=real.id, suggested_action=ShieldAction.REJECT_PARAM_PATTERN,
        scope=_make_scope(route="/api/search", parameter="q", client="attacker"),
        reason="narrow injection block", owner="shield-auto",
        intent_event_ids=[real.id],
    )
    assert not result.rejected
    assert result.rule is not None
    assert result.rule.action == ShieldAction.REJECT_PARAM_PATTERN.value
    assert result.rule.scope.route == "/api/search"
    assert result.rule.scope.parameter == "q"
    assert result.rule.scope.client == "attacker"


def test_rule_compiler_rejects_broad_route():
    """A rule with route='/' or '*' is rejected (overly broad)."""
    store, session = _make_store_session()
    real = store.append(session.id, "shield_intent", EvidenceState.INFERRED,
                        "sentinelx.shield", {"intent": "RECON"})
    compiler = RuleCompiler(store, session.id)

    result = compiler.compile(
        intent_id=real.id, suggested_action=ShieldAction.BLOCK_ROUTE_PATTERN,
        scope=_make_scope(route="/", parameter=None, client=None),
        reason="block all", owner="shield-auto", intent_event_ids=[real.id],
    )
    assert result.rejected
    assert result.rule is None

    result = compiler.compile(
        intent_id=real.id, suggested_action=ShieldAction.BLOCK_ROUTE_PATTERN,
        scope=_make_scope(route="*", parameter=None, client=None),
        reason="block all", owner="shield-auto", intent_event_ids=[real.id],
    )
    assert result.rejected
    assert result.rule is None


def test_rule_compiler_rejects_missing_intent_events():
    """A rule with no intent_event_ids is rejected."""
    store, session = _make_store_session()
    compiler = RuleCompiler(store, session.id)
    result = compiler.compile(
        intent_id="evt_fake", suggested_action=ShieldAction.BLOCK_ROUTE_PATTERN,
        scope=_make_scope(route="/api/notes", parameter=None, client=None),
        reason="no events", owner="shield-auto", intent_event_ids=[],
    )
    assert result.rejected
    assert result.rule is None


def test_rule_compiler_rejects_unknown_intent_event():
    """Cited intent event ids that don't exist in the store are rejected."""
    store, session = _make_store_session()
    compiler = RuleCompiler(store, session.id)
    result = compiler.compile(
        intent_id="evt_missing", suggested_action=ShieldAction.BLOCK_ROUTE_PATTERN,
        scope=_make_scope(route="/api/notes", parameter=None, client=None),
        reason="unknown event", owner="shield-auto", intent_event_ids=["evt_missing"],
    )
    assert result.rejected
    assert result.rule is None


def test_rule_compiler_rejects_missing_owner_reason():
    store, session = _make_store_session()
    real = store.append(session.id, "shield_intent", EvidenceState.INFERRED,
                        "sentinelx.shield", {"intent": "RECON"})
    compiler = RuleCompiler(store, session.id)

    result = compiler.compile(
        intent_id=real.id, suggested_action=ShieldAction.BLOCK_ROUTE_PATTERN,
        scope=_make_scope(route="/api/notes", parameter=None, client=None),
        reason="", owner="shield-auto", intent_event_ids=[real.id],
    )
    assert result.rejected

    result = compiler.compile(
        intent_id=real.id, suggested_action=ShieldAction.BLOCK_ROUTE_PATTERN,
        scope=_make_scope(route="/api/notes", parameter=None, client=None),
        reason="ok", owner="", intent_event_ids=[real.id],
    )
    assert result.rejected


# ------------------------------------------------------------------ rule lifecycle: TTL + approval

def test_rule_lifecycle_ttl_expiry():
    """Rules whose TTL has passed are expired to EXPIRED status."""
    store, session = _make_store_session()
    lifecycle = RuleLifecycle(store, session.id)
    now = datetime.now(UTC)
    expired_rule = __import__("sentinelx.common_schemas", fromlist=["ShieldRule"]).ShieldRule(
        id="rule_expired",
        target_id=session.id,
        scope=_make_scope(route="/api/notes"),
        action=ShieldAction.BLOCK_ROUTE_PATTERN.value,
        reason="test",
        linked_finding_id=None,
        intent_event_ids=["evt1"],
        owner="test",
        created_at=now - timedelta(hours=2),
        expires_at=now - timedelta(minutes=30),
        status=ShieldStatus.ACTIVE,
    )
    lifecycle.add_rule(expired_rule)
    count = lifecycle.expire_rules(now=now)
    assert count == 1
    assert lifecycle.get_rule("rule_expired").status == ShieldStatus.EXPIRED


def test_rule_lifecycle_manual_removal():
    """Manual removal sets a rule to REMOVED status."""
    store, session = _make_store_session()
    lifecycle = RuleLifecycle(store, session.id)
    rule = __import__("sentinelx.common_schemas", fromlist=["ShieldRule"]).ShieldRule(
        id="rule_remove",
        target_id=session.id,
        scope=_make_scope(route="/api/notes"),
        action=ShieldAction.BLOCK_ROUTE_PATTERN.value,
        reason="test",
        linked_finding_id=None,
        intent_event_ids=["evt1"],
        owner="test",
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        status=ShieldStatus.ACTIVE,
    )
    lifecycle.add_rule(rule)
    ok = lifecycle.remove_rule("rule_remove", actor="admin", reason="human override")
    assert ok
    assert lifecycle.get_rule("rule_remove").status == ShieldStatus.REMOVED


def test_rule_lifecycle_approve_rule_reruns_gate():
    """Human approval re-runs the benign-replay gate; activates only if it passes."""
    store, session = _make_store_session()
    lifecycle = RuleLifecycle(store, session.id)
    rule = __import__("sentinelx.common_schemas", fromlist=["ShieldRule"]).ShieldRule(
        id="rule_approve",
        target_id=session.id,
        scope=_make_scope(route="/api/notes", parameter=None, client=None),
        action=ShieldAction.BLOCK_ROUTE_PATTERN.value,
        reason="test",
        linked_finding_id=None,
        intent_event_ids=["evt1"],
        owner="test",
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        status=ShieldStatus.PROPOSED,
    )
    lifecycle.add_rule(rule)

    # Gate that fails (benign request /api/notes would be blocked)
    gate = BenignReplayGate(
        store, session.id,
        benign_requests=[{"method": "GET", "path": "/api/notes", "params": {}, "headers": {}}],
    )
    approval = ApprovalRecord(
        id="appr_1", subject_type="shield_rule", subject_id="rule_approve",
        reviewer="admin", decision=ApprovalDecision.APPROVE, rationale="ok",
        timestamp=datetime.now(UTC),
    )
    result = lifecycle.approve_rule("rule_approve", approval, gate)
    assert not result.passed
    # Rule must NOT be activated when gate fails
    assert lifecycle.get_rule("rule_approve").status == ShieldStatus.PROPOSED


def test_evaluate_rule_and_evaluate_rules():
    """RuleEvaluator.evaluate / evaluate_rules: active rule matches, inactive does not."""
    rule = __import__("sentinelx.common_schemas", fromlist=["ShieldRule"]).ShieldRule(
        id="rule_eval",
        target_id="s",
        scope=_make_scope(route="/api/admin", parameter=None, client=None),
        action=ShieldAction.BLOCK_ROUTE_PATTERN.value,
        reason="test",
        linked_finding_id=None,
        intent_event_ids=["evt1"],
        owner="test",
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        status=ShieldStatus.ACTIVE,
    )
    # Matching request -> blocked
    req = {"method": "GET", "path": "/api/admin", "params": {}, "headers": {}, "client_key": "c"}
    decision = evaluate_rule(rule, req)
    assert not decision.allowed
    assert decision.action == ShieldAction.BLOCK_ROUTE_PATTERN

    # Non-matching request -> allowed
    req = {"method": "GET", "path": "/api/notes", "params": {}, "headers": {}, "client_key": "c"}
    decision = evaluate_rule(rule, req)
    assert decision.allowed

    # Inactive rule -> allowed
    inactive = rule.model_copy(update={"status": ShieldStatus.REMOVED})
    req = {"method": "GET", "path": "/api/admin", "params": {}, "headers": {}, "client_key": "c"}
    decision = evaluate_rule(inactive, req)
    assert decision.allowed

    # Multiple rules: first match wins
    req = {"method": "GET", "path": "/api/admin", "params": {}, "headers": {}, "client_key": "c"}
    decision = evaluate_rules([rule, rule], req)
    assert not decision.allowed


# ------------------------------------------------------------------ proxy: fail-open + kill switch

def test_proxy_fail_open_when_killed(tmp_path, monkeypatch):
    """When the kill-switch file exists, the proxy forwards requests (fail-open)."""
    kill_file = tmp_path / "shield.kill"
    kill_file.write_text("1")
    config = ShieldConfig(
        upstream="http://orders.lab.test:18080",
        mode="enforce",
        fail_open=True,
        kill_switch_file=str(kill_file),
    )
    from sentinelx.shield.proxy import ShieldProxy
    conn = connect(":memory:")
    migrate(conn)
    store = EvidenceStore(conn)
    session_service = SessionService(conn)
    session, _ = session_service.create(
        kind=SessionKind.GUARD, policy_version="1.0",
        actor=Actor(id="shield", role=ActorRole.SYSTEM),
    )
    detector = Detector([], [])
    recorder = ShieldRecorder(store, session.id)
    proxy = ShieldProxy(config, store, session.id, detector, recorder)
    assert proxy._is_killed()
    # Kill switch present: proxy must not block even in enforce mode
    assert proxy.config.fail_open


def test_proxy_monitor_mode_never_blocks():
    """Monitor mode: labels intent but never blocks requests."""
    config = ShieldConfig(
        upstream="http://orders.lab.test:18080",
        mode="monitor",
        fail_open=True,
    )
    assert config.mode == "monitor"
    conn = connect(":memory:")
    migrate(conn)
    store = EvidenceStore(conn)
    session_service = SessionService(conn)
    session, _ = session_service.create(
        kind=SessionKind.GUARD, policy_version="1.0",
        actor=Actor(id="shield", role=ActorRole.SYSTEM),
    )
    detector = Detector([], [])
    recorder = ShieldRecorder(store, session.id)
    proxy = ShieldProxy(config, store, session.id, detector, recorder)
    # Monitor mode: no auto-activation
    assert proxy.config.mode == "monitor"
    assert proxy.config.auto_shield is False


def test_signal_to_intent_covers_taxonomy():
    """Every intent label in the taxonomy has at least one signal mapped to it."""
    mapped = {intent for _sig, intent, _conf in SIGNAL_TO_INTENT}
    for label in INTENT_LABELS:
        assert label in mapped, f"intent {label.value} has no signal mapping"


def test_aggregate_intent_unknown_signal_ignored():
    """Unknown signal names contribute nothing; default returned when none match."""
    intent, confidence, scores = aggregate_intent(["bogus_signal", "also_bogus"])
    assert intent == DEFAULT_INTENT
    assert confidence == DEFAULT_CONFIDENCE
    assert scores == {}
