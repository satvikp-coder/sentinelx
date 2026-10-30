"""Intent tests: deterministic mapping, AttackIntent always INFERRED, cites real events."""

from sentinelx.common_schemas import Actor, ActorRole, EvidenceState, SessionKind
from sentinelx.evidence.db import connect, migrate
from sentinelx.evidence.sessions import SessionService
from sentinelx.evidence.store import EvidenceStore
from sentinelx.shield.intent import (
    DEFAULT_INTENT,
    IntentAssessment,
    IntentVerdict,
    build_intent,
    map_intent,
)


def test_map_intent_each_signal():
    expected = {
        "sql_break_char": ("INJECTION_PROBE", 0.85),
        "markup_reflected": ("INJECTION_PROBE", 0.8),
        "sensitive_path_env": ("RECON", 0.7),
        "sensitive_path_git": ("RECON", 0.7),
        "backup_extension": ("RECON", 0.6),
        "debug_route": ("RECON", 0.6),
        "scanner_ua": ("RECON", 0.65),
        "oversized_param": ("INJECTION_PROBE", 0.5),
        "protected_no_session": ("CREDENTIAL_GUESSING", 0.6),
        "high_404_rate": ("RECON", 0.6),
        "repeated_failed_logins": ("CREDENTIAL_GUESSING", 0.8),
        "object_id_enumeration": ("DATA_ENUMERATION", 0.75),
        "admin_probe": ("ADMIN_PROBE", 0.8),
    }
    for sig, (intent, conf) in expected.items():
        got_intent, got_conf = map_intent([sig])
        assert got_intent.value == intent, sig
        assert got_conf == conf, sig


def test_map_intent_unknown_defaults_to_recon():
    intent, conf = map_intent(["no_such_signal"])
    assert intent == DEFAULT_INTENT
    assert conf == 0.4


def test_map_intent_first_match_wins():
    # sql_break_char precedes protected_no_session; first in list wins per signal order.
    intent, conf = map_intent(["protected_no_session", "sql_break_char"])
    assert intent.value == "CREDENTIAL_GUESSING"  # protected_no_session is first in list
    assert conf == 0.6


def test_intent_assessment_schema_strict():
    a = IntentAssessment(
        intent="RECON",
        summary="probing",
        cited_event_ids=["evt_1"],
        confidence=0.5,
    )
    assert a.intent.value == "RECON"
    assert a.model_used is False
    try:
        IntentAssessment(
            intent="RECON", summary="s", cited_event_ids=["evt_1"], confidence=0.5, extra="x"
        )
        raise AssertionError("expected ValidationError")
    except Exception:
        pass


def test_build_intent_always_inferred():

    verdict = IntentVerdict(
        intent="INJECTION_PROBE", summary="sqli probe", confidence=0.85,
        cited_event_ids=["evt_a", "evt_b"], model_used=False, note=None,
    )
    intent = build_intent("s1", ["evt_a", "evt_b"], verdict)
    assert intent.state.value == "INFERRED"
    assert intent.intent.value == "INJECTION_PROBE"
    assert intent.summary == "sqli probe"
    assert intent.confidence == 0.85
    assert set(intent.cited_event_ids) == {"evt_a", "evt_b"}


def test_build_intent_drops_unknown_cited_ids():

    conn = connect(":memory:")
    migrate(conn)
    store = EvidenceStore(conn)
    session_service = SessionService(conn)
    session, _ = session_service.create(
        kind=SessionKind.GUARD, policy_version="1.0", actor=Actor(id="a", role=ActorRole.SYSTEM)
    )
    real = store.append(session.id, "shield_suspicious", EvidenceState.OBSERVED,
                        "sentinelx.shield", {"method": "GET", "path": "/x"})

    verdict = IntentVerdict(
        intent="RECON", summary="s", confidence=0.5,
        cited_event_ids=[real.id, "evt_nonexistent"], model_used=False, note=None,
    )
    intent = build_intent(session.id, [real.id, "evt_nonexistent"], verdict, store=store)
    assert real.id in intent.cited_event_ids
    assert "evt_nonexistent" not in intent.cited_event_ids
