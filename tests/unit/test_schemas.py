"""Contract tests for sentinelx.common_schemas (PROMPT 1 / Part B)."""

import json
from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from sentinelx.common_schemas import (
    ALL_MODELS,
    ActionRequest,
    AttackIntent,
    Decision,
    EvidenceEvent,
    EvidenceState,
    ModelMode,
    ModelStatus,
    PatchProposal,
    PolicyDecision,
    ScenarioSpec,
    ShieldRule,
    render_schema_files,
)
from sentinelx.common_schemas.export import SCHEMA_DIR

NOW = datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC)


def valid_samples() -> dict[str, dict]:
    ev = "evt_1"
    return {
        "ScenarioSpec": dict(
            id="sc1", seed=7, fixture_id="fx", fixture_version="1", goal="buy item",
            allowed_hosts=["shop.lab.test"], allowed_actions=["click"], attack_surface="page",
            attack_payload_id="p1",
            forbidden_outcome={"type": "http_post", "endpoint": "/transfer"},
            goal_assertion={"type": "cart_contains", "expected": "item-1"},
        ),
        "ActionRequest": dict(
            session_id="s1", step=1, action_id="a1", timestamp=NOW, actor="agent",
            tool="click", arguments={"selector": "#x"}, origin_observation_ids=[ev],
        ),
        "PolicyDecision": dict(
            action_id="a1", decision="ALLOW", policy_version="p1", rule_ids=["r1"],
            reason_code="ok", explanation="fine", requires_human=False,
        ),
        "ApprovalRequest": dict(
            id="ar1", session_id="s1", action_id="a1", tool="send", args_digest="0" * 16,
            subject_id="a1:" + "0" * 16, reason_code="CONFIRMATION_REQUIRED",
            explanation="x", created_at=NOW,
        ),
        "EvidenceEvent": dict(
            id=ev, session_id="s1", seq=1, kind="k", timestamp_utc=NOW, state="OBSERVED",
            source="t", payload={}, previous_hash="0" * 64, event_hash="1" * 64,
        ),
        "IncidentFinding": dict(
            incident_id="i1", finding="f", evidence_event_ids=[ev], confidence=0.5,
            observed=["o"], inferred=["i"], recommended_mitigations=["m"],
        ),
        "ContainmentBranch": dict(
            branch_id="b1", parent_session_id="s1", checkpoint_ref="c", mitigation_id="m",
            new_seed=1, executed_trace_id="t", unauthorized_executed=False,
            task_completed=True, added_actions=0, duration_ms=5, verifier_version="v1",
            was_simulated=False, was_executed=True, model_mode="LIVE", fixture_hash="h",
        ),
        "TargetAuthorization": dict(
            target_id="t1", base_url="http://127.0.0.1:8080",
            scope={"schemes": ["http"], "hosts": ["127.0.0.1"], "ports": [8080]},
            lab=True, ownership_method="local_lab", verification_token_hash="h" * 8,
            status="PENDING",
        ),
        "ScanFinding": dict(
            id="f1", target_id="t1", vuln_class="xss", endpoint="/q", evidence_event_ids=[ev],
            redacted_request_excerpt="r", redacted_response_excerpt="r", severity="low",
            confidence=0.4, state="needs_validation", suggested_fix_category="escape",
        ),
        "AttackIntent": dict(
            id="ai1", session_ref="s1", intent="RECON", summary="s", cited_event_ids=[ev],
            confidence=0.3,
        ),
        "VulnerabilityFinding": dict(
            id="v1", scan_finding_id="f1", file="a.php", line_start=1, line_end=2, reasoning="r",
        ),
        "PatchProposal": dict(
            id="p1", finding_id="v1", diff="--- a", explanation="e", files_touched=["a.php"],
            fix_category="escape",
        ),
        "RepairVerification": dict(
            patch_id="p1", checks=[{"name": "n", "passed": True, "output_excerpt": ""}],
            status="VERIFIED", verifier_version="v1", duration_ms=3,
        ),
        "ShieldRule": dict(
            id="sr1", target_id="t1", scope={"route": "/login"}, action="block", reason="r",
            intent_event_ids=[ev], owner="op", created_at=NOW, expires_at=NOW + timedelta(hours=1),
            status="PROPOSED",
        ),
        "EscalationTicket": dict(
            id="e1", finding_id="f1", evidence_event_ids=[ev], explanation="x",
            options=["a", "b"], status="OPEN", created_at=NOW,
        ),
        "ApprovalRecord": dict(
            id="ap1", subject_type="patch", subject_id="p1", reviewer="op", decision="approve",
            rationale="ok", timestamp=NOW,
        ),
        "ModelStatus": dict(provider="nvidia", model="m", mode="LIVE", calls=1, tokens=2),
        "SessionRecord": dict(
            id="s1", kind="AGENT_RUN", state="CREATED", created_at=NOW, policy_version="p1",
        ),
        "Actor": dict(id="u1", role="OPERATOR"),
        "AuditRecord": dict(
            actor_id="u1", actor_role="SYSTEM", action="x", timestamp=NOW,
        ),
        "UsageRecord": dict(
            provider="p", model="m", tokens_in=1, tokens_out=2, latency_ms=3, timestamp=NOW,
        ),
    }


def test_samples_cover_every_model() -> None:
    assert set(valid_samples()) == {m.__name__ for m in ALL_MODELS}


@pytest.mark.parametrize("model", ALL_MODELS, ids=lambda m: m.__name__)
def test_valid_sample_roundtrips_with_schema_version(model: type) -> None:
    obj = model.model_validate(valid_samples()[model.__name__])
    assert obj.schema_version == "1.0"
    assert model.model_validate_json(obj.model_dump_json()) == obj


@pytest.mark.parametrize("model", ALL_MODELS, ids=lambda m: m.__name__)
def test_unknown_field_rejected(model: type) -> None:
    data = dict(valid_samples()[model.__name__], surprise="x")
    with pytest.raises(ValidationError):
        model.model_validate(data)


def test_enum_rejects_bad_values() -> None:
    s = valid_samples()
    with pytest.raises(ValidationError):
        PolicyDecision.model_validate(dict(s["PolicyDecision"], decision="MAYBE"))
    with pytest.raises(ValidationError):
        EvidenceEvent.model_validate(dict(s["EvidenceEvent"], state="GUESSED"))
    with pytest.raises(ValidationError):
        ModelStatus.model_validate(dict(s["ModelStatus"], mode="live"))
    with pytest.raises(ValidationError):
        AttackIntent.model_validate(dict(s["AttackIntent"], intent="HACK"))
    assert Decision("BLOCK") is Decision.BLOCK


def test_naive_datetime_rejected_and_normalised_to_utc() -> None:
    s = valid_samples()
    with pytest.raises(ValidationError):
        ActionRequest.model_validate(dict(s["ActionRequest"], timestamp=datetime(2026, 1, 1)))
    with pytest.raises(ValidationError):
        ActionRequest.model_validate(dict(s["ActionRequest"], timestamp="2026-01-01T00:00:00"))
    ist = timezone(timedelta(hours=5, minutes=30))
    a = ActionRequest.model_validate(
        dict(s["ActionRequest"], timestamp=datetime(2026, 1, 1, 5, 30, tzinfo=ist))
    )
    assert a.timestamp == datetime(2026, 1, 1, tzinfo=UTC)
    assert a.timestamp.utcoffset() == timedelta(0)
    assert json.loads(a.model_dump_json())["timestamp"] == "2026-01-01T00:00:00.000000Z"


def test_scenario_hosts_must_be_exact() -> None:
    s = valid_samples()["ScenarioSpec"]
    for bad in ("*.lab.test", "shop.*", "*"):
        with pytest.raises(ValidationError):
            ScenarioSpec.model_validate(dict(s, allowed_hosts=[bad]))


def test_fixed_state_fields() -> None:
    s = valid_samples()
    assert AttackIntent.model_validate(s["AttackIntent"]).state is EvidenceState.INFERRED
    with pytest.raises(ValidationError):
        AttackIntent.model_validate(dict(s["AttackIntent"], state="OBSERVED"))
    assert PatchProposal.model_validate(s["PatchProposal"]).state is EvidenceState.PROPOSED
    with pytest.raises(ValidationError):
        PatchProposal.model_validate(dict(s["PatchProposal"], state="VERIFIED"))
    rule = ShieldRule.model_validate(s["ShieldRule"])
    assert rule.label == "TEMPORARY SHIELD, NOT A FIX"
    with pytest.raises(ValidationError):
        ShieldRule.model_validate(dict(s["ShieldRule"], label="A FIX"))


def test_shield_rule_must_expire_after_creation_and_escalation_needs_2_3_options() -> None:
    s = valid_samples()
    with pytest.raises(ValidationError):
        ShieldRule.model_validate(dict(s["ShieldRule"], expires_at=NOW))
    from sentinelx.common_schemas import EscalationTicket

    for opts in (["a"], ["a", "b", "c", "d"]):
        with pytest.raises(ValidationError):
            EscalationTicket.model_validate(dict(s["EscalationTicket"], options=opts))


def test_model_status_unavailable_is_explicit() -> None:
    st = ModelStatus(provider="p", model="m", mode=ModelMode.UNAVAILABLE, calls=1, tokens=0,
                     error="timeout")
    assert st.mode is ModelMode.UNAVAILABLE


def test_exported_json_schemas_are_current() -> None:
    expected = render_schema_files()
    on_disk = {p.name: p.read_text(encoding="utf-8") for p in SCHEMA_DIR.glob("*.schema.json")}
    assert on_disk == expected, "run: python scripts/export_schemas.py"
