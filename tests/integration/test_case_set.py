"""The hand-authored attack / benign case set: schema, pairing, coverage, fixture assertions."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from apps.fixture_lab.app import create_app
from apps.fixture_lab.state import FIXTURES_ROOT, SIDE_EFFECT_ENDPOINTS, LabState
from sentinelx.common_schemas import AttackTemplate, BenignTemplate, ScenarioSpec, Surface
from sentinelx.evaluation.cases import case_hash, load_all_cases, payload_path

CASES = load_all_cases()
ATTACKS = [c for c in CASES if c.is_attack]
BENIGN = [c for c in CASES if not c.is_attack]
RULES = {"TOOL_NOT_IN_SCENARIO", "DESTINATION_NOT_ALLOWED", "SECRET_EGRESS",
         "CONFIRMATION_REQUIRED", "EGRESS_BLOCKED"}


def test_enough_cases_and_unique_ids() -> None:
    assert len(ATTACKS) >= 12 and len(BENIGN) >= 12
    ids = [c.id for c in CASES]
    assert len(set(ids)) == len(ids)
    assert all(c.id.startswith("A") for c in ATTACKS) and all(c.id.startswith("B") for c in BENIGN)


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.id)
def test_every_case_is_schema_valid_and_strict(case) -> None:
    folder = "attacks" if case.is_attack else "benign"
    raw = json.loads((FIXTURES_ROOT / folder / f"{case.id}.json").read_text(encoding="utf-8"))
    model = AttackTemplate if case.is_attack else BenignTemplate
    model.model_validate(raw)
    with pytest.raises(ValidationError):
        model.model_validate({**raw, "surprise": 1})
    ScenarioSpec.model_validate(case.scenario.model_dump())  # runnable
    assert payload_path(case.template, FIXTURES_ROOT).is_file()
    assert case.template.fixture_assertions and case.template.notes
    host, _, path = case.template.forbidden_outcome.endpoint.partition("/")
    assert (host.removesuffix(".lab.test"), "/" + path) in SIDE_EFFECT_ENDPOINTS, \
        "the ledger must be able to see the forbidden outcome"


def test_every_attack_has_a_benign_neighbor_and_the_pairing_is_symmetric() -> None:
    by_id = {c.id: c for c in CASES}
    for attack in ATTACKS:
        neighbor = by_id[attack.template.benign_neighbor_id]
        assert not neighbor.is_attack
        assert neighbor.template.attack_neighbor_id == attack.id
        # "looks similar": same family, same surface, same lab host, same slot
        assert (neighbor.template.family, neighbor.template.surface) == (
            attack.template.family, attack.template.surface)
        assert neighbor.template.permitted_lab_target == attack.template.permitted_lab_target
        assert neighbor.template.placement == attack.template.placement
    assert {c.template.attack_neighbor_id for c in BENIGN} == {c.id for c in ATTACKS}


def test_coverage_of_scenarios_surfaces_and_rules() -> None:
    assert {c.template.family for c in ATTACKS} == {"S1", "S2", "S3"}
    assert {c.template.surface for c in ATTACKS} == set(Surface)
    expected = {c.template.expected_protected_rule for c in ATTACKS}
    assert expected == RULES, "each control family must be exercised by at least one attack"
    http = {"navigate", "read_page", "click", "submit_form", "tool_call"}
    for attack in ATTACKS:
        rule = attack.template.expected_protected_rule
        has_http = "http_request" in attack.template.allowed_actions
        if rule == "TOOL_NOT_IN_SCENARIO":
            assert not has_http  # the forbidden tool is not in the scenario
        if rule in {"DESTINATION_NOT_ALLOWED", "CONFIRMATION_REQUIRED"}:
            assert has_http  # the tool IS allowed; destination / impact decides
    assert http  # (documents the base tool set)


def test_benign_cases_exercise_confirm_and_allowed_http_requests() -> None:
    confirm = [c for c in BENIGN if c.template.expected_protected_rule == "CONFIRMATION_REQUIRED"]
    assert len(confirm) >= 3
    for c in confirm:
        posts = [s for s in c.template.task.steps
                 if s.tool == "http_request" and (s.method or "").upper() == "POST"]
        assert posts, f"{c.id} must touch an allowed high-impact action"
    legit_reads = [c for c in BENIGN if any(
        s.tool == "http_request" and (s.method or "").upper() == "GET"
        for s in c.template.task.steps)]
    assert len(legit_reads) >= 3
    assert all(c.template.expected_protected_rule in {None, "CONFIRMATION_REQUIRED"}
               for c in BENIGN)


def test_safety_constraints_and_lab_only_targets() -> None:
    for c in CASES:
        assert c.template.permitted_lab_target.endswith(".lab.test")
        assert c.scenario.allowed_hosts == [c.template.permitted_lab_target]
        assert len(c.template.safety_constraints) == 5


@pytest.fixture(scope="module")
def lab_client(tmp_path_factory: pytest.TempPathFactory):
    state = LabState(tmp_path_factory.mktemp("cases"), "tok")
    state.port = 7777
    with TestClient(create_app(state)) as client:
        yield state, client


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.id)
def test_fixture_assertions_hold_against_the_real_lab(lab_client, case) -> None:
    state, client = lab_client
    state.reset(case.id)
    for a in case.template.fixture_assertions:
        r = client.get(a.path, headers={"Host": f"{a.vhost}.lab.test:7777"})
        assert r.status_code == 200, (case.id, a.path)
        body = r.text
        if a.kind == "page_contains":
            assert a.text in body, (case.id, a.text)
        else:
            assert a.text not in body, (case.id, a.text)
    assert "{{" not in client.get(
        case.template.fixture_assertions[0].path,
        headers={"Host": f"{case.template.fixture_assertions[0].vhost}.lab.test:7777"}).text


def test_case_hash_changes_when_the_case_or_its_payload_changes(tmp_path: Path) -> None:
    import shutil

    root = tmp_path / "fixtures"
    shutil.copytree(FIXTURES_ROOT, root)
    case = next(c for c in CASES if c.id == "A01")
    before = case_hash(case, root)
    assert before == case_hash(case, FIXTURES_ROOT)
    payload = payload_path(case.template, root)
    payload.write_text(payload.read_text(encoding="utf-8") + " ", encoding="utf-8")
    assert case_hash(case, root) != before
    changed = type(case)(case.id, case.label,
                         case.template.model_copy(update={"notes": "edited"}), case.scenario)
    assert case_hash(changed, FIXTURES_ROOT) != before
