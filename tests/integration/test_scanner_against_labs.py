"""Full orchestrated scans against the REAL labs. Node tests need no Docker; the PHP ones are
marked `docker` (loud skip locally if the daemon is down, a failure under SENTINELX_CI=1)."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import pytest

from apps import labctl
from sentinelx.evaluation.scan_scoring import clean_copy_check, score
from sentinelx.evidence.db import connect, migrate
from sentinelx.evidence.store import EvidenceStore
from sentinelx.scanner.authz import KillSwitch, register_lab_target
from sentinelx.scanner.models import load_profile
from sentinelx.scanner.orchestrate import run_scan

ROOT = Path(__file__).resolve().parents[2]
PROFILE = load_profile()


def scan(lab: str, conn: Any, **kw: Any):
    target = register_lab_target(lab, ["127.0.0.1"], [labctl.get(lab).port])
    return run_scan(target, PROFILE, ROOT / "labs", lab, conn, **kw)


@pytest.fixture()
def conn(tmp_path: Path):
    c = connect(tmp_path / "scan.db")
    migrate(c)
    yield c
    c.close()


# ------------------------------------------------------------------ Node (no Docker)
@pytest.fixture(scope="module")
def node_up():
    labctl.reset("vibe_notes_node")
    yield
    labctl.down("vibe_notes_node")


@pytest.fixture(scope="module")
def node_ref_up():
    labctl.reset("vibe_notes_node_reference")
    yield
    labctl.down("vibe_notes_node_reference")


def confirmed_set(result) -> set[tuple[str, str, str]]:
    return {(f.candidate.vuln_class.value, f.candidate.method, f.candidate.endpoint)
            for f in result.findings if f.verification.state == "confirmed"}


def test_node_scan_confirms_the_classes_our_checks_can_find(node_up, conn) -> None:
    result = scan("vibe_notes_node", conn)
    assert result.stop_reason == "completed"
    confirmed = {cls for cls, _m, _e in confirmed_set(result)}
    expected = {"sql_injection", "broken_object_authorization", "debug_exposure",
               "sensitive_file_exposure", "missing_authentication", "permissive_cors",
               "security_headers_and_cookies", "verbose_errors"}
    assert expected <= confirmed, expected - confirmed
    rate_limit = next(f for f in result.findings if f.candidate.check_id == "missing_rate_limit")
    assert rate_limit.verification.state == "needs_validation", (
        "behavioural evidence must never reach 'confirmed'")
    assert not any(f.candidate.check_id == "weak_upload_validation" for f in result.findings)
    ledger_rows = result.coverage.rows
    not_applicable = [r for r in ledger_rows if r.check_id == "weak_upload_validation"]
    assert not_applicable
    assert not_applicable[0].reason == "not applicable: no matching endpoint was found"


def test_node_scan_scores_against_planted_ground_truth(node_up, conn) -> None:
    result = scan("vibe_notes_node", conn)
    findings = [f.model_dump(mode="json") for f in result.findings]
    scored = score("vibe_notes_node", findings)
    assert {"NODE-01", "NODE-03", "NODE-05", "NODE-06", "NODE-08", "NODE-10"} <= set(
        scored.planted_found)
    assert scored.overall["denominator"] == 10 and scored.overall["numerator"] >= 6


def test_node_reference_clean_copy_shows_no_false_findings_of_planted_classes(
        node_ref_up, conn) -> None:
    result = scan("vibe_notes_node_reference", conn)
    findings = [f.model_dump(mode="json") for f in result.findings]
    clean = clean_copy_check("vibe_notes_node", findings)
    assert clean.false_findings_count == 0, clean.false_findings


def test_evidence_chain_verifies_ok_after_a_scan(node_up, conn) -> None:
    result = scan("vibe_notes_node", conn)
    assert EvidenceStore(conn).verify_chain(result.session_id).ok


def test_coverage_ledger_lists_unexercised_cells_with_reasons(node_up, conn) -> None:
    result = scan("vibe_notes_node", conn)
    assert result.coverage.rows
    assert 0 < result.coverage.coverage_percent <= 100
    unexercised = result.coverage.unexercised
    assert all(r.reason for r in unexercised)


def test_two_scans_of_a_freshly_reset_lab_give_the_same_confirmed_set(conn) -> None:
    labctl.reset("vibe_notes_node")
    first = confirmed_set(scan("vibe_notes_node", conn))
    labctl.reset("vibe_notes_node")
    second = confirmed_set(scan("vibe_notes_node", conn))
    labctl.down("vibe_notes_node")
    assert first == second and first


def test_a_tiny_request_budget_stops_the_scan_and_makes_no_more_requests(node_up, conn) -> None:
    tiny = PROFILE.model_copy(update={"request_budget": 5, "requests_per_second": 1000,
                                      "burst": 1000})
    target = register_lab_target("vibe_notes_node", ["127.0.0.1"],
                                 [labctl.get("vibe_notes_node").port])
    result = run_scan(target, tiny, ROOT / "labs", "vibe_notes_node", conn)
    assert result.stop_reason == "BUDGET_EXCEEDED" and result.requests_used <= 5
    assert result.skipped_checks, "later checks are recorded as skipped, not silently dropped"


def test_a_pre_tripped_kill_switch_stops_the_scan_before_any_request(node_up, conn) -> None:
    kill = KillSwitch()
    kill.trip("test")
    target = register_lab_target("vibe_notes_node", ["127.0.0.1"],
                                 [labctl.get("vibe_notes_node").port])
    result = run_scan(target, PROFILE, ROOT / "labs", "vibe_notes_node", conn, kill=kill)
    assert result.stop_reason == "KILL_SWITCH" and result.requests_used == 0
    assert result.findings == [], "nothing was ever crawled, so there is nothing to find"
    assert len(result.skipped_checks) == len(PROFILE.checks)


def test_cancel_event_stops_the_scan(node_up, conn) -> None:
    event = threading.Event()
    event.set()
    target = register_lab_target("vibe_notes_node", ["127.0.0.1"],
                                 [labctl.get("vibe_notes_node").port])
    result = run_scan(target, PROFILE, ROOT / "labs", "vibe_notes_node", conn,
                      cancel_event=event)
    assert result.stop_reason == "CANCELLED" and result.requests_used == 0


def test_the_scan_never_scans_anything_but_the_registered_lab_host(node_up, conn) -> None:
    result = scan("vibe_notes_node", conn)
    events = EvidenceStore(conn).list_session(result.session_id)
    for e in events:
        if e.kind in {"SCAN_REQUEST", "SCAN_REQUEST_REFUSED"}:
            assert e.payload["target_id"] == "vibe_notes_node"


# ------------------------------------------------------------------ PHP (Docker)
@pytest.fixture(scope="module")
def php_up():
    labctl.reset("vibe_shop_php")
    yield
    labctl.down("vibe_shop_php")


@pytest.fixture(scope="module")
def php_ref_up():
    labctl.reset("vibe_shop_php_reference")
    yield
    labctl.down("vibe_shop_php_reference")


@pytest.mark.docker
def test_php_scan_confirms_the_classes_our_checks_can_find(php_up, conn) -> None:
    result = scan("vibe_shop_php", conn)
    assert result.stop_reason == "completed"
    confirmed = {cls for cls, _m, _e in confirmed_set(result)}
    expected = {"sql_injection", "reflected_xss", "broken_object_authorization",
               "missing_authentication", "debug_exposure", "sensitive_file_exposure",
               "security_headers_and_cookies", "permissive_cors"}
    assert expected <= confirmed, expected - confirmed


@pytest.mark.docker
def test_php_scan_scores_against_planted_ground_truth(php_up, conn) -> None:
    result = scan("vibe_shop_php", conn)
    findings = [f.model_dump(mode="json") for f in result.findings]
    scored = score("vibe_shop_php", findings)
    assert scored.overall["denominator"] == 10 and scored.overall["numerator"] >= 6


@pytest.mark.docker
def test_php_reference_clean_copy_shows_no_false_findings_of_planted_classes(
        php_ref_up, conn) -> None:
    result = scan("vibe_shop_php_reference", conn)
    findings = [f.model_dump(mode="json") for f in result.findings]
    clean = clean_copy_check("vibe_shop_php", findings)
    assert clean.false_findings_count == 0, clean.false_findings


@pytest.mark.docker
def test_php_weak_upload_validation_fires_on_vulnerable_not_on_reference(
        php_up, php_ref_up, conn) -> None:
    vuln = scan("vibe_shop_php", conn)
    ref = scan("vibe_shop_php_reference", conn)
    assert any(f.candidate.check_id == "weak_upload_validation"
              and f.verification.state == "confirmed" for f in vuln.findings)
    assert not any(f.candidate.check_id == "weak_upload_validation"
                  and f.verification.state == "confirmed" for f in ref.findings)
