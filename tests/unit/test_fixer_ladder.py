"""Decision ladder, approval, and escalation tests (no model, no Docker). Fake PatchGenResult
and VerificationReport objects stand in for what Parts C/D would have actually produced."""

from __future__ import annotations

import json

import pytest

from sentinelx.common_schemas import EscalationStatus, VerificationStatus
from sentinelx.evidence.db import connect, migrate
from sentinelx.evidence.store import EvidenceStore
from sentinelx.fixer import ladder
from sentinelx.fixer.diff_validator import ValidationResult
from sentinelx.fixer.models import FixCategory, FixPolicyEntry, RepoScope
from sentinelx.fixer.patch_gen import PatchGenResult
from sentinelx.fixer.verify import TimedCheck, VerificationReport
from sentinelx.model_clients import ModelCallStatus


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "db.sqlite")
    migrate(c)
    return c


def _check(name: str, passed: bool) -> TimedCheck:
    from sentinelx.common_schemas import CheckResult

    return TimedCheck(CheckResult(name=name, passed=passed, output_excerpt="x"), 5)


def _verified_report() -> VerificationReport:
    r = VerificationReport(patch_id="p")
    r.checks = [_check("diff_review", True), _check("syntax", True),
               _check("benign_traffic", True), _check("full_scan", True)]
    r.status = VerificationStatus.VERIFIED
    return r


def _rejected_report(failed_check: str = "full_scan") -> VerificationReport:
    r = VerificationReport(patch_id="p")
    r.checks = [_check("diff_review", True), _check("syntax", True),
               _check("benign_traffic", failed_check != "benign_traffic"),
               _check(failed_check, False)]
    r.status = VerificationStatus.REJECTED
    return r


def _good_patch() -> PatchGenResult:
    return PatchGenResult("VALIDATED", diff="--- a/x\n+++ b/x\n", explanation="fix",
                          fix_category=FixCategory.PARAMETERIZED_QUERY,
                          validation=ValidationResult(True, [], None))


def _unavailable_patch() -> PatchGenResult:
    status = ModelCallStatus.MODEL_UNAVAILABLE.value
    return PatchGenResult("MODEL_UNAVAILABLE", reasons=[f"{status}: timed out"])


def test_auto_verified_awaits_approval_not_auto_applied(conn) -> None:
    policy_entry = FixPolicyEntry(fix_category=FixCategory.PARAMETERIZED_QUERY, decision="AUTO")
    outcome = ladder.decide(conn, finding_id="f1", vuln_class="sql_injection",
                            policy_entry=policy_entry, patch=_good_patch(),
                            verification=_verified_report(), rejected_count=0,
                            evidence_event_ids=[], files_touched=["x.php"])
    assert outcome.status == "AWAITING_APPROVAL"
    assert outcome.patch_id is not None
    # nothing has been applied anywhere - only a PatchProposal + RepairVerification exist
    assert conn.execute("SELECT COUNT(*) FROM approvals").fetchone()[0] == 0


def test_needs_human_class_never_auto_applies_even_when_verified(conn) -> None:
    policy_entry = FixPolicyEntry(fix_category=FixCategory.CORS_CONFIG, decision="NEEDS_HUMAN")
    outcome = ladder.decide(conn, finding_id="f1", vuln_class="permissive_cors",
                            policy_entry=policy_entry, patch=_good_patch(),
                            verification=_verified_report(), rejected_count=0,
                            evidence_event_ids=[], files_touched=["x.js"])
    assert outcome.status == "ESCALATED"
    assert outcome.ticket_id is not None
    ticket = json.loads(conn.execute("SELECT body FROM escalations WHERE id = ?",
                                     (outcome.ticket_id,)).fetchone()["body"])
    assert ticket["status"] == EscalationStatus.OPEN.value
    assert 2 <= len(ticket["options"]) <= 3


def test_model_unavailable_escalates_not_a_silent_skip(conn) -> None:
    outcome = ladder.decide(conn, finding_id="f1", vuln_class="sql_injection", policy_entry=None,
                            patch=_unavailable_patch(), verification=None, rejected_count=0,
                            evidence_event_ids=[], files_touched=[])
    assert outcome.status == "ESCALATED"
    assert conn.execute("SELECT COUNT(*) FROM escalations").fetchone()[0] == 1


def test_rejected_once_asks_for_a_retry_not_an_escalation(conn) -> None:
    policy_entry = FixPolicyEntry(fix_category=FixCategory.PARAMETERIZED_QUERY, decision="AUTO")
    outcome = ladder.decide(conn, finding_id="f1", vuln_class="sql_injection",
                            policy_entry=policy_entry, patch=_good_patch(),
                            verification=_rejected_report(), rejected_count=0,
                            evidence_event_ids=[], files_touched=["x.php"])
    assert outcome.status == "REJECTED_RETRY"


def test_rejected_twice_escalates_with_the_failed_checks_named(conn) -> None:
    policy_entry = FixPolicyEntry(fix_category=FixCategory.PARAMETERIZED_QUERY, decision="AUTO")
    outcome = ladder.decide(conn, finding_id="f1", vuln_class="sql_injection",
                            policy_entry=policy_entry, patch=_good_patch(),
                            verification=_rejected_report("full_scan"), rejected_count=1,
                            evidence_event_ids=[], files_touched=["x.php"])
    assert outcome.status == "ESCALATED"
    ticket = json.loads(conn.execute("SELECT body FROM escalations WHERE id = ?",
                                     (outcome.ticket_id,)).fetchone()["body"])
    assert "full_scan" in ticket["explanation"]


def test_apply_approved_touches_only_labs_applied_and_keeps_a_rollback_copy(
        conn, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(ladder, "APPLIED_ROOT", tmp_path / "labs_applied")
    work_dir = tmp_path / "scope_work"
    work_dir.mkdir()
    (work_dir / "product.php").write_text("v1", encoding="utf-8")
    scope = RepoScope(lab="demo_lab", source_dir=tmp_path, work_dir=work_dir)

    approval_id = ladder.apply_approved(conn, patch_id="patch_1", lab="demo_lab", scope=scope,
                                        reviewer="alice")
    current = ladder.APPLIED_ROOT / "demo_lab" / "current"
    assert (current / "product.php").read_text(encoding="utf-8") == "v1"
    approval_body = json.loads(conn.execute(
        "SELECT body FROM approvals WHERE id = ?", (approval_id,)).fetchone()["body"])
    assert approval_body["decision"] == "approve"

    # a second apply (simulating a later patch) keeps the first version as a rollback copy
    (work_dir / "product.php").write_text("v2", encoding="utf-8")
    ladder.apply_approved(conn, patch_id="patch_2", lab="demo_lab", scope=scope, reviewer="alice")
    assert (current / "product.php").read_text(encoding="utf-8") == "v2"
    rollbacks = list((ladder.APPLIED_ROOT / "demo_lab").glob("rollback_*"))
    assert len(rollbacks) == 1
    assert (rollbacks[0] / "product.php").read_text(encoding="utf-8") == "v1"


def test_rollback_restores_the_previous_copy(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(ladder, "APPLIED_ROOT", tmp_path / "labs_applied")
    dest = ladder.APPLIED_ROOT / "demo_lab"
    (dest / "rollback_20260101T000000Z").mkdir(parents=True)
    (dest / "rollback_20260101T000000Z" / "f.php").write_text("old", encoding="utf-8")
    (dest / "current").mkdir(parents=True)
    (dest / "current" / "f.php").write_text("new", encoding="utf-8")

    ladder.rollback("demo_lab", "rollback_20260101T000000Z")
    assert (dest / "current" / "f.php").read_text(encoding="utf-8") == "old"


def test_evidence_chain_verifies_ok_for_a_fix_session(conn) -> None:
    from sentinelx.common_schemas import EvidenceState
    from sentinelx.evidence.records import RecordStore
    from sentinelx.scanner.authz import register_lab_target

    target = register_lab_target("f1", ["127.0.0.1"], [18080])
    RecordStore(conn).insert(target)
    session_id = ladder.start_fix_session(conn, finding_id="f1")
    EvidenceStore(conn).append(session_id, "FIX_STARTED", EvidenceState.OBSERVED,
                               "fixer.ladder", {"finding_id": "f1"})
    assert EvidenceStore(conn).verify_chain(session_id).ok


def test_patch_proposal_and_verification_are_persisted(conn) -> None:
    policy_entry = FixPolicyEntry(fix_category=FixCategory.PARAMETERIZED_QUERY, decision="AUTO")
    outcome = ladder.decide(conn, finding_id="f1", vuln_class="sql_injection",
                            policy_entry=policy_entry, patch=_good_patch(),
                            verification=_verified_report(), rejected_count=0,
                            evidence_event_ids=[], files_touched=["x.php"])
    row = conn.execute("SELECT finding_id FROM patches WHERE id = ?",
                       (outcome.patch_id,)).fetchone()
    assert row["finding_id"] == "f1"
    vrow = conn.execute("SELECT body FROM verifications WHERE patch_id = ?",
                        (outcome.patch_id,)).fetchone()
    assert json.loads(vrow["body"])["status"] == "VERIFIED"
